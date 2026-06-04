package com.apisec.engine;

import com.apisec.config.AppConfig;
import com.apisec.curl.CurlParser;
import com.apisec.eval.Evaluator;
import com.apisec.model.*;
import com.apisec.mutate.Mutator;
import com.apisec.report.ReportModels.*;
import com.apisec.report.Reporter;
import com.apisec.rules.RuleLoader;
import com.apisec.rules.RuleLoader.ScannerMetadata;
import com.apisec.rules.RuleModels.*;
import com.apisec.webhook.WebhookClient;
import java.net.URI;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.regex.Pattern;

public class ScannerEngine {
  public record Options(String curl, String altCurl, String rulesFile) {}
  public record Result(Report report, String path) {}

  public static Result run(AppConfig cfg, Options opt) throws Exception {
    Instant started = Instant.now();
    String scanId = "scan_" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    RequestModel req = CurlParser.parse(opt.curl());
    RequestModel alt = opt.altCurl() == null || opt.altCurl().isBlank() ? null : CurlParser.parse(opt.altCurl());
    HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(cfg.scanner.timeoutSeconds)).build();
    ResponseModel baseline = execute(client, req, cfg.scanner.timeoutSeconds);
    List<Group> groups = loadGroups(cfg, opt.rulesFile());
    List<Finding> findings = evaluateGroups(client, cfg, groups, req, alt, baseline);
    Report prelim = Reporter.build(scanId, started, Instant.now(), req.method, req.url, req.host, groups, findings, new WebhookStatus());
    Reporter.WriteResult first = Reporter.writeJson(prelim, cfg);
    WebhookStatus ws = WebhookClient.send(cfg, scanId, first.payload());
    Report finalReport = Reporter.build(scanId, started, Instant.now(), req.method, req.url, req.host, groups, findings, ws);
    Reporter.WriteResult wr = Reporter.writeJson(finalReport, cfg);
    return new Result(finalReport, wr.path());
  }

  private static List<Group> loadGroups(AppConfig cfg, String explicit) throws Exception {
    if (explicit == null || explicit.isBlank()) return RuleLoader.loadDir(cfg.rules.directory, cfg.rules.activeGroups);
    java.nio.file.Path p = java.nio.file.Path.of(explicit);
    if (java.nio.file.Files.exists(p)) return List.of(RuleLoader.loadFile(p));
    for (Group g: RuleLoader.loadDir(cfg.rules.directory, List.of())) {
      if (explicit.equals(g.id) || explicit.equals(g.name)) return List.of(g);
    }
    java.nio.file.Path byName = java.nio.file.Path.of(cfg.rules.directory, explicit.endsWith(".json") ? explicit : explicit + ".json");
    if (java.nio.file.Files.exists(byName)) return List.of(RuleLoader.loadFile(byName));
    throw new IllegalArgumentException("rule group not found: " + explicit);
  }

  public static ResponseModel execute(HttpClient client, RequestModel req, int timeoutSeconds) {
    long start = System.nanoTime(); ResponseModel rm = new ResponseModel();
    try {
      HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(req.url)).timeout(Duration.ofSeconds(timeoutSeconds));
      req.headers.forEach((k, vals) -> vals.forEach(v -> b.header(k, v)));
      b.method(req.method, req.body.length > 0 ? HttpRequest.BodyPublishers.ofByteArray(req.body) : HttpRequest.BodyPublishers.noBody());
      HttpResponse<byte[]> res = client.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
      rm.statusCode = res.statusCode(); rm.headers = res.headers().map(); rm.body = res.body(); rm.bodySize = rm.body.length; rm.contentType = rm.headers.getOrDefault("content-type", List.of("")).stream().findFirst().orElse("");
    } catch (Exception e) { rm.error = e.getMessage(); }
    rm.durationMs = Duration.ofNanos(System.nanoTime() - start).toMillis();
    return rm;
  }

  private static List<Finding> evaluateGroups(HttpClient client, AppConfig cfg, List<Group> groups, RequestModel req, RequestModel alt, ResponseModel baseline) {
    List<Finding> out = new ArrayList<>();
    for (Group g: groups) {
      if (!Evaluator.condition(g.precondition, req, baseline, baseline).passed()) {
        for (Rule r: g.rules) out.add(skipped(r, "rule group precondition did not match"));
        continue;
      }
      for (Rule r: g.rules) out.add(evaluateRule(client, cfg, r, req, alt, baseline));
    }
    return out;
  }

  static Finding evaluateRule(HttpClient client, AppConfig cfg, Rule rule, RequestModel req, RequestModel alt, ResponseModel baseline) {
    ScannerMetadata md = RuleLoader.metadata(rule);
    Finding f = base(rule, md); f.status = "SKIPPED";
    String bola = bolaSkipReason(rule.ruleId, req); if (!bola.isBlank()) { f.evidence.put("reason", bola); return f; }
    if (!md.cves.isEmpty()) { f.evidence.put("reason", "CVE-specific rules require product/version fingerprint evidence and were skipped"); return f; }
    if (md.destructive && !cfg.scanner.allowDangerous) { f.evidence.put("reason", "dangerous rule skipped; use --allow-dangerous for explicit opt-in"); return f; }
    AuthCredential auth = detectAuth(req);
    if (md.requiresAuthContext && auth.kind.isBlank()) { f.evidence.put("reason", "auth context required but no supported credential was provided"); return f; }
    if (isBearerAuthRule(rule.ruleId) && !hasHeader(req.headers, "Authorization")) { f.evidence.put("reason", "Authorization bearer token was not provided"); return f; }
    List<Mutation> muts = authAwareMutations(rule.ruleId, md.mutations, auth);
    if (isAuthRemovalRule(rule.ruleId) && muts.isEmpty()) { f.evidence.put("reason", "No supported auth credential detected for this auth-removal rule"); return f; }
    if (md.requiresAltContext && alt == null) { f.evidence.put("reason", "alternate low-privilege curl was not provided"); return f; }
    if (md.passive || muts.isEmpty()) {
      Evaluator.Result ev = Evaluator.assertion(rule.assertion, req, baseline, baseline);
      f.status = ev.passed() ? "PASSED" : "FAILED"; f.evidence.put("baselineStatus", baseline.statusCode); f.evidence.put("reason", ev.reason()); return f;
    }
    int limit = cfg.scanner.maxRequestsPerRule <= 0 || cfg.scanner.maxRequestsPerRule > 3 ? 3 : cfg.scanner.maxRequestsPerRule;
    for (int i=0; i<muts.size() && i<limit; i++) {
      Mutation spec = muts.get(i); Mutator.Result m = Mutator.generate(req, spec, cfg.scanner.allowDangerous);
      if (m.skipped) { f.evidence.put("mutation", spec.name); f.evidence.put("reason", m.reason); return f; }
      ResponseModel resp = md.requiresAltContext && alt != null ? execute(client, alt, cfg.scanner.timeoutSeconds) : execute(client, m.request, cfg.scanner.timeoutSeconds);
      f.evidence.put("baselineStatus", baseline.statusCode); f.evidence.put("mutationStatus", resp.statusCode); f.evidence.put("mutation", spec.name); f.evidence.put("mutatedCredential", mutationTarget(spec));
      if (!resp.error.isBlank()) { f.status = "ERROR"; f.evidence.put("reason", resp.error); return f; }
      Evaluator.Result ev = Evaluator.assertion(rule.assertion, req, baseline, resp);
      f.status = ev.passed() ? "PASSED" : "FAILED";
      f.evidence.put("reason", f.status.equals("FAILED") && isAuthRemovalRule(rule.ruleId) ? "Endpoint returned " + resp.statusCode + " after " + mutationTarget(spec) + " was removed." : ev.reason());
      return f;
    }
    f.evidence.put("reason", "no mutation generated"); return f;
  }

  private static Finding base(Rule r, ScannerMetadata md) {
    Finding f = new Finding(); f.ruleId = r.ruleId; f.name = r.name; f.severity = r.priority; f.owasp = md.owasp; f.cwe = md.cwe; f.cves = md.cves; f.remediation = md.remediation; return f;
  }
  private static Finding skipped(Rule r, String reason) { Finding f = base(r, RuleLoader.metadata(r)); f.status = "SKIPPED"; f.evidence.put("reason", reason); return f; }

  public record AuthCredential(String kind, String name) {}
  static AuthCredential detectAuth(RequestModel r) {
    for (String h: List.of("Authorization","X-API-Key","x-apikey","Api-Key","X-Auth-Token")) for (String k: r.headers.keySet()) if (k.equalsIgnoreCase(h)) return new AuthCredential("header", k);
    for (String c: r.cookies.keySet()) if (isSessionCookie(c)) return new AuthCredential("cookie", c);
    for (String q: List.of("api_key","apikey","access_token","token")) for (String k: r.query.keySet()) if (k.equalsIgnoreCase(q)) return new AuthCredential("query", k);
    return new AuthCredential("", "");
  }
  private static List<Mutation> authAwareMutations(String ruleId, List<Mutation> muts, AuthCredential auth) {
    if (!isAuthRemovalRule(ruleId)) return muts;
    if (auth.kind.isBlank()) return List.of();
    Mutation m = new Mutation(); m.key = auth.name; m.name = "remove-" + auth.name.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "-").replaceAll("(^-|-$)", "") + "-" + ("query".equals(auth.kind) ? "query-param" : auth.kind);
    m.operation = switch (auth.kind) { case "header" -> "REMOVE_HEADER"; case "cookie" -> "REMOVE_COOKIE"; default -> "REMOVE_QUERY_PARAM"; };
    return List.of(m);
  }
  private static boolean isAuthRemovalRule(String id) { return Set.of("API2-AUTH-001","API2-AUTH-006").contains(id); }
  private static boolean isBearerAuthRule(String id) { return Set.of("API2-AUTH-002","API2-AUTH-003").contains(id); }
  private static boolean hasHeader(Map<String,List<String>> h, String key) { return h.keySet().stream().anyMatch(k -> k.equalsIgnoreCase(key)); }
  private static boolean isSessionCookie(String n) { String x = n.toLowerCase(Locale.ROOT); return Set.of("session","sessionid","sid","jsessionid","connect.sid","auth","token").contains(x) || x.contains("session"); }
  private static String bolaSkipReason(String id, RequestModel r) {
    if ("API1-BOLA-001".equals(id) && Arrays.stream(r.path.split("/")).noneMatch(p -> p.matches("^\\d+$"))) return "No object identifier detected.";
    if (Set.of("API1-BOLA-002","API1-BOLA-005").contains(id) && r.query.keySet().stream().noneMatch(k -> Set.of("id","userId","accountId","orgId","tenantId","orderId","permissionId").stream().anyMatch(x -> x.equalsIgnoreCase(k)))) return "No object identifier detected.";
    Pattern uuid = Pattern.compile("(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    if ("API1-BOLA-003".equals(id) && !uuid.matcher(r.path).find() && r.query.values().stream().flatMap(List::stream).noneMatch(v -> uuid.matcher(v).find())) return "No object identifier detected.";
    if ("API1-BOLA-004".equals(id) && List.of("X-Tenant-ID","X-Org-ID","Organization-ID","Org-ID","Tenant-ID").stream().noneMatch(h -> hasHeader(r.headers, h))) return "No object identifier detected.";
    return "";
  }
  private static String mutationTarget(Mutation m) {
    return switch (m.operation) { case "REMOVE_HEADER","REPLACE_HEADER","ADD_HEADER" -> m.key + " header"; case "REMOVE_COOKIE" -> m.key + " cookie"; case "REMOVE_QUERY_PARAM","REPLACE_QUERY_PARAM","ADD_QUERY_PARAM" -> m.key + " query parameter"; default -> m.name; };
  }
}
