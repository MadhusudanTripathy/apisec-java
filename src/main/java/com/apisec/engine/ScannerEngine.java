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
    public interface ProgressSink {
        default void stage(int percent, String message) {}
        default void rules(int current, int total, String ruleId) {}
        default void done() {}
    }

    private static final ProgressSink NO_PROGRESS = new ProgressSink() {};

    public record Options(String curl, String altCurl, String rulesFile, Application application, Resource resource, String scanId) {
        public Options(String curl, String altCurl, String rulesFile) {
            this(curl, altCurl, rulesFile, null, null, null);
        }
        public Options(String curl, String altCurl, String rulesFile, Application application, Resource resource) {
            this(curl, altCurl, rulesFile, application, resource, null);
        }
    }

    public record Result(Report report, String path) {
    }

    public static Result run(AppConfig cfg, Options opt) throws Exception {
        return run(cfg, opt, NO_PROGRESS);
    }

    public static Result run(AppConfig cfg, Options opt, ProgressSink progress) throws Exception {
        if (progress == null) progress = NO_PROGRESS;
        Instant started = Instant.now();
        String scanId = opt.scanId() == null || opt.scanId().isBlank()
            ? "scan_" + UUID.randomUUID().toString().replace("-", "").substring(0, 8)
            : opt.scanId();
        progress.stage(3, "Parsing curl");
        RequestModel req = CurlParser.parse(opt.curl());
        RequestModel alt = opt.altCurl() == null || opt.altCurl().isBlank() ? null : CurlParser.parse(opt.altCurl());
        progress.stage(10, "Executing baseline request");
        HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(cfg.scanner.timeoutSeconds)).build();
        ResponseModel baseline = execute(client, req, cfg.scanner.timeoutSeconds);
        progress.stage(18, "Loading rule groups");
        List<Group> groups = loadGroups(cfg, opt.rulesFile());
        EndpointClassifier.EndpointContext endpoint = EndpointClassifier.classify(req);
        ResponseSemanticAnalyzer.Semantics baselineSemantics = ResponseSemanticAnalyzer.analyze(baseline);
        List<Finding> findings = evaluateGroups(client, cfg, groups, req, alt, baseline, endpoint, baselineSemantics, progress);
        progress.stage(88, "Preparing report");
        Map<String,Object> baselineExchange = exchangeSnapshot(req, baseline, cfg.reports.redactSecrets);
        Report finalReport = Reporter.build(scanId, started, Instant.now(), req.method, req.url, req.host, baselineExchange, groups, findings, new WebhookStatus());
        finalReport.type = endpoint.type();
        attachContext(finalReport, opt);
        progress.stage(90, "Generating AI summary");
        AiSummaryService.enrich(cfg, finalReport);
        progress.stage(94, "Writing JSON report");
        Reporter.WriteResult wr = Reporter.writeJson(finalReport, cfg);
        progress.stage(97, "Sending webhook");
        WebhookStatus ws = WebhookClient.send(cfg, scanId, wr.payload());
        finalReport.webhook = ws;
        progress.stage(100, "Completed");
        progress.done();
        return new Result(finalReport, wr.path());
    }

    private static void attachContext(Report report, Options options) {
        if (report == null || options == null) {
            return;
        }
        report.application = options.application();
        report.resource = options.resource();
    }

    private static List<Group> loadGroups(AppConfig cfg, String explicit) throws Exception {
        if (explicit == null || explicit.isBlank()) {
            List<Group> configured = RuleLoader.loadDir(cfg.rules.directory, cfg.rules.activeGroups);
            if (!configured.isEmpty()) return configured;
            return RuleLoader.loadDir(cfg.rules.directory, List.of());
        }
        java.nio.file.Path p = java.nio.file.Path.of(explicit);
        if (java.nio.file.Files.exists(p)) return List.of(RuleLoader.loadFile(p));
        for (Group g : RuleLoader.loadDir(cfg.rules.directory, List.of())) {
            if (explicit.equals(g.id) || explicit.equals(g.name) || explicit.equals(RuleLoader.displayKey(g))) return List.of(g);
        }
        java.nio.file.Path byName = java.nio.file.Path.of(cfg.rules.directory, explicit.endsWith(".json") ? explicit : explicit + ".json");
        if (java.nio.file.Files.exists(byName)) return List.of(RuleLoader.loadFile(byName));
        throw new IllegalArgumentException("rule group not found: " + explicit);
    }

    public static ResponseModel execute(HttpClient client, RequestModel req, int timeoutSeconds) {
        long start = System.nanoTime();
        ResponseModel rm = new ResponseModel();
        try {
            HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(req.url)).timeout(Duration.ofSeconds(timeoutSeconds));
            req.headers.forEach((k, vals) -> vals.forEach(v -> b.header(k, v)));
            b.method(req.method, req.body.length > 0 ? HttpRequest.BodyPublishers.ofByteArray(req.body) : HttpRequest.BodyPublishers.noBody());
            HttpResponse<byte[]> res = client.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
            rm.statusCode = res.statusCode();
            rm.headers = res.headers().map();
            rm.body = res.body();
            rm.bodySize = rm.body.length;
            rm.contentType = rm.headers.getOrDefault("content-type", List.of("")).stream().findFirst().orElse("");
        } catch (Exception e) {
            rm.error = e.getMessage();
        }
        rm.durationMs = Duration.ofNanos(System.nanoTime() - start).toMillis();
        return rm;
    }

    private static List<Finding> evaluateGroups(HttpClient client, AppConfig cfg, List<Group> groups, RequestModel req, RequestModel alt, ResponseModel baseline,
                                                EndpointClassifier.EndpointContext endpoint, ResponseSemanticAnalyzer.Semantics baselineSemantics, ProgressSink progress) {
        List<Finding> out = new ArrayList<>();
        int total = groups.stream().mapToInt(g -> g.rules == null ? 0 : g.rules.size()).sum();
        int current = 0;
        for (Group g : groups) {
            if (!Evaluator.condition(g.precondition, req, baseline, baseline).passed()) {
                for (Rule r : g.rules) {
                    current++;
                    progress.rules(current, total, r.ruleId);
                    out.add(skipped(r, "rule group precondition did not match"));
                }
                continue;
            }
            for (Rule r : g.rules) {
                current++;
                progress.rules(current, total, r.ruleId);
                out.add(evaluateRule(client, cfg, r, req, alt, baseline, endpoint, baselineSemantics));
            }
        }
        return out;
    }

    static Finding evaluateRule(HttpClient client, AppConfig cfg, Rule rule, RequestModel req, RequestModel alt, ResponseModel baseline,
                                EndpointClassifier.EndpointContext endpoint, ResponseSemanticAnalyzer.Semantics baselineSemantics) {
        ScannerMetadata md = RuleLoader.metadata(rule);
        Finding f = base(rule, md);
        f.status = "SKIPPED";
        RuleApplicabilityService.Decision applicability = RuleApplicabilityService.applicable(rule.ruleId, req, endpoint, baselineSemantics);
        if (!applicability.applicable()) {
            f.evidence.put("reason", applicability.reason());
            f.evidence.put("endpointTypes", new ArrayList<>(endpoint.types()));
            return f;
        }
        String bola = bolaSkipReason(rule.ruleId, req);
        if (!bola.isBlank()) {
            f.evidence.put("reason", bola);
            f.evidence.put("endpointTypes", new ArrayList<>(endpoint.types()));
            return f;
        }
        if (!md.cves.isEmpty()) {
            f.evidence.put("reason", "CVE-specific rules require product/version fingerprint evidence and were skipped");
            return f;
        }
        if (md.destructive && !cfg.scanner.allowDangerous) {
            f.evidence.put("reason", "dangerous rule skipped; use --allow-dangerous for explicit opt-in");
            return f;
        }
        AuthCredential auth = detectAuth(req);
        if (md.requiresAuthContext && auth.kind.isBlank()) {
            f.evidence.put("reason", "auth context required but no supported credential was provided");
            return f;
        }
        if (isBearerAuthRule(rule.ruleId) && !hasHeader(req.headers, "Authorization")) {
            f.evidence.put("reason", "Authorization bearer token was not provided");
            return f;
        }
        List<Mutation> muts = authAwareMutations(rule.ruleId, md.mutations, auth);
        if (isAuthRemovalRule(rule.ruleId) && muts.isEmpty()) {
            f.evidence.put("reason", "No supported auth credential detected for this auth-removal rule");
            return f;
        }
        if (md.requiresAltContext && alt == null) {
            f.evidence.put("reason", "alternate low-privilege curl was not provided");
            return f;
        }
        if (md.passive || muts.isEmpty()) {
            Evaluator.Result ev = Evaluator.assertion(rule.assertion, req, baseline, baseline);
            f.status = ev.passed() ? "PASSED" : "FAILED";
            f.evidence.put("baselineStatus", baseline.statusCode);
            f.evidence.put("reason", ev.reason());
            attachPassiveLocation(f, rule);
            FindingQuality.annotatePassive(f, rule.ruleId, baseline, baselineSemantics);
            FindingNarratives.enrichEvidence(f, rule.ruleId, rule.name, null, true);
            return f;
        }
        int limit = cfg.scanner.maxRequestsPerRule <= 0 || cfg.scanner.maxRequestsPerRule > 3 ? 3 : cfg.scanner.maxRequestsPerRule;
        for (int i = 0; i < muts.size() && i < limit; i++) {
            Mutation spec = muts.get(i);
            Mutator.Result m = Mutator.generate(req, spec, cfg.scanner.allowDangerous);
            if (m.skipped) {
                f.evidence.put("mutation", spec.name);
                f.evidence.put("reason", m.reason);
                attachMutationLocation(f, spec);
                return f;
            }
            ResponseModel resp = md.requiresAltContext && alt != null ? execute(client, alt, cfg.scanner.timeoutSeconds) : execute(client, m.request, cfg.scanner.timeoutSeconds);
            ResponseSemanticAnalyzer.Semantics mutationSemantics = ResponseSemanticAnalyzer.analyze(resp);
            f.evidence.put("baselineStatus", baseline.statusCode);
            f.evidence.put("mutationStatus", resp.statusCode);
            f.evidence.put("mutation", spec.name);
            f.evidence.put("mutatedCredential", mutationTarget(spec));
            f.evidence.put("mutationExchange", exchangeSnapshot(md.requiresAltContext && alt != null ? alt : m.request, resp, cfg.reports.redactSecrets));
            attachMutationLocation(f, spec);
            if (!resp.error.isBlank()) {
                f.status = "ERROR";
                f.evidence.put("reason", resp.error);
                FindingNarratives.enrichEvidence(f, rule.ruleId, rule.name, spec, false);
                return f;
            }
            Evaluator.Result ev = Evaluator.assertion(rule.assertion, req, baseline, resp);
            f.status = ev.passed() ? "PASSED" : "FAILED";
            f.evidence.put("reason", f.status.equals("FAILED") && isAuthRemovalRule(rule.ruleId) ? "Endpoint returned " + resp.statusCode + " after " + mutationTarget(spec) + " was removed." : ev.reason());
            FindingQuality.annotateMutation(f, rule.ruleId, spec, baseline, resp, baselineSemantics, mutationSemantics, endpoint);
            FindingNarratives.enrichEvidence(f, rule.ruleId, rule.name, spec, false);
            return f;
        }
        f.evidence.put("reason", "no mutation generated");
        FindingNarratives.enrichEvidence(f, rule.ruleId, rule.name, null, false);
        return f;
    }

    private static Finding base(Rule r, ScannerMetadata md) {
        Finding f = new Finding();
        f.ruleId = r.ruleId;
        f.name = r.name;
        f.severity = r.priority;
        f.owasp = md.owasp;
        f.cwe = md.cwe;
        f.cves = md.cves;
        f.remediation = md.remediation;
        f.confidence = "NONE";
        f.certainty = "UNKNOWN";
        FindingNarratives.enrichStatic(f, r.ruleId, r.name, r.description, md.owasp);
        return f;
    }

    private static Finding skipped(Rule r, String reason) {
        Finding f = base(r, RuleLoader.metadata(r));
        f.status = "SKIPPED";
        f.evidence.put("reason", reason);
        return f;
    }

    public record AuthCredential(String kind, String name) {
    }

    static AuthCredential detectAuth(RequestModel r) {
        for (String h : List.of("Authorization", "X-API-Key", "x-apikey", "Api-Key", "X-Auth-Token"))
            for (String k : r.headers.keySet()) if (k.equalsIgnoreCase(h)) return new AuthCredential("header", k);
        for (String c : r.cookies.keySet()) if (isSessionCookie(c)) return new AuthCredential("cookie", c);
        for (String q : List.of("api_key", "apikey", "access_token", "token"))
            for (String k : r.query.keySet()) if (k.equalsIgnoreCase(q)) return new AuthCredential("query", k);
        return new AuthCredential("", "");
    }

    private static List<Mutation> authAwareMutations(String ruleId, List<Mutation> muts, AuthCredential auth) {
        if (!isAuthRemovalRule(ruleId)) return muts;
        if (auth.kind.isBlank()) return List.of();
        Mutation m = new Mutation();
        m.key = auth.name;
        m.name = "remove-" + auth.name.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "-").replaceAll("(^-|-$)", "") + "-" + ("query".equals(auth.kind) ? "query-param" : auth.kind);
        m.operation = switch (auth.kind) {
            case "header" -> "REMOVE_HEADER";
            case "cookie" -> "REMOVE_COOKIE";
            default -> "REMOVE_QUERY_PARAM";
        };
        return List.of(m);
    }

    private static boolean isAuthRemovalRule(String id) {
        return Set.of("API2-AUTH-001", "API2-AUTH-006").contains(id);
    }

    private static boolean isBearerAuthRule(String id) {
        return Set.of("API2-AUTH-002", "API2-AUTH-003").contains(id);
    }

    private static boolean hasHeader(Map<String, List<String>> h, String key) {
        return h.keySet().stream().anyMatch(k -> k.equalsIgnoreCase(key));
    }

    private static boolean isSessionCookie(String n) {
        String x = n.toLowerCase(Locale.ROOT);
        return Set.of("session", "sessionid", "sid", "jsessionid", "connect.sid", "auth", "token").contains(x) || x.contains("session");
    }

    private static String bolaSkipReason(String id, RequestModel r) {
        if ("API1-BOLA-001".equals(id) && Arrays.stream(r.path.split("/")).noneMatch(p -> p.matches("^\\d+$")))
            return "No object identifier detected.";
        if (Set.of("API1-BOLA-002", "API1-BOLA-005").contains(id) && r.query.keySet().stream().noneMatch(k -> Set.of("id", "userId", "accountId", "orgId", "tenantId", "orderId", "permissionId").stream().anyMatch(x -> x.equalsIgnoreCase(k))))
            return "No object identifier detected.";
        Pattern uuid = Pattern.compile("(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
        if ("API1-BOLA-003".equals(id) && !uuid.matcher(r.path).find() && r.query.values().stream().flatMap(List::stream).noneMatch(v -> uuid.matcher(v).find()))
            return "No object identifier detected.";
        if ("API1-BOLA-004".equals(id) && List.of("X-Tenant-ID", "X-Org-ID", "Organization-ID", "Org-ID", "Tenant-ID").stream().noneMatch(h -> hasHeader(r.headers, h)))
            return "No object identifier detected.";
        return "";
    }

    private static String mutationTarget(Mutation m) {
        return switch (m.operation) {
            case "REMOVE_HEADER", "REPLACE_HEADER", "ADD_HEADER" -> m.key + " header";
            case "REMOVE_COOKIE" -> m.key + " cookie";
            case "REMOVE_QUERY_PARAM", "REPLACE_QUERY_PARAM", "ADD_QUERY_PARAM" -> m.key + " query parameter";
            default -> m.name;
        };
    }

    private static void attachMutationLocation(Finding finding, Mutation mutation) {
        if (finding == null || finding.evidence == null || mutation == null) return;
        Map<String, Object> location = new LinkedHashMap<>();
        switch (String.valueOf(mutation.operation)) {
            case "REPLACE_JSON_FIELD", "ADD_JSON_FIELD", "REMOVE_JSON_FIELD" -> {
                location.put("requestPart", "body");
                location.put("field", mutation.key);
            }
            case "REMOVE_HEADER", "REPLACE_HEADER", "ADD_HEADER" -> {
                location.put("requestPart", "header");
                location.put("field", mutation.key);
            }
            case "REMOVE_QUERY_PARAM", "REPLACE_QUERY_PARAM", "ADD_QUERY_PARAM", "LARGE_PAGINATION_LIMIT", "NEGATIVE_PAGINATION_LIMIT" -> {
                location.put("requestPart", "query");
                location.put("field", mutation.key);
            }
            case "REMOVE_COOKIE" -> {
                location.put("requestPart", "cookie");
                location.put("field", mutation.key);
            }
            case "REPLACE_PATH_ID" -> location.put("requestPart", "path");
            default -> {
                return;
            }
        }
        location.put("operation", mutation.operation);
        location.put("mutationName", mutation.name);
        finding.evidence.put("location", location);
    }

    private static void attachPassiveLocation(Finding finding, Rule rule) {
        if (finding == null || finding.evidence == null || rule == null || rule.assertion == null || rule.assertion.placeholders == null) return;
        for (Placeholder placeholder : rule.assertion.placeholders) {
            Map<String, Object> location = passiveLocation(placeholder);
            if (!location.isEmpty()) {
                location.put("mutationName", "baseline-passive-check");
                finding.evidence.put("location", location);
                return;
            }
        }
    }

    private static Map<String, Object> passiveLocation(Placeholder placeholder) {
        Map<String, Object> location = new LinkedHashMap<>();
        if (placeholder == null || placeholder.key == null || placeholder.key.isBlank()) return location;
        String key = placeholder.key;
        String operation = passiveOperation(placeholder.rule, key);
        if (key.startsWith("response.headers.")) {
            location.put("requestPart", "response-header");
            location.put("field", key.substring("response.headers.".length()));
        } else if (key.startsWith("baseline.headers.")) {
            location.put("requestPart", "baseline-header");
            location.put("field", key.substring("baseline.headers.".length()));
        } else if (key.equals("response.headers.*") || key.equals("response.headers.*~")) {
            location.put("requestPart", "response-header");
            location.put("field", "*");
        } else if (key.equals("baseline.headers.*") || key.equals("baseline.headers.*~")) {
            location.put("requestPart", "baseline-header");
            location.put("field", "*");
        } else if (key.startsWith("response.body.")) {
            location.put("requestPart", "response-body");
            location.put("field", key.substring("response.body.".length()));
        } else if (key.startsWith("baseline.body.")) {
            location.put("requestPart", "baseline-body");
            location.put("field", key.substring("baseline.body.".length()));
        } else if (key.equals("response.body")) {
            location.put("requestPart", "response-body");
        } else if (key.equals("baseline.body")) {
            location.put("requestPart", "baseline-body");
        } else if (key.equals("response.code") || key.equals("response.status") || key.equals("response.statusCode")) {
            location.put("requestPart", "response-status");
            location.put("field", "statusCode");
        } else if (key.equals("baseline.code") || key.equals("baseline.status") || key.equals("baseline.statusCode")) {
            location.put("requestPart", "baseline-status");
            location.put("field", "statusCode");
        } else {
            return location;
        }
        if (!operation.isBlank()) location.put("operation", operation);
        return location;
    }

    private static String passiveOperation(String rule, String key) {
        String normalizedRule = (rule == null || rule.isBlank()) ? "CHECK" : rule.trim().toUpperCase(Locale.ROOT);
        if (key.startsWith("response.headers.") || key.equals("response.headers.*") || key.equals("response.headers.*~")) {
            return normalizedRule + "_RESPONSE_HEADER";
        }
        if (key.startsWith("baseline.headers.") || key.equals("baseline.headers.*") || key.equals("baseline.headers.*~")) {
            return normalizedRule + "_BASELINE_HEADER";
        }
        if (key.startsWith("response.body.") || key.equals("response.body")) {
            return normalizedRule + "_RESPONSE_BODY";
        }
        if (key.startsWith("baseline.body.") || key.equals("baseline.body")) {
            return normalizedRule + "_BASELINE_BODY";
        }
        if (key.equals("response.code") || key.equals("response.status") || key.equals("response.statusCode")) {
            return normalizedRule + "_RESPONSE_STATUS";
        }
        if (key.equals("baseline.code") || key.equals("baseline.status") || key.equals("baseline.statusCode")) {
            return normalizedRule + "_BASELINE_STATUS";
        }
        return normalizedRule;
    }

    private static Map<String, Object> exchangeSnapshot(RequestModel request, ResponseModel response, boolean redactSecrets) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("request", requestSnapshot(request, redactSecrets));
        out.put("response", responseSnapshot(response, redactSecrets));
        return out;
    }

    private static Map<String, Object> requestSnapshot(RequestModel r, boolean redactSecrets) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("method", r.method);
        out.put("url", r.url);
        out.put("path", r.path);
        out.put("query", copyMap(r.query, redactSecrets));
        out.put("headers", copyMap(r.headers, redactSecrets));
        out.put("cookies", copyCookies(r.cookies, redactSecrets));
        out.put("bodySize", r.body == null ? 0 : r.body.length);
        out.put("body", bodyText(r.body, redactSecrets));
        if (r.formEncoding != null && !r.formEncoding.isBlank() && r.formFields != null && !r.formFields.isEmpty()) {
            Map<String, Object> form = new LinkedHashMap<>();
            form.put("encoding", r.formEncoding);
            List<Map<String, Object>> fields = new ArrayList<>();
            for (RequestModel.FormField field : r.formFields) {
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("name", field.name);
                item.put("value", field.value == null ? null : redactSecrets ? redactText(field.value) : field.value);
                item.put("contentType", field.contentType);
                item.put("filename", field.filename);
                fields.add(item);
            }
            form.put("fields", fields);
            out.put("form", form);
        }
        return out;
    }

    private static Map<String, Object> responseSnapshot(ResponseModel r, boolean redactSecrets) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("statusCode", r.statusCode);
        out.put("durationMs", r.durationMs);
        out.put("bodySize", r.bodySize);
        out.put("contentType", r.contentType);
        out.put("headers", copyMap(r.headers, redactSecrets));
        out.put("body", bodyText(r.body, redactSecrets));
        if (r.error != null && !r.error.isBlank()) out.put("error", r.error);
        return out;
    }

    private static Map<String, List<String>> copyMap(Map<String, List<String>> in, boolean redactSecrets) {
        Map<String, List<String>> out = new LinkedHashMap<>();
        if (in == null) return out;
        in.forEach((k, values) -> {
            if (redactSecrets && isSecretKey(k)) out.put(k, List.of("[REDACTED]"));
            else out.put(k, values == null ? List.of() : values.stream().map(v -> redactSecrets ? redactText(v) : v).toList());
        });
        return out;
    }

    private static Map<String, String> copyCookies(Map<String, String> in, boolean redactSecrets) {
        Map<String, String> out = new LinkedHashMap<>();
        if (in == null) return out;
        in.forEach((k, v) -> out.put(k, redactSecrets && isSecretKey(k) ? "[REDACTED]" : redactSecrets ? redactText(v) : v));
        return out;
    }

    private static String bodyText(byte[] body, boolean redactSecrets) {
        if (body == null || body.length == 0) return "";
        String text = new String(body, StandardCharsets.UTF_8);
        return redactSecrets ? redactText(text) : text;
    }

    private static String redactText(String text) {
        return com.apisec.redact.Redactor.text(text);
    }

    private static boolean isSecretKey(String key) {
        if (key == null) return false;
        String k = key.toLowerCase(Locale.ROOT);
        return Set.of("authorization", "cookie", "set-cookie", "x-api-key", "x-apikey", "api_key", "apikey", "access_token", "refresh_token", "token", "password", "passwd", "secret", "client_secret", "private_key").contains(k);
    }
}
