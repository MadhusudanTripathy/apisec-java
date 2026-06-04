package com.apisec.report;

import com.apisec.config.AppConfig;
import com.apisec.redact.Redactor;
import com.apisec.report.ReportModels.*;
import com.apisec.rules.RuleModels.Group;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.io.*;
import java.nio.file.*;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class Reporter {
  public record DisplayOptions(boolean jsonOnly, boolean showPassed, boolean showSkipped, boolean verbose) {}
  private static final ObjectMapper MAPPER = new ObjectMapper().registerModule(new JavaTimeModule()).disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

  public static Report build(String id, Instant started, Instant finished, String method, String url, String host, List<Group> groups, List<Finding> findings, WebhookStatus ws) {
    Report r = new Report(); r.scanId = id; r.startedAt = started; r.finishedAt = finished; r.durationMs = Duration.between(started, finished).toMillis();
    r.target.method = method; r.target.url = url; r.target.host = host; r.findings = findings; r.webhook = ws;
    for (Group g: groups) { RuleGroupInfo i = new RuleGroupInfo(); i.name = g.name; i.version = g.version(); r.ruleGroups.add(i); }
    for (Finding f: findings) {
      r.summary.totalRules++;
      switch (f.status) {
        case "PASSED" -> r.summary.passed++;
        case "SKIPPED" -> r.summary.skipped++;
        case "ERROR" -> r.summary.errors++;
        case "FAILED" -> { r.summary.failed++; switch (String.valueOf(f.severity).toUpperCase(Locale.ROOT)) {
          case "CRITICAL" -> r.summary.critical++; case "HIGH" -> r.summary.high++; case "MEDIUM" -> r.summary.medium++; case "LOW" -> r.summary.low++;
        }}
      }
    }
    return r;
  }

  public static WriteResult writeJson(Report r, AppConfig cfg) throws IOException {
    JsonNode n = MAPPER.valueToTree(r);
    if (cfg.reports.redactSecrets) Redactor.json(n);
    String json = MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(n);
    Files.createDirectories(Path.of(cfg.reports.directory));
    String ts = DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss").withZone(ZoneOffset.UTC).format(r.startedAt);
    String name = cfg.reports.fileNamePattern.replace("{timestamp}", ts).replace("{scanId}", r.scanId);
    Path p = Path.of(cfg.reports.directory, name);
    Files.writeString(p, json);
    return new WriteResult(p.toString(), json.getBytes());
  }

  public static void print(Report r, String exportPath, DisplayOptions opts) throws IOException {
    if (opts.jsonOnly()) { System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(r)); return; }
    boolean showPassed = opts.showPassed() || opts.verbose(), showSkipped = opts.showSkipped() || opts.verbose();
    System.out.println("API Security Scan Report");
    System.out.printf("Scan: %s   Duration: %dms%n", r.scanId, r.durationMs);
    System.out.printf("Target: %s %s%n", r.target.method, Redactor.text(r.target.url));
    if (!r.ruleGroups.isEmpty()) System.out.printf("Rule Group: %s v%s%n", r.ruleGroups.get(0).name, r.ruleGroups.get(0).version);
    System.out.println();
    System.out.println("Summary");
    table(List.of(List.of("Total","Passed","Failed","Skipped","Errors"), List.of(""+r.summary.totalRules,""+r.summary.passed,""+r.summary.failed,""+r.summary.skipped,""+r.summary.errors)));
    System.out.println();
    System.out.println("Failed Severity");
    table(List.of(List.of("Critical","High","Medium","Low"), List.of(""+r.summary.critical,""+r.summary.high,""+r.summary.medium,""+r.summary.low)));
    System.out.println();
    System.out.println("Critical/High Failed Findings"); failedTable(r.findings, Set.of("CRITICAL","HIGH"));
    System.out.println();
    System.out.println("Medium/Low Failed Findings"); failedTable(r.findings, Set.of("MEDIUM","LOW"));
    if (showPassed) { System.out.println(); System.out.println("Passed Checks"); statusTable(r.findings, "PASSED"); }
    if (showSkipped) { System.out.println(); System.out.println("Skipped Rules"); statusTable(r.findings, "SKIPPED"); }
    else if (r.summary.skipped > 0) { System.out.println(); System.out.printf("Skipped Rules: %d (use --show-skipped or --verbose for details)%n", r.summary.skipped); }
    System.out.println();
    System.out.println("Critical Details");
    int critical = 0;
    for (Finding f: r.findings) if ("FAILED".equals(f.status) && "CRITICAL".equalsIgnoreCase(f.severity)) {
      critical++; System.out.printf("[%s] %s %s%nOWASP: %s%nCWE: %s%nEvidence: %s%nFix: %s%n%n", f.severity, f.ruleId, f.name, f.owasp, String.join(", ", f.cwe), humanEvidence(f), f.remediation);
    }
    if (critical == 0) System.out.println("None");
    System.out.println(); System.out.println("Exports"); System.out.println("JSON: " + exportPath); System.out.println("Webhook: " + (r.webhook.enabled ? (r.webhook.delivered ? "delivered" : "failed") : "disabled"));
  }

  private static void failedTable(List<Finding> findings, Set<String> severities) {
    List<List<String>> rows = new ArrayList<>(); rows.add(List.of("Severity","Rule","OWASP","Result"));
    for (Finding f: findings) if ("FAILED".equals(f.status) && severities.contains(String.valueOf(f.severity).toUpperCase(Locale.ROOT))) rows.add(List.of(f.severity, f.ruleId, f.owasp, humanEvidence(f)));
    if (rows.size() == 1) System.out.println("No failed findings"); else table(rows);
  }
  private static void statusTable(List<Finding> findings, String status) {
    List<List<String>> rows = new ArrayList<>(); rows.add(List.of("Severity","Rule","OWASP","Reason"));
    for (Finding f: findings) if (status.equals(f.status)) rows.add(List.of(f.severity, f.ruleId, f.owasp, "PASSED".equals(status) ? f.name : String.valueOf(f.evidence.getOrDefault("reason", "-"))));
    if (rows.size() == 1) System.out.println("No " + status.toLowerCase(Locale.ROOT) + " rules"); else table(rows);
  }
  private static String humanEvidence(Finding f) {
    Object target = f.evidence.get("mutatedCredential"), st = f.evidence.get("mutationStatus");
    if (target != null && st != null) return Redactor.text("Endpoint returned " + st + " after " + target + " was removed.");
    if (f.evidence.get("baselineStatus") != null) return "Baseline returned " + f.evidence.get("baselineStatus") + " and matched the rule condition.";
    return Redactor.text(String.valueOf(f.evidence.getOrDefault("reason", "See JSON report for evidence.")));
  }
  private static void table(List<List<String>> rows) {
    int cols = rows.get(0).size(); int[] w = new int[cols];
    for (List<String> row: rows) for (int i=0; i<cols; i++) w[i] = Math.max(w[i], Math.min(70, row.get(i).length()));
    border(w); for (int r=0; r<rows.size(); r++) { System.out.print("|"); for (int c=0; c<cols; c++) System.out.printf(" %-" + w[c] + "s |", clip(rows.get(r).get(c), w[c])); System.out.println(); if (r == 0) border(w); } border(w);
  }
  private static String clip(String s, int w) { s = s == null ? "-" : s.replaceAll("\\s+", " "); return s.length() > w ? s.substring(0, Math.max(0,w-3)) + "..." : s; }
  private static void border(int[] w) { System.out.print("+"); for (int x: w) System.out.print("-".repeat(x+2) + "+"); System.out.println(); }
  public record WriteResult(String path, byte[] payload) {}
}
