package com.apisec.report;

import com.apisec.config.AppConfig;
import com.apisec.redact.Redactor;
import com.apisec.report.ReportModels.*;
import com.apisec.rules.RuleModels.Group;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.io.*;
import java.nio.file.*;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class Reporter {
  public record DisplayOptions(boolean jsonOnly, boolean showPassed, boolean showSkipped, boolean verbose) {}
  public record ApplicationScanEntry(
      String applicationId,
      String applicationName,
      String resourceId,
      String method,
      String endpoint,
      String operationId,
      long durationMs,
      int findings,
      String maxSeverity,
      String aiStatus,
      String webhookStatus,
      String exportPath,
      String error,
      List<Finding> findingsDetail) {}
  private static final ObjectMapper MAPPER = new ObjectMapper().registerModule(new JavaTimeModule()).disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

  public static Report build(String id, Instant started, Instant finished, String method, String url, String host, Map<String,Object> baseline, List<Group> groups, List<Finding> findings, WebhookStatus ws) {
    Report r = new Report(); r.scanId = id; r.startedAt = started; r.finishedAt = finished; r.durationMs = Duration.between(started, finished).toMillis();
    r.target.method = method; r.target.url = url; r.target.host = host; r.baseline = baseline == null ? new LinkedHashMap<>() : baseline; r.webhook = ws;
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
    r.totalFindings = r.summary.failed;
    r.maxSeverity = maxSeverity(r.summary);
    r.findings = findings.stream().filter(Reporter::isDetectedFinding).toList();
    return r;
  }

  public static Report build(String id, Instant started, Instant finished, String method, String url, String host, List<Group> groups, List<Finding> findings, WebhookStatus ws) {
    return build(id, started, finished, method, url, host, new LinkedHashMap<>(), groups, findings, ws);
  }

  private static boolean isDetectedFinding(Finding f) {
    return "FAILED".equals(f.status);
  }

  public static WriteResult writeJson(Report r, AppConfig cfg) throws IOException {
    JsonNode n = toJson(r);
    if (cfg.reports.redactSecrets) Redactor.json(n);
    String json = MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(n);
    Files.createDirectories(Path.of(cfg.reports.directory));
    String ts = DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss").withZone(ZoneOffset.UTC).format(r.startedAt);
    String baseName = cfg.reports.fileNamePattern.replace("{timestamp}", ts).replace("{scanId}", r.scanId);
    Path p = nextAvailablePath(Path.of(cfg.reports.directory), baseName);
    Files.writeString(p, json);
    return new WriteResult(p.toString(), json.getBytes());
  }

  private static Path nextAvailablePath(Path dir, String fileName) {
    Path candidate = dir.resolve(fileName);
    if (!Files.exists(candidate)) return candidate;
    int dot = fileName.lastIndexOf('.');
    String stem = dot >= 0 ? fileName.substring(0, dot) : fileName;
    String ext = dot >= 0 ? fileName.substring(dot) : "";
    int suffix = 2;
    while (true) {
      candidate = dir.resolve(stem + "_" + suffix + ext);
      if (!Files.exists(candidate)) return candidate;
      suffix++;
    }
  }

  public static void print(Report r, String exportPath, DisplayOptions opts) throws IOException {
    if (opts.jsonOnly()) { System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(toJson(r))); return; }
    boolean showPassed = opts.showPassed() || opts.verbose(), showSkipped = opts.showSkipped() || opts.verbose();
    System.out.println("API Security Scan");
    System.out.println("=".repeat(96));
    System.out.printf("Scan ID      %s%n", r.scanId);
    System.out.printf("Duration     %dms%n", r.durationMs);
    if (r.application != null) {
      System.out.printf("Application  %s (%s)%n",
          Redactor.text(String.valueOf(r.application.name == null || r.application.name.isBlank() ? r.application.applicationId : r.application.name)),
          Redactor.text(String.valueOf(r.application.applicationId)));
    }
    if (r.resource != null && r.resource.swaggerName != null) {
      System.out.printf("Swagger      %s%n", Redactor.text(r.resource.swaggerName));
    }
    System.out.printf("Target       %s %s%n", r.target.method, Redactor.text(r.target.url));
    if (!r.ruleGroups.isEmpty()) System.out.printf("Rule Group   %s v%s%n", r.ruleGroups.get(0).name, r.ruleGroups.get(0).version);
    System.out.printf("AI Summary   %s%n", aiStatusLabel(r));
    System.out.printf("Webhook      %s%n", webhookStatusLabel(r.webhook));
    System.out.println();
    System.out.println("Overview");
    table(List.of(
        List.of("Total","Failed","Passed","Skipped","Errors","Critical","High","Medium","Low"),
        List.of(""+r.summary.totalRules,""+r.summary.failed,""+r.summary.passed,""+r.summary.skipped,""+r.summary.errors,
            ""+r.summary.critical,""+r.summary.high,""+r.summary.medium,""+r.summary.low)
    ));
    System.out.println();
    System.out.println("Top Findings");
    failedTable(topFindings(r.findings, 8), Set.of("CRITICAL","HIGH","MEDIUM","LOW"));
    System.out.println();
    System.out.println("Severity Breakdown");
    severitySummary(r.summary);
    if (r.aiSummary != null && r.aiUsed) {
      System.out.println();
      System.out.println("AI Overview");
      printKeyValue("Overview", r.aiSummary.overview);
    } else if (r.aiError != null && !r.aiError.isBlank()) {
      System.out.println();
      System.out.println("AI Overview");
      printKeyValue("Status", aiStatusLabel(r));
      printKeyValue("Detail", r.aiError);
    }
    if (showPassed) { System.out.println(); System.out.println("Passed Checks"); statusTable(r.findings, "PASSED"); }
    if (showSkipped) { System.out.println(); System.out.println("Skipped Rules"); statusTable(r.findings, "SKIPPED"); }
    else if (r.summary.skipped > 0) { System.out.println(); System.out.printf("Skipped Rules: %d (use --show-skipped or --verbose for details)%n", r.summary.skipped); }
    System.out.println();
    System.out.println("Critical Details");
    printDetailedFindings(r.findings, "CRITICAL", 3);
    System.out.println();
    System.out.println("Exports");
    System.out.println("JSON     " + exportPath);
    System.out.println("Webhook  " + webhookStatusLabel(r.webhook));
  }

  public static ApplicationScanEntry applicationEntry(Report report, String exportPath) {
    String endpoint = "-";
    String operationId = "";
    String resourceId = "";
    String method = report == null || report.target == null ? "GET" : firstNonBlank(report.target.method, "GET");
    String appId = "";
    String appName = "";
    if (report != null) {
      if (report.application != null) {
        appId = firstNonBlank(report.application.applicationId, report.application.applicationProfileId);
        appName = firstNonBlank(report.application.name, appId);
      }
      if (report.resource != null) {
        resourceId = firstNonBlank(report.resource.resourceId);
        operationId = firstNonBlank(report.resource.operationId);
        endpoint = firstNonBlank(report.resource.path, report.target == null ? "" : report.target.url, "-");
      } else if (report.target != null) {
        endpoint = firstNonBlank(report.target.url, "-");
      }
    }
    return new ApplicationScanEntry(
        appId,
        appName,
        resourceId,
        method,
        endpoint,
        operationId,
        report == null ? 0 : report.durationMs,
        report == null ? 0 : report.totalFindings,
        report == null ? "ERROR" : firstNonBlank(report.maxSeverity, "NONE"),
        report == null ? "DISABLED" : firstNonBlank(report.aiStatus, "DISABLED"),
        report == null ? "disabled" : webhookStatusLabel(report.webhook),
        exportPath,
        null,
        report == null ? List.of() : report.findings);
  }

  public static ApplicationScanEntry failedApplicationEntry(String applicationId, String applicationName, String resourceId, String method, String endpoint, String operationId, String error) {
    return new ApplicationScanEntry(
        applicationId,
        applicationName,
        resourceId,
        firstNonBlank(method, "GET"),
        firstNonBlank(endpoint, "-"),
        firstNonBlank(operationId, ""),
        0,
        0,
        "ERROR",
        "FAILED",
        "not-sent",
        "",
        firstNonBlank(error, "scan failed"),
        List.of());
  }

  public static void printApplicationSummary(String requestedApplicationId, List<ApplicationScanEntry> entries, int resolvedResources, int skippedResources, long durationMs) {
    if (entries == null || entries.isEmpty()) {
      System.out.println("No scan results available.");
      return;
    }
    String appName = entries.stream().map(ApplicationScanEntry::applicationName).filter(Reporter::notBlank).findFirst().orElse("");
    String appId = entries.stream().map(ApplicationScanEntry::applicationId).filter(Reporter::notBlank).findFirst().orElse(requestedApplicationId);
    int errors = (int) entries.stream().filter(e -> notBlank(e.error())).count();
    int scanned = Math.max(0, entries.size() - errors);
    int totalFindings = entries.stream().mapToInt(ApplicationScanEntry::findings).sum();
    int critical = 0, high = 0, medium = 0, low = 0;
    List<FindingWithEndpoint> topFindings = new ArrayList<>();
    for (ApplicationScanEntry entry : entries) {
      for (Finding finding : entry.findingsDetail()) {
        if (!"FAILED".equals(finding.status)) continue;
        switch (String.valueOf(finding.severity).toUpperCase(Locale.ROOT)) {
          case "CRITICAL" -> critical++;
          case "HIGH" -> high++;
          case "MEDIUM" -> medium++;
          case "LOW" -> low++;
        }
        topFindings.add(new FindingWithEndpoint(entry, finding));
      }
    }
    topFindings.sort(Comparator
        .comparingInt((FindingWithEndpoint item) -> severityRank(item.finding.severity))
        .thenComparing(item -> String.valueOf(item.finding.ruleId))
        .thenComparing(item -> item.entry.endpoint()));

    System.out.println("Application API Security Scan");
    System.out.println("=".repeat(120));
    System.out.printf("Application     %s%n", Redactor.text(firstNonBlank(appName, appId)));
    System.out.printf("Application ID  %s%n", Redactor.text(firstNonBlank(appId, requestedApplicationId)));
    System.out.printf("Duration        %dms%n", durationMs);
    System.out.println();
    System.out.println("Overview");
    table(List.of(
        List.of("Resolved","Scanned","Skipped","Errors","Findings","Critical","High","Medium","Low","Max"),
        List.of(
            String.valueOf(resolvedResources),
            String.valueOf(scanned),
            String.valueOf(skippedResources),
            String.valueOf(errors),
            String.valueOf(totalFindings),
            String.valueOf(critical),
            String.valueOf(high),
            String.valueOf(medium),
            String.valueOf(low),
            maxSeverity(critical, high, medium, low))
    ));
    System.out.println();
    System.out.println("Endpoints");
    List<List<String>> endpointRows = new ArrayList<>();
    endpointRows.add(List.of("#","Method","Endpoint","Op","Findings","Max","AI","Webhook","Duration","Result"));
    int index = 0;
    for (ApplicationScanEntry entry : entries) {
      index++;
      endpointRows.add(List.of(
          String.valueOf(index),
          firstNonBlank(entry.method(), "GET"),
          firstNonBlank(entry.endpoint(), "-"),
          firstNonBlank(entry.operationId(), "-"),
          String.valueOf(entry.findings()),
          firstNonBlank(entry.maxSeverity(), "NONE"),
          firstNonBlank(entry.aiStatus(), "DISABLED"),
          firstNonBlank(entry.webhookStatus(), "disabled"),
          entry.durationMs() > 0 ? entry.durationMs() + "ms" : "-",
          notBlank(entry.error()) ? entry.error() : "completed"
      ));
    }
    table(endpointRows);
    System.out.println();
    System.out.println("Top Findings Across Endpoints");
    if (topFindings.isEmpty()) {
      System.out.println("No failed findings");
    } else {
      List<List<String>> findingRows = new ArrayList<>();
      findingRows.add(List.of("Severity","Rule","Endpoint","Confidence","Certainty","Result"));
      for (FindingWithEndpoint item : topFindings.stream().limit(12).toList()) {
        findingRows.add(List.of(
            firstNonBlank(item.finding.severity, "-"),
            firstNonBlank(item.finding.ruleId, "-"),
            firstNonBlank(item.entry.endpoint(), "-"),
            firstNonBlank(item.finding.confidence, "-"),
            firstNonBlank(item.finding.certainty, "-"),
            humanEvidence(item.finding)
        ));
      }
      table(findingRows);
    }
  }

  private static void failedTable(List<Finding> findings, Set<String> severities) {
    List<List<String>> rows = new ArrayList<>(); rows.add(List.of("Severity","Confidence","Certainty","Rule","OWASP","Result"));
    for (Finding f: findings) if ("FAILED".equals(f.status) && severities.contains(String.valueOf(f.severity).toUpperCase(Locale.ROOT))) rows.add(List.of(f.severity, f.confidence, f.certainty, f.ruleId, f.owasp, humanEvidence(f)));
    if (rows.size() == 1) System.out.println("No failed findings"); else table(rows);
  }
  private static void severitySummary(Summary s) {
    System.out.printf("Critical  %d%n", s.critical);
    System.out.printf("High      %d%n", s.high);
    System.out.printf("Medium    %d%n", s.medium);
    System.out.printf("Low       %d%n", s.low);
  }
  private static void statusTable(List<Finding> findings, String status) {
    List<List<String>> rows = new ArrayList<>(); rows.add(List.of("Severity","Rule","OWASP","Reason"));
    for (Finding f: findings) if (status.equals(f.status)) rows.add(List.of(f.severity, f.ruleId, f.owasp, "PASSED".equals(status) ? f.name : String.valueOf(f.evidence.getOrDefault("reason", "-"))));
    if (rows.size() == 1) System.out.println("No " + status.toLowerCase(Locale.ROOT) + " rules"); else table(rows);
  }
  private static List<Finding> topFindings(List<Finding> findings, int max) {
    if (findings == null) return List.of();
    return findings.stream()
        .filter(f -> "FAILED".equals(f.status))
        .sorted(Comparator.comparingInt((Finding f) -> severityRank(f.severity)).thenComparing(f -> String.valueOf(f.ruleId)))
        .limit(max)
        .toList();
  }
  private static int severityRank(String severity) {
    return switch (String.valueOf(severity).toUpperCase(Locale.ROOT)) {
      case "CRITICAL" -> 0;
      case "HIGH" -> 1;
      case "MEDIUM" -> 2;
      case "LOW" -> 3;
      default -> 4;
    };
  }
  private static void printDetailedFindings(List<Finding> findings, String severity, int limit) {
    int count = 0;
    for (Finding f: findings) if ("FAILED".equals(f.status) && severity.equalsIgnoreCase(f.severity)) {
      count++;
      System.out.printf("[%s] %s %s%n", f.severity, f.ruleId, Redactor.text(f.name));
      printKeyValue("OWASP", f.owasp);
      printKeyValue("Confidence", firstNonBlank(f.confidence, "-") + " / " + firstNonBlank(f.certainty, "-"));
      printKeyValue("Description", f.description);
      printKeyValue("Impact", f.impact);
      if (f.ai != null) {
        printKeyValue("AI Risk", f.ai.whyDangerous);
        printKeyValue("AI Fix", f.ai.remediation);
        printKeyValue("AI Impact", f.ai.businessImpact);
        printKeyValue("AI Evidence", firstNonBlank(f.ai.evidenceTitle, ""));
        printKeyValue("AI Detail", f.ai.evidenceSummary);
      }
      printKeyValue("Evidence", humanEvidence(f));
      printKeyValue("Fix", f.remediation);
      System.out.println();
      if (count >= limit) return;
    }
    if (count == 0) System.out.println("None");
  }
  private static void printKeyValue(String label, String value) {
    if (value == null || value.isBlank()) return;
    System.out.printf("%-16s%s%n", label, Redactor.text(value));
  }
  private static String webhookStatusLabel(WebhookStatus webhook) {
    if (webhook == null || !webhook.enabled) return "disabled";
    if (webhook.delivered) return "delivered";
    return firstNonBlank(webhook.error, "failed");
  }
  private static String aiStatusLabel(Report report) {
    if (report == null) return "disabled";
    if (report.aiUsed && report.aiSummary != null) return "used";
    return firstNonBlank(report.aiStatus, "disabled").toLowerCase(Locale.ROOT);
  }
  private static String humanEvidence(Finding f) {
    Object reason = f.evidence.get("reason");
    if (reason != null && !String.valueOf(reason).isBlank()) return Redactor.text(String.valueOf(reason));
    Object target = f.evidence.get("mutatedCredential"), st = f.evidence.get("mutationStatus");
    if (target != null && st != null) return Redactor.text("Endpoint returned " + st + " after " + target + " mutation.");
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
  private static String firstNonBlank(String... values) {
    for (String value : values) {
      if (value != null && !value.isBlank()) return value;
    }
    return "";
  }

  private static String maxSeverity(Summary summary) {
    if (summary == null || summary.failed <= 0) return "NONE";
    if (summary.critical > 0) return "CRITICAL";
    if (summary.high > 0) return "HIGH";
    if (summary.medium > 0) return "MEDIUM";
    if (summary.low > 0) return "LOW";
    return "NONE";
  }

  private static String maxSeverity(int critical, int high, int medium, int low) {
    if (critical > 0) return "CRITICAL";
    if (high > 0) return "HIGH";
    if (medium > 0) return "MEDIUM";
    if (low > 0) return "LOW";
    return "NONE";
  }

  private static boolean notBlank(String value) {
    return value != null && !value.isBlank();
  }

  private record FindingWithEndpoint(ApplicationScanEntry entry, Finding finding) {}

  private static JsonNode toJson(Report r) {
    ObjectNode root = MAPPER.createObjectNode();
    put(root, "scanId", r.scanId);
    if (r.startedAt != null) put(root, "startedAt", r.startedAt.toString());
    if (r.finishedAt != null) put(root, "finishedAt", r.finishedAt.toString());
    root.put("durationMs", r.durationMs);
    put(root, "maxSeverity", r.maxSeverity);
    root.put("totalFindings", r.totalFindings);
    root.put("aiUsed", r.aiUsed);
    put(root, "aiStatus", r.aiStatus);
    put(root, "aiError", r.aiError);
    if (r.aiSummary != null) root.set("aiSummary", aiSummaryNode(r.aiSummary));
    if (r.application != null) root.set("application", applicationNode(r.application));
    if (r.resource != null) root.set("resource", resourceNode(r.resource));
    root.set("target", targetNode(r.target));
    root.set("baseline", MAPPER.valueToTree(r.baseline == null ? new LinkedHashMap<>() : r.baseline));
    root.set("ruleGroups", ruleGroupsNode(r.ruleGroups));
    root.set("summary", summaryNode(r.summary));
    root.set("findings", findingsNode(r.findings));
    root.set("webhook", webhookNode(r.webhook));
    return root;
  }

  private static ObjectNode applicationNode(Application application) {
    ObjectNode node = MAPPER.createObjectNode();
    put(node, "applicationProfileId", application.applicationProfileId);
    put(node, "applicationId", application.applicationId);
    put(node, "name", application.name);
    put(node, "description", application.description);
    node.set("swaggerIds", stringArray(application.swaggerIds));
    return node;
  }

  private static ObjectNode resourceNode(Resource resource) {
    ObjectNode node = MAPPER.createObjectNode();
    put(node, "resourceId", resource.resourceId);
    put(node, "swaggerDocumentId", resource.swaggerDocumentId);
    put(node, "swaggerId", resource.swaggerId);
    put(node, "swaggerName", resource.swaggerName);
    if (resource.revision != null) node.put("revision", resource.revision);
    put(node, "status", resource.status);
    put(node, "baseUrl", resource.baseUrl);
    put(node, "path", resource.path);
    put(node, "method", resource.method);
    put(node, "operationId", resource.operationId);
    put(node, "summary", resource.summary);
    node.set("tags", stringArray(resource.tags));
    node.set("servers", stringArray(resource.servers));
    return node;
  }

  private static ObjectNode targetNode(Target target) {
    ObjectNode node = MAPPER.createObjectNode();
    if (target == null) return node;
    put(node, "method", target.method);
    put(node, "url", target.url);
    put(node, "host", target.host);
    return node;
  }

  private static ArrayNode ruleGroupsNode(List<RuleGroupInfo> groups) {
    ArrayNode array = MAPPER.createArrayNode();
    if (groups == null) return array;
    for (RuleGroupInfo group : groups) {
      ObjectNode node = MAPPER.createObjectNode();
      put(node, "name", group.name);
      put(node, "version", group.version);
      array.add(node);
    }
    return array;
  }

  private static ObjectNode summaryNode(Summary summary) {
    ObjectNode node = MAPPER.createObjectNode();
    if (summary == null) return node;
    node.put("totalRules", summary.totalRules);
    node.put("passed", summary.passed);
    node.put("failed", summary.failed);
    node.put("skipped", summary.skipped);
    node.put("errors", summary.errors);
    node.put("critical", summary.critical);
    node.put("high", summary.high);
    node.put("medium", summary.medium);
    node.put("low", summary.low);
    return node;
  }

  private static ObjectNode aiSummaryNode(AiSummary aiSummary) {
    ObjectNode node = MAPPER.createObjectNode();
    if (aiSummary == null) return node;
    put(node, "model", aiSummary.model);
    if (aiSummary.generatedAt != null) put(node, "generatedAt", aiSummary.generatedAt.toString());
    put(node, "overview", aiSummary.overview);
    return node;
  }

  private static ArrayNode findingsNode(List<Finding> findings) {
    ArrayNode array = MAPPER.createArrayNode();
    if (findings == null) return array;
    for (Finding finding : findings) {
      ObjectNode node = MAPPER.createObjectNode();
      put(node, "ruleId", finding.ruleId);
      put(node, "name", finding.name);
      put(node, "description", finding.description);
      put(node, "impact", finding.impact);
      put(node, "severity", finding.severity);
      put(node, "owasp", finding.owasp);
      put(node, "status", finding.status);
      put(node, "confidence", finding.confidence);
      put(node, "certainty", finding.certainty);
      put(node, "remediation", finding.remediation);
      if (finding.ai != null) node.set("ai", findingAiNode(finding.ai));
      node.set("cwe", stringArray(finding.cwe));
      node.set("cves", stringArray(finding.cves));
      node.set("evidence", MAPPER.valueToTree(finding.evidence == null ? new LinkedHashMap<>() : finding.evidence));
      array.add(node);
    }
    return array;
  }

  private static ObjectNode webhookNode(WebhookStatus webhook) {
    ObjectNode node = MAPPER.createObjectNode();
    if (webhook == null) return node;
    node.put("enabled", webhook.enabled);
    node.put("delivered", webhook.delivered);
    node.put("statusCode", webhook.statusCode);
    node.put("attempts", webhook.attempts);
    put(node, "error", webhook.error);
    return node;
  }

  private static ObjectNode findingAiNode(FindingAiSummary ai) {
    ObjectNode node = MAPPER.createObjectNode();
    if (ai == null) return node;
    put(node, "whyDangerous", ai.whyDangerous);
    put(node, "remediation", ai.remediation);
    put(node, "businessImpact", ai.businessImpact);
    put(node, "evidenceTitle", ai.evidenceTitle);
    put(node, "evidenceSummary", ai.evidenceSummary);
    return node;
  }

  private static ArrayNode stringArray(List<String> values) {
    ArrayNode array = MAPPER.createArrayNode();
    if (values == null) return array;
    for (String value : values) if (value != null) array.add(value);
    return array;
  }

  private static void put(ObjectNode node, String field, String value) {
    if (value != null) node.put(field, value);
  }
  public record WriteResult(String path, byte[] payload) {}
}
