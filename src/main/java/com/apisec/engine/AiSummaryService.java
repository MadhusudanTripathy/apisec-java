package com.apisec.engine;

import com.apisec.config.AppConfig;
import com.apisec.report.ReportModels.AiSummary;
import com.apisec.report.ReportModels.Finding;
import com.apisec.report.ReportModels.FindingAiSummary;
import com.apisec.report.ReportModels.Report;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

final class AiSummaryService {
  private static final ObjectMapper MAPPER = new ObjectMapper();
  private static final String SYSTEM_PROMPT = """
      You are generating UI-safe summaries for an API security scan report.
      Return exactly one JSON object and nothing else.
      Do not use markdown, code fences, commentary, or extra keys.
      The JSON object must contain exactly these top-level keys:
      overview, findings.
      `overview` must be a string.
      `findings` must be an array of objects.
      Each object in `findings` must contain exactly these string keys:
      ruleId, whyDangerous, remediation, businessImpact, evidenceTitle, evidenceSummary.
      Rules:
      - Base the output only on the supplied scan data.
      - Be concise, factual, and deterministic in tone.
      - Do not invent vulnerabilities, exploitability, or internal code details.
      - If evidence is weak or the finding is marked POTENTIAL or INFO, reflect that uncertainty.
      - Keep each value short enough for UI cards and detail panes.
      - Include one entry in `findings` for each failed finding in the supplied data.
      - Copy the exact `ruleId` from the supplied finding into the output entry.
      - `overview` is a 100 words scan-level summary paragraph.
      - `whyDangerous` explains that finding's main security risk in plain engineering language.
      - `remediation` gives actionable remediation guidance for that finding.
      - `businessImpact` explains likely operational or business risk for that finding.
      - `evidenceTitle` is a short headline for that finding's evidence section.
      - `evidenceSummary` is a short explanation of what the evidence showed for that finding.
      - If a finding includes `location`, use it in `evidenceTitle` or `evidenceSummary` when it helps identify where the issue was observed, such as a header name, query parameter, body field, path segment, or response field.
      - Prefer concrete evidence from `location` over generic wording like "the request" or "the response" when the supplied data identifies the exact place.
      - Do not invent a location; only use `location` details that are present in the supplied finding data.
      If the scan has no failed findings, state that clearly and avoid implying a confirmed vulnerability.
      """;

  private AiSummaryService() {}

  static void enrich(AppConfig cfg, Report report) throws Exception {
    report.aiUsed = false;
    report.aiSummary = null;
    report.aiError = null;
    report.aiStatus = "DISABLED";
    clearFindingAi(report);

    if (cfg == null || report == null) return;
    if (!cfg.openai.enabled) return;
    if (cfg.openai.apiKey == null || cfg.openai.apiKey.isBlank()) {
      failOrSkip(cfg, report, "OpenAI API key is missing");
      return;
    }
    if (!shouldSummarize(report)) {
      report.aiStatus = "SKIPPED";
      return;
    }

    try {
      String payload = requestPayload(cfg, report);
      HttpRequest request = HttpRequest.newBuilder(URI.create(cfg.openai.baseUrl))
          .timeout(Duration.ofSeconds(cfg.openai.timeoutSeconds))
          .header("Content-Type", "application/json")
          .header("Authorization", "Bearer " + cfg.openai.apiKey)
          .POST(HttpRequest.BodyPublishers.ofString(payload))
          .build();
      HttpResponse<String> response = HttpClient.newBuilder()
          .connectTimeout(Duration.ofSeconds(cfg.openai.timeoutSeconds))
          .build()
          .send(request, HttpResponse.BodyHandlers.ofString());
      if (response.statusCode() < 200 || response.statusCode() >= 300) {
        failOrSkip(cfg, report, formatHttpError(response.statusCode(), response.body()));
        return;
      }
      AiSummary summary = parseSummary(report, response.body(), cfg.openai.model);
      if (summary == null) {
        failOrSkip(cfg, report, "OpenAI response did not contain a valid summary");
        return;
      }
      report.aiSummary = summary;
      report.aiUsed = true;
      report.aiStatus = "USED";
    } catch (Exception e) {
      failOrSkip(cfg, report, e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
    }
  }

  private static boolean shouldSummarize(Report report) {
    if (report.summary == null) return false;
    if (report.summary.failed > 0 || report.summary.skipped > 0 || report.summary.errors > 0) return true;
    return report.application != null || report.resource != null || (report.target != null && report.target.url != null && !report.target.url.isBlank());
  }

  private static void clearFindingAi(Report report) {
    if (report == null || report.findings == null) return;
    for (Finding finding : report.findings) {
      if (finding != null) finding.ai = null;
    }
  }

  private static void failOrSkip(AppConfig cfg, Report report, String error) {
    report.aiUsed = false;
    report.aiStatus = "FAILED";
    report.aiError = error;
    if (!cfg.openai.failOpen) {
      throw new IllegalStateException(error);
    }
  }

  private static String requestPayload(AppConfig cfg, Report report) throws Exception {
    ObjectNode root = MAPPER.createObjectNode();
    root.put("model", cfg.openai.model);
    root.put("temperature", cfg.openai.temperature);
    ArrayNode messages = root.putArray("messages");

    ObjectNode system = messages.addObject();
    system.put("role", "system");
    system.put("content", SYSTEM_PROMPT);

    ObjectNode user = messages.addObject();
    user.put("role", "user");
    user.put("content", MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(compactReport(cfg, report)));
    return MAPPER.writeValueAsString(root);
  }

  private static ObjectNode compactReport(AppConfig cfg, Report report) {
    ObjectNode root = MAPPER.createObjectNode();
    if (report.target != null) {
      ObjectNode target = root.putObject("target");
      put(target, "method", report.target.method);
      put(target, "url", report.target.url);
      put(target, "host", report.target.host);
      if (report.resource != null) put(target, "path", report.resource.path);
    }
    if (report.application != null) {
      ObjectNode application = root.putObject("application");
      put(application, "applicationProfileId", report.application.applicationProfileId);
      put(application, "applicationId", report.application.applicationId);
      put(application, "name", report.application.name);
    }
    if (report.resource != null) {
      ObjectNode resource = root.putObject("resource");
      put(resource, "resourceId", report.resource.resourceId);
      put(resource, "swaggerName", report.resource.swaggerName);
      put(resource, "method", report.resource.method);
      put(resource, "path", report.resource.path);
    }
    if (report.summary != null) {
      ObjectNode summary = root.putObject("summary");
      summary.put("totalRules", report.summary.totalRules);
      summary.put("failed", report.summary.failed);
      summary.put("skipped", report.summary.skipped);
      summary.put("errors", report.summary.errors);
      summary.put("critical", report.summary.critical);
      summary.put("high", report.summary.high);
      summary.put("medium", report.summary.medium);
      summary.put("low", report.summary.low);
    }
    if (cfg.openai.includeRawEvidence) {
      root.set("baseline", MAPPER.valueToTree(report.baseline == null ? new LinkedHashMap<>() : report.baseline));
    } else {
      root.set("baseline", compactBaseline(report.baseline));
    }

    ArrayNode findings = root.putArray("findings");
    int limit = Math.max(1, cfg.openai.maxFindings);
    int count = 0;
    for (Finding finding : report.findings == null ? List.<Finding>of() : report.findings) {
      if (!"FAILED".equals(finding.status)) continue;
      if (count++ >= limit) break;
      ObjectNode node = findings.addObject();
      put(node, "ruleId", finding.ruleId);
      put(node, "name", finding.name);
      put(node, "description", finding.description);
      put(node, "impact", finding.impact);
      put(node, "severity", finding.severity);
      put(node, "owasp", finding.owasp);
      put(node, "confidence", finding.confidence);
      put(node, "certainty", finding.certainty);
      put(node, "reason", stringValue(finding.evidence == null ? null : finding.evidence.get("reason")));
      put(node, "evidenceTitle", stringValue(finding.evidence == null ? null : finding.evidence.get("title")));
      put(node, "evidenceSummary", stringValue(finding.evidence == null ? null : finding.evidence.get("summary")));
      if (finding.evidence != null) {
        Object location = finding.evidence.get("location");
        if (location != null) node.set("location", MAPPER.valueToTree(location));
        put(node, "baselineStatus", stringValue(finding.evidence.get("baselineStatus")));
        put(node, "mutationStatus", stringValue(finding.evidence.get("mutationStatus")));
        Object responseSemantics = finding.evidence.get("responseSemantics");
        if (responseSemantics != null) node.set("responseSemantics", MAPPER.valueToTree(responseSemantics));
        if (cfg.openai.includeRawEvidence) {
          Object mutationExchange = finding.evidence.get("mutationExchange");
          if (mutationExchange != null) node.set("mutationExchange", MAPPER.valueToTree(mutationExchange));
        }
      }
    }
    return root;
  }

  private static JsonNode compactBaseline(Map<String, Object> baseline) {
    ObjectNode root = MAPPER.createObjectNode();
    if (baseline == null) return root;
    ObjectNode request = root.putObject("request");
    Object requestObj = baseline.get("request");
    if (requestObj instanceof Map<?,?> req) {
      put(request, "method", stringValue(req.get("method")));
      put(request, "url", stringValue(req.get("url")));
      put(request, "path", stringValue(req.get("path")));
      request.set("queryKeys", keyArray(req.get("query")));
      request.set("headerKeys", keyArray(req.get("headers")));
    }
    ObjectNode response = root.putObject("response");
    Object responseObj = baseline.get("response");
    if (responseObj instanceof Map<?,?> resp) {
      put(response, "statusCode", stringValue(resp.get("statusCode")));
      put(response, "durationMs", stringValue(resp.get("durationMs")));
      put(response, "contentType", stringValue(resp.get("contentType")));
    }
    return root;
  }

  private static ArrayNode keyArray(Object value) {
    ArrayNode array = MAPPER.createArrayNode();
    if (value instanceof Map<?,?> map) {
      for (Object key : map.keySet()) if (key != null) array.add(String.valueOf(key));
    }
    return array;
  }

  private static AiSummary parseSummary(Report report, String body, String requestedModel) throws Exception {
    JsonNode root = MAPPER.readTree(body);
    String model = text(root, "model");
    JsonNode message = root.path("choices").isArray() && root.path("choices").size() > 0 ? root.path("choices").get(0).path("message") : null;
    String content = extractMessageContent(message);
    if (content == null || content.isBlank()) return null;
    JsonNode summaryNode = MAPPER.readTree(stripCodeFence(content));
    AiSummary summary = new AiSummary();
    summary.model = firstNonBlank(model, requestedModel);
    summary.generatedAt = Instant.now();
    summary.overview = text(summaryNode, "overview");
    applyFindingSummaries(report, summaryNode.path("findings"));
    return summary;
  }

  private static void applyFindingSummaries(Report report, JsonNode findingsNode) {
    if (report == null || report.findings == null || findingsNode == null || !findingsNode.isArray()) return;
    Map<String, Finding> byRuleId = new LinkedHashMap<>();
    for (Finding finding : report.findings) {
      if (finding != null && finding.ruleId != null && "FAILED".equals(finding.status)) {
        byRuleId.put(finding.ruleId, finding);
      }
    }
    for (JsonNode node : findingsNode) {
      String ruleId = text(node, "ruleId");
      if (ruleId == null || ruleId.isBlank()) continue;
      Finding finding = byRuleId.get(ruleId);
      if (finding == null) continue;
      FindingAiSummary ai = new FindingAiSummary();
      ai.whyDangerous = text(node, "whyDangerous");
      ai.remediation = text(node, "remediation");
      ai.businessImpact = text(node, "businessImpact");
      ai.evidenceTitle = text(node, "evidenceTitle");
      ai.evidenceSummary = text(node, "evidenceSummary");
      finding.ai = ai;
    }
  }

  private static String extractMessageContent(JsonNode message) {
    if (message == null || message.isMissingNode()) return "";
    JsonNode content = message.path("content");
    if (content.isTextual()) return content.asText();
    if (content.isArray()) {
      StringBuilder out = new StringBuilder();
      for (JsonNode item : content) {
        if (item.path("type").asText("").equals("text")) {
          out.append(item.path("text").asText(""));
        }
      }
      return out.toString();
    }
    return "";
  }

  private static String formatHttpError(int statusCode, String responseBody) {
    StringBuilder message = new StringBuilder("OpenAI API returned ").append(statusCode);
    String compactBody = compactErrorBody(responseBody);
    if (!compactBody.isBlank()) {
      message.append(": ").append(compactBody);
    }
    return message.toString();
  }

  private static String compactErrorBody(String responseBody) {
    if (responseBody == null) return "";
    String compact = responseBody.trim().replaceAll("\\s+", " ");
    if (compact.length() <= 1000) return compact;
    return compact.substring(0, 1000) + "...";
  }

  private static String stripCodeFence(String text) {
    String trimmed = text.trim();
    if (!trimmed.startsWith("```")) return trimmed;
    trimmed = trimmed.replaceFirst("^```[a-zA-Z0-9_-]*\\s*", "");
    return trimmed.replaceFirst("\\s*```$", "").trim();
  }

  private static String text(JsonNode node, String field) {
    JsonNode value = node == null ? null : node.path(field);
    return value == null || value.isMissingNode() || value.isNull() ? null : value.asText();
  }

  private static String stringValue(Object value) {
    return value == null ? null : String.valueOf(value);
  }

  private static String firstNonBlank(String... values) {
    for (String value : values) {
      if (value != null && !value.isBlank()) return value;
    }
    return "";
  }

  private static void put(ObjectNode node, String field, String value) {
    if (value != null && !value.isBlank()) node.put(field, value);
  }
}
