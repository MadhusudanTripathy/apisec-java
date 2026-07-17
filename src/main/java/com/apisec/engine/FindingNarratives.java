package com.apisec.engine;

import com.apisec.report.ReportModels.Finding;
import com.apisec.rules.RuleModels.Mutation;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

final class FindingNarratives {
  private static final Map<String, String> IMPACT_BY_RULE_ID = new LinkedHashMap<>();

  static {
    IMPACT_BY_RULE_ID.put("API2-AUTH-001", "An attacker may access protected functionality without valid authentication by removing an existing credential.");
    IMPACT_BY_RULE_ID.put("API2-AUTH-006", "A missing credential boundary can allow a caller to continue using a session or token after it should have been rejected.");
    IMPACT_BY_RULE_ID.put("API3-BOPLA-003", "Unexpected writable fields can let an attacker change protected object properties that should be controlled by the server.");
    IMPACT_BY_RULE_ID.put("API3-BOPLA-004", "Unauthorized writable fields can expose or modify attributes outside the intended object ownership boundary.");
    IMPACT_BY_RULE_ID.put("API3-BOPLA-005", "Relaxed object property validation can let an attacker tamper with fields that influence business decisions.");
    IMPACT_BY_RULE_ID.put("API3-BOPLA-006", "Improper property-level authorization can expose hidden fields or allow unauthorized updates.");
    IMPACT_BY_RULE_ID.put("API5-BFLA-003", "Method or function authorization gaps can let an attacker perform operations that should require higher privilege.");
    IMPACT_BY_RULE_ID.put("API6-BUSINESS-001", "Weak anti-automation protections can enable scripted abuse, enumeration, and repeated business workflow execution.");
    IMPACT_BY_RULE_ID.put("API6-BUSINESS-003", "Missing replay or idempotency controls can allow the same business action to be repeated multiple times.");
    IMPACT_BY_RULE_ID.put("API6-BUSINESS-005", "Sensitive workflows without confirmation or step-up checks can be executed too easily after a single successful request.");
    IMPACT_BY_RULE_ID.put("API7-SSRF-003", "Accepting unexpected URL-like input can allow outbound calls, callback abuse, or internal network access.");
    IMPACT_BY_RULE_ID.put("API8-INJ-001", "Untrusted input may alter downstream query execution, exposing, modifying, or deleting sensitive data.");
    IMPACT_BY_RULE_ID.put("API8-INJ-002", "Template or expression injection can let attacker-controlled input execute unintended server-side logic.");
    IMPACT_BY_RULE_ID.put("API10-CONSUME-004", "Unexpected remote resource handling can increase risk of callback abuse, SSRF, or unsafe third-party interactions.");
  }

  private FindingNarratives() {}

  static void enrichStatic(Finding finding, String ruleId, String name, String description, String owasp) {
    if (finding == null) return;
    finding.description = firstNonBlank(description, defaultDescription(name, owasp));
    finding.impact = firstNonBlank(IMPACT_BY_RULE_ID.get(ruleId), defaultImpact(name, owasp));
  }

  static void enrichEvidence(Finding finding, String ruleId, String name, Mutation mutation, boolean passive) {
    if (finding == null || finding.evidence == null) return;
    String title = evidenceTitle(ruleId, name, mutation, passive);
    String summary = evidenceSummary(finding, mutation, passive);
    if (!title.isBlank()) finding.evidence.put("title", title);
    if (!summary.isBlank()) finding.evidence.put("summary", summary);
  }

  private static String evidenceTitle(String ruleId, String name, Mutation mutation, boolean passive) {
    String lowerName = safe(name).toLowerCase(Locale.ROOT);
    if (ruleId != null && ruleId.startsWith("API1-BOLA")) {
      return "Object reference tampering did not trigger the expected access control";
    }
    if ("API2-AUTH-001".equals(ruleId) || "API2-AUTH-006".equals(ruleId)) {
      return "Endpoint accepted request after authentication was removed";
    }
    if (lowerName.contains("sql")) return "Payload triggered an unexpected database response";
    if (lowerName.contains("cross-site scripting") || lowerName.contains("(xss)") || lowerName.contains(" xss")) {
      return "Injected content was reflected or processed unexpectedly";
    }
    if (lowerName.contains("ssrf") || lowerName.contains("server-side request forgery")) {
      return "URL-like input changed external request handling";
    }
    if (lowerName.contains("mass assignment") || lowerName.contains("object property") || ruleId.startsWith("API3-BOPLA")) {
      return "Unexpected field mutation changed server behavior";
    }
    if (lowerName.contains("idempotency") || lowerName.contains("replay")) {
      return "Repeated workflow execution did not trigger the expected control";
    }
    if (lowerName.contains("rate limit") || lowerName.contains("automation")) {
      return "The endpoint did not present the expected anti-automation signal";
    }
    if (mutation != null) return "Mutation triggered an unexpected application response";
    return passive ? "The baseline response matched a risky security pattern" : "Unexpected behavior was detected during the scan";
  }

  private static String evidenceSummary(Finding finding, Mutation mutation, boolean passive) {
    String reason = safe(String.valueOf(finding.evidence.getOrDefault("reason", "")));
    Object baselineStatus = finding.evidence.get("baselineStatus");
    Object mutationStatus = finding.evidence.get("mutationStatus");
    if (finding != null && finding.ruleId != null && finding.ruleId.startsWith("API1-BOLA") && mutationStatus != null) {
      return reason + " Baseline status was " + baselineStatus + " and the tampered-object request returned " + mutationStatus + ".";
    }
    if (!reason.isBlank() && mutationStatus != null) {
      return reason + " Baseline status was " + baselineStatus + " and mutated status was " + mutationStatus + ".";
    }
    if (!reason.isBlank() && passive) {
      return reason;
    }
    if (mutation != null && mutationStatus != null) {
      return "A " + mutation.name + " mutation changed the observed response to status " + mutationStatus + ".";
    }
    if (mutationStatus != null) {
      return "The mutated request produced status " + mutationStatus + " after the scanner changed the original input.";
    }
    return reason;
  }

  private static String defaultDescription(String name, String owasp) {
    if (!safe(name).isBlank()) return "Detects whether the endpoint exhibits " + name + " behavior during the scan.";
    if (!safe(owasp).isBlank()) return "Detects a security issue mapped to " + owasp + ".";
    return "Detects unexpected security-relevant behavior during the scan.";
  }

  private static String defaultImpact(String name, String owasp) {
    if (!safe(name).isBlank()) return "If confirmed, " + name + " can weaken the endpoint's security controls or expose sensitive operations and data.";
    if (!safe(owasp).isBlank()) return "If confirmed, this issue can introduce risk associated with " + owasp + ".";
    return "If confirmed, this issue can expose protected data, workflows, or internal services to unauthorized use.";
  }

  private static String firstNonBlank(String... values) {
    for (String value : values) {
      if (value != null && !value.isBlank()) return value;
    }
    return "";
  }

  private static String safe(String value) {
    return value == null ? "" : value.trim();
  }
}
