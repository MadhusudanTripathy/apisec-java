package com.apisec.engine;

import com.apisec.engine.EndpointClassifier.EndpointContext;
import com.apisec.engine.ResponseSemanticAnalyzer.Semantics;
import com.apisec.model.ResponseModel;
import com.apisec.report.ReportModels.Finding;
import com.apisec.rules.RuleModels.Mutation;

import java.util.*;

public class FindingQuality {
  public static void annotatePassive(Finding f, String ruleId, ResponseModel baseline, Semantics sem) {
    if (!"FAILED".equals(f.status)) {
      f.confidence = "NONE";
      f.certainty = f.status;
      return;
    }
    if (Set.of("API8-CONFIG-004", "API8-CONFIG-007", "API4-RESOURCE-006").contains(ruleId)) {
      f.confidence = "HIGH";
      f.certainty = "INFO";
    } else if (ruleId.startsWith("API6-")) {
      f.confidence = sem.success() ? "MEDIUM" : "LOW";
      f.certainty = "POTENTIAL";
    } else {
      f.confidence = "MEDIUM";
      f.certainty = "POTENTIAL";
    }
    f.evidence.put("responseSemantics", semanticMap(sem));
    f.evidence.put("reason", improvePassiveReason(ruleId, f.evidence.get("reason"), baseline, sem));
  }

  public static void annotateMutation(Finding f, String ruleId, Mutation mutation, ResponseModel baseline, ResponseModel mutationResponse,
                                      Semantics baselineSem, Semantics mutationSem, EndpointContext ctx) {
    if (!"FAILED".equals(f.status)) {
      f.confidence = "NONE";
      f.certainty = f.status;
      return;
    }

    boolean sameSuccess = isSuccess(mutationResponse) && mutationSem.success();
    boolean sensitive = mutationSem.sensitiveData();

    if (isAuthRemoval(ruleId) && sameSuccess && sensitive) {
      f.confidence = "HIGH";
      f.certainty = "CONFIRMED";
    } else if (isMassAssignment(ruleId) && sameSuccess) {
      f.confidence = mutationSem.markers().containsAll(baselineSem.markers()) ? "HIGH" : "MEDIUM";
      f.certainty = "POTENTIAL";
    } else if (isGeneric200(ruleId) && sameSuccess) {
      f.confidence = "MEDIUM";
      f.certainty = "POTENTIAL";
    } else {
      f.confidence = "LOW";
      f.certainty = "POTENTIAL";
    }

    f.evidence.put("responseSemantics", semanticMap(mutationSem));
    f.evidence.put("endpointTypes", new ArrayList<>(ctx.types()));
    f.evidence.put("reason", improveMutationReason(ruleId, mutation, mutationResponse, mutationSem, f.evidence.get("reason")));
  }

  private static String improvePassiveReason(String ruleId, Object oldReason, ResponseModel baseline, Semantics sem) {
    return switch (ruleId) {
      case "API4-RESOURCE-006" -> "Baseline response does not expose common rate-limit headers.";
      case "API6-BUSINESS-001" -> "Sensitive business endpoint has no visible anti-automation/rate-limit signal.";
      case "API6-BUSINESS-002" -> "OTP/auth-like endpoint has no visible rate-limit signal.";
      case "API6-BUSINESS-003" -> "Payment/transfer endpoint returned " + baseline.statusCode + " without a visible idempotency signal.";
      case "API6-BUSINESS-005" -> "Sensitive action completed without a visible confirmation, MFA, OTP, or step-up signal.";
      case "API8-CONFIG-004" -> "Response exposes server/version style headers.";
      case "API8-CONFIG-007" -> "Response is missing X-Content-Type-Options.";
      default -> String.valueOf(oldReason);
    };
  }

  private static String improveMutationReason(String ruleId, Mutation mutation, ResponseModel resp, Semantics sem, Object oldReason) {
    String target = mutation == null ? "mutation" : mutation.name;
    if (isBola(ruleId)) {
      String objectTarget = bolaTarget(mutation);
      return "Object identifier tampering on " + objectTarget + " returned HTTP " + resp.statusCode + successText(sem) + ".";
    }
    if (isMassAssignment(ruleId)) {
      return "Request with unexpected field mutation '" + target + "' returned HTTP " + resp.statusCode + successText(sem) + ".";
    }
    if (ruleId.equals("API5-BFLA-001")) {
      return "Admin/function-level authorization probe returned HTTP " + resp.statusCode + successText(sem) + ".";
    }
    if (ruleId.equals("API5-BFLA-003")) {
      return "Request with unsafe method override returned HTTP " + resp.statusCode + successText(sem) + ".";
    }
    if (ruleId.equals("API5-BFLA-005") || ruleId.equals("API5-BFLA-006")) {
      return "Request with privileged access tampering '" + target + "' returned HTTP " + resp.statusCode + successText(sem) + ".";
    }
    if (ruleId.startsWith("API7-") || ruleId.startsWith("API10-")) {
      return "Request containing URL-like input mutation '" + target + "' returned HTTP " + resp.statusCode + successText(sem) + ".";
    }
    if (ruleId.equals("API8-CONFIG-006")) {
      return "TRACE method probe returned HTTP " + resp.statusCode + successText(sem) + ".";
    }
    if (isAuthRemoval(ruleId)) {
      return "Endpoint returned HTTP " + resp.statusCode + successText(sem) + " after auth credential was removed.";
    }
    return String.valueOf(oldReason);
  }

  private static String successText(Semantics sem) {
    return sem.success() ? " with success semantics " + sem.markers() : "";
  }

  private static Map<String, Object> semanticMap(Semantics sem) {
    Map<String, Object> out = new LinkedHashMap<>();
    out.put("success", sem.success());
    out.put("sensitiveData", sem.sensitiveData());
    out.put("confirmationSignal", sem.confirmationSignal());
    out.put("rateLimitSignal", sem.rateLimitSignal());
    out.put("cookieSignal", sem.cookieSignal());
    out.put("markers", new ArrayList<>(sem.markers()));
    return out;
  }

  private static boolean isSuccess(ResponseModel r) {
    return r.statusCode >= 200 && r.statusCode < 300;
  }

  private static boolean isAuthRemoval(String ruleId) {
    return Set.of("API2-AUTH-001", "API2-AUTH-006").contains(ruleId);
  }

  private static boolean isMassAssignment(String ruleId) {
    return Set.of("API3-BOPLA-003", "API3-BOPLA-004", "API3-BOPLA-005", "API3-BOPLA-006").contains(ruleId);
  }

  private static boolean isBola(String ruleId) {
    return ruleId != null && ruleId.startsWith("API1-BOLA");
  }

  private static String bolaTarget(Mutation mutation) {
    if (mutation == null || mutation.operation == null) return "the object reference";
    return switch (String.valueOf(mutation.operation)) {
      case "REPLACE_PATH_ID" -> "the path object identifier";
      case "REMOVE_QUERY_PARAM", "REPLACE_QUERY_PARAM", "ADD_QUERY_PARAM" -> "the object identifier query parameter";
      case "REMOVE_HEADER", "REPLACE_HEADER", "ADD_HEADER" -> "the tenant or ownership header";
      default -> "the object reference";
    };
  }

  private static boolean isGeneric200(String ruleId) {
    return ruleId.startsWith("API3-") || ruleId.startsWith("API4-") || ruleId.startsWith("API5-")
        || ruleId.startsWith("API6-") || ruleId.startsWith("API7-") || ruleId.startsWith("API10-");
  }
}
