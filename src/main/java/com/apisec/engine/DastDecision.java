package com.apisec.engine;

import com.apisec.model.RequestModel;
import com.apisec.model.ResponseModel;
import com.apisec.rules.RuleModels.Mutation;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

final class DastDecision {
  private static final Pattern ERROR_SIGNATURE = Pattern.compile(
      "(?i)(sql syntax|mysql|postgres|ora-\\d+|sqlite|syntax error|stack trace|exception|traceback|warning:|fatal error|command not found|permission denied|unterminated|xpath|xml parsing)");

  private DastDecision() {
  }

  record Result(boolean finding, String reason, Map<String, Object> evidence) {
  }

  static boolean enabled(String evaluationMode, Map<String, Object> criteria) {
    if (criteria == null || criteria.isEmpty()) return false;
    String mode = s(evaluationMode);
    return mode.isBlank() || "THREAT_MATCH".equalsIgnoreCase(mode);
  }

  static Result evaluate(Map<String, Object> criteria, RequestModel mutatedRequest, Mutation mutation,
                         ResponseModel baseline, ResponseModel response,
                         ResponseSemanticAnalyzer.Semantics semantics) {
    String type = s(criteria.get("type")).toUpperCase(Locale.ROOT);
    return switch (type) {
      case "AUTHZ_BYPASS" -> authzBypass(criteria, baseline, response, semantics);
      case "INJECTION_SIGNAL" -> injectionSignal(mutatedRequest, mutation, response);
      case "SSRF_SIGNAL" -> ssrfSignal(criteria, mutation, response);
      case "MUTATION_ACCEPTED" -> mutationAccepted(criteria, response);
      case "THREAT_ASSERTION_MATCH", "STRUCTURAL_LIMIT_EXCEEDED" ->
          new Result(false, "passive criteria must be evaluated by the rule assertion", Map.of("dastCriteria", type));
      default -> mutationAccepted(criteria, response);
    };
  }

  private static Result authzBypass(Map<String, Object> criteria, ResponseModel baseline, ResponseModel response,
                                    ResponseSemanticAnalyzer.Semantics semantics) {
    boolean denied = response.statusCode == 401 || response.statusCode == 403;
    double threshold = doubleVal(criteria.get("bodySimilarityThreshold"), 0.85);
    double similarity = similarity(baseline.body, response.body);
    boolean statusAllowed = statusMatches(response.statusCode, list(criteria.get("successStatus")));
    boolean finding = !denied && (statusAllowed || semantics.success() || similarity >= threshold);
    Map<String, Object> evidence = new LinkedHashMap<>();
    evidence.put("dastCriteria", "AUTHZ_BYPASS");
    evidence.put("bodySimilarity", similarity);
    evidence.put("semanticSuccess", semantics.success());
    evidence.put("deniedStatus", denied);
    String reason = finding
        ? "Mutated authorization request was accepted or remained similar to the baseline response."
        : "Mutated authorization request was denied or changed enough from baseline.";
    return new Result(finding, reason, evidence);
  }

  private static Result injectionSignal(RequestModel mutatedRequest, Mutation mutation, ResponseModel response) {
    String body = body(response);
    String payload = firstNonBlank(mutation == null ? "" : mutation.value, payloadFromRequest(mutatedRequest));
    boolean serverError = response.statusCode >= 500 && response.statusCode < 600;
    boolean reflected = !payload.isBlank() && body.contains(payload);
    boolean errorSignature = ERROR_SIGNATURE.matcher(body).find();
    boolean finding = serverError || reflected || errorSignature;
    Map<String, Object> evidence = new LinkedHashMap<>();
    evidence.put("dastCriteria", "INJECTION_SIGNAL");
    evidence.put("serverError", serverError);
    evidence.put("payloadReflected", reflected);
    evidence.put("errorSignature", errorSignature);
    String reason = finding
        ? "Injected payload produced a server error, reflected payload, or known error signature."
        : "Injected payload did not produce a clear injection signal.";
    return new Result(finding, reason, evidence);
  }

  private static Result ssrfSignal(Map<String, Object> criteria, Mutation mutation, ResponseModel response) {
    String body = body(response);
    String payload = mutation == null ? "" : s(mutation.value);
    boolean statusAllowed = statusMatches(response.statusCode, list(criteria.get("successStatus")));
    boolean reflectedTarget = !payload.isBlank() && body.contains(payload);
    boolean metadataSignal = body.contains("169.254.169.254") || body.toLowerCase(Locale.ROOT).contains("metadata");
    boolean finding = statusAllowed || reflectedTarget || metadataSignal;
    Map<String, Object> evidence = new LinkedHashMap<>();
    evidence.put("dastCriteria", "SSRF_SIGNAL");
    evidence.put("statusAllowed", statusAllowed);
    evidence.put("targetReflected", reflectedTarget);
    evidence.put("metadataSignal", metadataSignal);
    String reason = finding
        ? "URL injection was accepted or produced a target-processing signal."
        : "URL injection did not produce a clear SSRF signal.";
    return new Result(finding, reason, evidence);
  }

  private static Result mutationAccepted(Map<String, Object> criteria, ResponseModel response) {
    boolean accepted = statusMatches(response.statusCode, list(criteria.get("successStatus")));
    boolean serverError = statusMatches(response.statusCode, list(criteria.get("serverErrorStatus")));
    boolean finding = accepted || serverError;
    Map<String, Object> evidence = new LinkedHashMap<>();
    evidence.put("dastCriteria", firstNonBlank(s(criteria.get("type")), "MUTATION_ACCEPTED"));
    evidence.put("acceptedStatus", accepted);
    evidence.put("serverErrorStatus", serverError);
    String reason = finding
        ? "Mutated request was accepted or produced a server error."
        : "Mutated request was rejected without a clear vulnerable response.";
    return new Result(finding, reason, evidence);
  }

  private static boolean statusMatches(int status, List<String> patterns) {
    if (patterns.isEmpty()) return status >= 200 && status < 300;
    for (String p : patterns) {
      String x = p.trim().toLowerCase(Locale.ROOT);
      if (x.length() == 3 && x.endsWith("xx") && Character.isDigit(x.charAt(0))) {
        int start = Character.digit(x.charAt(0), 10) * 100;
        if (status >= start && status < start + 100) return true;
      } else {
        try {
          if (Integer.parseInt(x) == status) return true;
        } catch (Exception ignored) {
        }
      }
    }
    return false;
  }

  private static String payloadFromRequest(RequestModel request) {
    if (request == null) return "";
    for (List<String> values : request.query.values()) {
      for (String value : values) {
        if (looksLikePayload(value)) return value;
      }
    }
    String body = new String(request.body == null ? new byte[0] : request.body, StandardCharsets.UTF_8);
    if (looksLikePayload(body)) return body;
    return "";
  }

  private static boolean looksLikePayload(String value) {
    String v = s(value);
    return v.contains("<script") || v.contains("' OR ") || v.contains(";id") || v.contains("169.254.169.254")
        || v.contains("127.0.0.1") || v.contains("() {");
  }

  private static double similarity(byte[] a, byte[] b) {
    String x = new String(a == null ? new byte[0] : a, StandardCharsets.UTF_8);
    String y = new String(b == null ? new byte[0] : b, StandardCharsets.UTF_8);
    if (x.equals(y)) return 1.0;
    Set<String> xs = new HashSet<>(Arrays.asList(x.split("\\W+")));
    Set<String> ys = new HashSet<>(Arrays.asList(y.split("\\W+")));
    if (xs.isEmpty() && ys.isEmpty()) return 1.0;
    Set<String> inter = new HashSet<>(xs);
    inter.retainAll(ys);
    Set<String> union = new HashSet<>(xs);
    union.addAll(ys);
    return union.isEmpty() ? 0.0 : (double) inter.size() / union.size();
  }

  private static String body(ResponseModel response) {
    return new String(response == null || response.body == null ? new byte[0] : response.body, StandardCharsets.UTF_8);
  }

  private static double doubleVal(Object value, double fallback) {
    try {
      return Double.parseDouble(s(value));
    } catch (Exception ignored) {
      return fallback;
    }
  }

  private static List<String> list(Object value) {
    if (value instanceof List<?> values) return values.stream().map(String::valueOf).toList();
    if (value == null) return List.of();
    return List.of(String.valueOf(value));
  }

  private static String firstNonBlank(String... values) {
    for (String value : values) if (!s(value).isBlank()) return value;
    return "";
  }

  private static String s(Object value) {
    return value == null ? "" : String.valueOf(value);
  }
}
