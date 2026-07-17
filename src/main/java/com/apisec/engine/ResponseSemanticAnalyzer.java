package com.apisec.engine;

import com.apisec.model.ResponseModel;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

public class ResponseSemanticAnalyzer {
  private static final ObjectMapper MAPPER = new ObjectMapper();
  private static final Pattern SENSITIVE = Pattern.compile("(?i)\\b(access[_-]?token|refresh[_-]?token|api[_-]?key|password|secret|private[_-]?key|ssn|pan|cardNumber|accountNo|email)\\b");

  public record Semantics(boolean success, boolean sensitiveData, boolean confirmationSignal,
                          boolean rateLimitSignal, boolean cookieSignal, Set<String> markers) {}

  public static Semantics analyze(ResponseModel response) {
    Set<String> markers = new TreeSet<>();
    String body = new String(response.body == null ? new byte[0] : response.body, StandardCharsets.UTF_8);
    String lower = body.toLowerCase(Locale.ROOT);
    boolean success = response.statusCode >= 200 && response.statusCode < 300;
    boolean sensitive = SENSITIVE.matcher(body).find();
    boolean confirmation = hasHeader(response.headers, "X-Confirmation-Required")
        || hasHeader(response.headers, "X-Step-Up-Required")
        || hasHeader(response.headers, "X-MFA-Required");
    boolean rateLimit = hasHeader(response.headers, "X-RateLimit-Limit")
        || hasHeader(response.headers, "RateLimit-Limit")
        || hasHeader(response.headers, "RateLimit-Remaining")
        || hasHeader(response.headers, "Retry-After");
    boolean cookie = hasHeader(response.headers, "Set-Cookie");

    if (success) markers.add("http_success");
    if (sensitive) markers.add("sensitive_field_name");
    if (confirmation) markers.add("confirmation_header");
    if (rateLimit) markers.add("rate_limit_header");
    if (cookie) markers.add("set_cookie");

    try {
      JsonNode root = MAPPER.readTree(body);
      Scan scan = scanJson(root);
      success = success || scan.success;
      sensitive = sensitive || scan.sensitive;
      confirmation = confirmation || scan.confirmation;
      markers.addAll(scan.markers);
    } catch (Exception ignored) {
      if (containsAny(lower, "\"success\"", "success", "approved", "completed")) {
        success = true;
        markers.add("success_text");
      }
    }
    return new Semantics(success, sensitive, confirmation, rateLimit, cookie, markers);
  }

  private static Scan scanJson(JsonNode node) {
    Scan out = new Scan();
    walk(node, "", out);
    return out;
  }

  private static void walk(JsonNode node, String path, Scan out) {
    if (node == null || node.isMissingNode()) return;
    if (node.isObject()) {
      node.properties().forEach(e -> {
        String key = e.getKey();
        String k = key.toLowerCase(Locale.ROOT);
        JsonNode val = e.getValue();
        String text = val.isValueNode() ? val.asText("").toLowerCase(Locale.ROOT) : "";
        if (Set.of("status", "state", "result").contains(k) && Set.of("success", "succeeded", "approved", "completed", "ok").contains(text)) {
          out.success = true;
          out.markers.add(key + "=" + val.asText());
        }
        if (Set.of("confirmationrequired", "confirmation_required", "stepuprequired", "step_up_required", "mfarequired", "mfa_required", "otprequired", "otp_required").contains(k)) {
          out.confirmation = val.asBoolean(false) || text.equals("true") || text.contains("required");
          out.markers.add(key);
        }
        if (k.contains("token") || k.contains("password") || k.contains("secret") || k.contains("apikey") || k.contains("api_key")
            || k.contains("accountno") || k.contains("email") || k.contains("card")) {
          out.sensitive = true;
          out.markers.add("sensitive:" + key);
        }
        walk(val, path.isBlank() ? key : path + "." + key, out);
      });
    } else if (node.isArray()) {
      node.forEach(n -> walk(n, path, out));
    }
  }

  private static boolean hasHeader(Map<String, List<String>> headers, String key) {
    if (headers == null) return false;
    return headers.keySet().stream().anyMatch(k -> k.equalsIgnoreCase(key));
  }

  private static boolean containsAny(String text, String... needles) {
    for (String n : needles) if (text.contains(n)) return true;
    return false;
  }

  private static class Scan {
    boolean success;
    boolean sensitive;
    boolean confirmation;
    Set<String> markers = new TreeSet<>();
  }
}
