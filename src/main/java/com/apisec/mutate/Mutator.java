package com.apisec.mutate;

import com.apisec.model.RequestModel;
import com.apisec.rules.RuleModels.Mutation;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

public class Mutator {
  private static final ObjectMapper MAPPER = new ObjectMapper();

  public static Result generate(RequestModel req, Mutation spec, boolean allowDangerous) {
    RequestModel out = req.copy();
    Result r = new Result(spec.name, out);
    String op = spec.operation == null ? "" : spec.operation;
    switch (op) {
      case "REMOVE_HEADER" -> removeHeader(out.headers, spec.key);
      case "REPLACE_HEADER" -> setHeader(out.headers, spec.key, spec.value);
      case "ADD_HEADER" -> out.headers.computeIfAbsent(spec.key, k -> new ArrayList<>()).add(spec.value);
      case "REMOVE_COOKIE" -> { out.cookies.remove(spec.key); rebuildCookie(out); }
      case "REMOVE_QUERY_PARAM" -> { out.query.remove(spec.key); rebuildUrl(out); }
      case "REPLACE_QUERY_PARAM", "ADD_QUERY_PARAM" -> { out.query.put(spec.key, new ArrayList<>(List.of(spec.value))); rebuildUrl(out); }
      case "REPLACE_PATH_ID" -> { out.path = replacePathID(out.path, spec.value); rebuildUrl(out); }
      case "CHANGE_METHOD", "OPTIONS_METHOD", "TRACE_METHOD" -> {
        String method = op.equals("OPTIONS_METHOD") ? "OPTIONS" : op.equals("TRACE_METHOD") ? "TRACE" : spec.value;
        if (isDangerous(method) && !allowDangerous && !req.method.equalsIgnoreCase(method)) return r.skip("dangerous method tampering requires --allow-dangerous");
        out.method = method.toUpperCase(Locale.ROOT);
      }
      case "MALFORM_JSON" -> out.body = "{\"apisec\":".getBytes(StandardCharsets.UTF_8);
      case "LARGE_PAGINATION_LIMIT" -> { out.query.put(spec.key == null || spec.key.isBlank() ? "limit" : spec.key, List.of(spec.value == null || spec.value.isBlank() ? "10000" : spec.value)); rebuildUrl(out); }
      case "NEGATIVE_PAGINATION_LIMIT" -> { out.query.put(spec.key == null || spec.key.isBlank() ? "limit" : spec.key, List.of("-1")); rebuildUrl(out); }
      case "REPLACE_JSON_FIELD", "ADD_JSON_FIELD", "REMOVE_JSON_FIELD" -> { if (!jsonMutation(out, spec)) return r.skip("request body is not a JSON object"); }
      default -> { return r.skip("unsupported mutation operation " + op); }
    }
    return r;
  }

  private static void removeHeader(Map<String,List<String>> h, String key) { h.keySet().removeIf(k -> k.equalsIgnoreCase(key)); }
  private static void setHeader(Map<String,List<String>> h, String key, String val) { removeHeader(h, key); h.put(key, new ArrayList<>(List.of(val == null ? "" : val))); }
  private static void rebuildCookie(RequestModel r) {
    removeHeader(r.headers, "Cookie");
    if (!r.cookies.isEmpty()) {
      StringJoiner j = new StringJoiner("; ");
      r.cookies.forEach((k,v) -> j.add(k + "=" + v));
      setHeader(r.headers, "Cookie", j.toString());
    }
  }
  private static void rebuildUrl(RequestModel r) {
    try {
      URI u = URI.create(r.url);
      StringJoiner q = new StringJoiner("&");
      r.query.forEach((k, vals) -> vals.forEach(v -> q.add(enc(k) + "=" + enc(v))));
      r.url = new URI(u.getScheme(), u.getAuthority(), r.path, q.length() == 0 ? null : q.toString(), null).toString();
    } catch (Exception ignored) {}
  }
  private static String enc(String s) { return URLEncoder.encode(s == null ? "" : s, StandardCharsets.UTF_8); }
  private static String replacePathID(String path, String val) {
    if (val == null || val.isBlank()) val = "999999";
    String[] parts = path.split("/", -1);
    Pattern num = Pattern.compile("^\\d+$"), uuid = Pattern.compile("(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    for (int i=parts.length-1; i>=0; i--) if (num.matcher(parts[i]).matches() || uuid.matcher(parts[i]).matches()) { parts[i]=val; break; }
    return String.join("/", parts);
  }
  private static boolean jsonMutation(RequestModel r, Mutation m) {
    try {
      Map<String,Object> obj = MAPPER.readValue(r.body, new TypeReference<>() {});
      if ("REMOVE_JSON_FIELD".equals(m.operation)) obj.remove(m.key); else obj.put(m.key, m.value);
      r.body = MAPPER.writeValueAsBytes(obj); return true;
    } catch (Exception e) { return false; }
  }
  private static boolean isDangerous(String m) { return Set.of("DELETE","PUT","PATCH").contains((m == null ? "" : m).toUpperCase(Locale.ROOT)); }

  public static class Result {
    public String name; public RequestModel request; public boolean skipped; public String reason = "";
    Result(String name, RequestModel request) { this.name = name; this.request = request; }
    Result skip(String reason) { this.skipped = true; this.reason = reason; return this; }
  }
}
