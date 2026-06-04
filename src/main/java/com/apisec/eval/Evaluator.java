package com.apisec.eval;

import com.apisec.model.*;
import com.apisec.rules.RuleModels.*;
import com.fasterxml.jackson.databind.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

public class Evaluator {
  private static final ObjectMapper MAPPER = new ObjectMapper();

  public record Result(boolean passed, String reason) {}

  public static Result assertion(Assertion a, RequestModel req, ResponseModel baseline, ResponseModel response) {
    return eval(a, req, baseline, response, true);
  }
  public static Result condition(Assertion a, RequestModel req, ResponseModel baseline, ResponseModel response) {
    return eval(a, req, baseline, response, false);
  }
  private static Result eval(Assertion a, RequestModel req, ResponseModel baseline, ResponseModel response, boolean threatSemantics) {
    if (a.placeholders == null || a.placeholders.isEmpty()) {
      boolean v = "true".equalsIgnoreCase(a.expression);
      return threatSemantics ? new Result(!v, "runtime expression evaluated") : new Result(v, "runtime condition evaluated");
    }
    boolean[] vals = new boolean[a.placeholders.size()];
    List<String> reasons = new ArrayList<>();
    for (int i=0; i<a.placeholders.size(); i++) {
      PHResult r = placeholder(a.placeholders.get(i), req, baseline, response);
      vals[i] = r.ok; reasons.add(r.reason);
    }
    boolean threat = boolExpr(a.expression, vals);
    return threatSemantics ? new Result(!threat, String.join("; ", reasons)) : new Result(threat, String.join("; ", reasons));
  }

  private static PHResult placeholder(Placeholder p, RequestModel req, ResponseModel baseline, ResponseModel response) {
    List<String> many = values(p.key, req, baseline, response);
    if (many != null) {
      for (String v: many) if (match(p, v, true)) return new PHResult(true, p.key + " wildcard check");
      return new PHResult(false, p.key + " wildcard check");
    }
    Val v = value(p.key, req, baseline, response);
    return new PHResult(match(p, v.value, v.present), p.key + " " + String.valueOf(p.rule).toLowerCase(Locale.ROOT) + " check");
  }

  private static boolean match(Placeholder p, String actual, boolean present) {
    String rule = p.rule == null ? "" : p.rule;
    String exp = p.value == null ? "" : String.valueOf(p.value);
    return switch (rule) {
      case "PRESENT" -> present;
      case "ABSENT" -> !present;
      case "EQUAL_TO" -> present && actual.equals(exp);
      case "NOT_EQUAL_TO" -> present && !actual.equals(exp);
      case "CONTAINS" -> present && actual.contains(exp);
      case "REGEX" -> present && Pattern.compile(exp).matcher(actual).find();
      case "GREATER_THAN", "GREATER_THAN_EQUAL_TO", "LESSER_THAN", "LESSER_THAN_EQUAL_TO" -> compare(rule, actual, exp);
      default -> false;
    };
  }
  private static boolean compare(String rule, String a, String e) {
    try {
      double av = Double.parseDouble(a), ev = Double.parseDouble(e);
      return switch (rule) {
        case "GREATER_THAN" -> av > ev;
        case "GREATER_THAN_EQUAL_TO" -> av >= ev;
        case "LESSER_THAN" -> av < ev;
        default -> av <= ev;
      };
    } catch (Exception ex) { return false; }
  }

  private static List<String> values(String key, RequestModel req, ResponseModel baseline, ResponseModel response) {
    return switch (key) {
      case "request.headers.*" -> mapValues(req.headers);
      case "request.headers.*~" -> new ArrayList<>(req.headers.keySet());
      case "request.queryParams.*" -> mapValues(req.query);
      case "request.queryParams.*~" -> new ArrayList<>(req.query.keySet());
      case "response.headers.*" -> mapValues(response.headers);
      case "response.headers.*~" -> new ArrayList<>(response.headers.keySet());
      case "baseline.headers.*" -> mapValues(baseline.headers);
      case "baseline.headers.*~" -> new ArrayList<>(baseline.headers.keySet());
      default -> null;
    };
  }
  private static List<String> mapValues(Map<String,List<String>> m) { List<String> out = new ArrayList<>(); m.values().forEach(out::addAll); return out; }

  private static Val value(String key, RequestModel req, ResponseModel baseline, ResponseModel response) {
    if (key == null) return new Val("", false);
    if (key.equals("request.method")) return new Val(req.method, !req.method.isBlank());
    if (key.equals("request.url")) return new Val(req.url, !req.url.isBlank());
    if (key.equals("request.path")) return new Val(req.path, !req.path.isBlank());
    if (key.equals("request.body")) return new Val(new String(req.body, StandardCharsets.UTF_8), req.body.length > 0);
    if (key.startsWith("request.headers.")) return header(req.headers, key.substring("request.headers.".length()));
    if (key.startsWith("request.queryParams.")) return query(req.query, key.substring("request.queryParams.".length()));
    if (key.equals("response.code") || key.equals("response.status") || key.equals("response.statusCode")) return new Val(String.valueOf(response.statusCode), response.statusCode != 0);
    if (key.equals("baseline.code") || key.equals("baseline.status") || key.equals("baseline.statusCode")) return new Val(String.valueOf(baseline.statusCode), baseline.statusCode != 0);
    if (key.equals("response.body")) return new Val(new String(response.body, StandardCharsets.UTF_8), response.body.length > 0);
    if (key.equals("baseline.body")) return new Val(new String(baseline.body, StandardCharsets.UTF_8), baseline.body.length > 0);
    if (key.startsWith("response.body.")) return jsonPath(response.body, key.substring("response.body.".length()));
    if (key.startsWith("baseline.body.")) return jsonPath(baseline.body, key.substring("baseline.body.".length()));
    if (key.equals("response.bodySize")) return new Val(String.valueOf(response.bodySize), true);
    if (key.equals("response.timeMs")) return new Val(String.valueOf(response.durationMs), true);
    if (key.startsWith("response.headers.")) return header(response.headers, key.substring("response.headers.".length()));
    if (key.startsWith("baseline.headers.")) return header(baseline.headers, key.substring("baseline.headers.".length()));
    if (key.equals("baseline.bodySimilarity")) return new Val(String.valueOf(similarity(baseline.body, response.body)), true);
    return new Val("", false);
  }
  private static Val header(Map<String,List<String>> h, String key) {
    for (var e: h.entrySet()) if (e.getKey().equalsIgnoreCase(key)) return new Val(String.join(" ", e.getValue()), !e.getValue().isEmpty());
    return new Val("", false);
  }
  private static Val query(Map<String,List<String>> q, String key) {
    for (var e: q.entrySet()) if (e.getKey().equalsIgnoreCase(key)) return new Val(String.join(" ", e.getValue()), !e.getValue().isEmpty());
    return new Val("", false);
  }
  private static Val jsonPath(byte[] body, String path) {
    try {
      JsonNode n = MAPPER.readTree(body);
      for (String p: path.split("\\.")) n = n == null ? null : n.get(p);
      if (n == null || n.isMissingNode()) return new Val("", false);
      return new Val(n.isTextual() ? n.asText() : n.toString(), true);
    } catch (Exception e) { return new Val("", false); }
  }
  private static double similarity(byte[] a, byte[] b) {
    String x = new String(a, StandardCharsets.UTF_8), y = new String(b, StandardCharsets.UTF_8);
    if (x.equals(y)) return 1.0;
    Set<String> xs = new HashSet<>(Arrays.asList(x.split("\\W+"))), ys = new HashSet<>(Arrays.asList(y.split("\\W+")));
    if (xs.isEmpty() && ys.isEmpty()) return 1.0;
    Set<String> inter = new HashSet<>(xs); inter.retainAll(ys);
    Set<String> union = new HashSet<>(xs); union.addAll(ys);
    return union.isEmpty() ? 0.0 : (double) inter.size() / union.size();
  }
  private static boolean boolExpr(String expr, boolean[] vals) {
    String e = expr == null ? "" : expr;
    for (int i=0; i<vals.length; i++) e = e.replace("{"+i+"}", String.valueOf(vals[i]));
    e = e.replace("(", " ").replace(")", " ").trim();
    if (e.contains("||")) { for (String p: e.split("\\|\\|")) if (boolExpr(p, new boolean[0])) return true; return false; }
    if (e.contains("&&")) { for (String p: e.split("&&")) if (!boolExpr(p, new boolean[0])) return false; return true; }
    e = e.trim();
    if (e.startsWith("!")) return !boolExpr(e.substring(1), new boolean[0]);
    return Boolean.parseBoolean(e);
  }
  private record Val(String value, boolean present) {}
  private record PHResult(boolean ok, String reason) {}
}
