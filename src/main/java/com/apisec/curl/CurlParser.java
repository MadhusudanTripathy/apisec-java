package com.apisec.curl;

import com.apisec.model.RequestModel;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class CurlParser {
  public static RequestModel parse(String curl) {
    List<String> t = tokenize(curl);
    if (t.isEmpty() || !"curl".equals(t.get(0))) throw new IllegalArgumentException("curl command must start with curl");
    RequestModel r = new RequestModel();
    String url = null;
    for (int i=1; i<t.size(); i++) {
      String a = t.get(i);
      switch (a) {
        case "-X", "--request" -> r.method = require(t, ++i, a).toUpperCase(Locale.ROOT);
        case "-H", "--header" -> addHeader(r, require(t, ++i, a));
        case "-d", "--data", "--data-raw", "--data-binary" -> { r.body = require(t, ++i, a).getBytes(StandardCharsets.UTF_8); if ("GET".equals(r.method)) r.method = "POST"; }
        case "-b", "--cookie" -> addCookie(r, require(t, ++i, a));
        case "--location", "-L", "-s", "-i" -> {}
        default -> {
          if (a.startsWith("-")) throw new IllegalArgumentException("unsupported curl option: " + a);
          url = a;
        }
      }
    }
    if (url == null) throw new IllegalArgumentException("curl URL is required");
    r.url = url; r.normalizeFromUrl(); parseQuery(r); return r;
  }

  private static void addHeader(RequestModel r, String h) {
    int idx = h.indexOf(':'); if (idx < 0) throw new IllegalArgumentException("header must be 'Name: value'");
    String k = h.substring(0, idx).trim(), v = h.substring(idx+1).trim();
    r.headers.computeIfAbsent(k, x -> new ArrayList<>()).add(v);
    if (k.equalsIgnoreCase("Cookie")) addCookie(r, v);
  }
  private static void addCookie(RequestModel r, String c) {
    for (String p: c.split(";")) {
      int idx = p.indexOf('=');
      if (idx > 0) r.cookies.put(p.substring(0, idx).trim(), p.substring(idx+1).trim());
    }
  }
  private static void parseQuery(RequestModel r) {
    String raw = URI.create(r.url).getRawQuery(); if (raw == null || raw.isBlank()) return;
    for (String p: raw.split("&")) {
      String[] kv = p.split("=", 2);
      r.query.computeIfAbsent(dec(kv[0]), x -> new ArrayList<>()).add(kv.length > 1 ? dec(kv[1]) : "");
    }
  }
  private static String dec(String s) { return URLDecoder.decode(s, StandardCharsets.UTF_8); }
  private static String require(List<String> t, int i, String opt) { if (i >= t.size()) throw new IllegalArgumentException(opt + " requires value"); return t.get(i); }

  static List<String> tokenize(String s) {
    List<String> out = new ArrayList<>(); StringBuilder cur = new StringBuilder(); char quote = 0; boolean esc = false;
    for (int i=0; i<s.length(); i++) {
      char c = s.charAt(i);
      if (esc) { cur.append(c); esc=false; continue; }
      if (c == '\\') { esc = true; continue; }
      if (quote != 0) { if (c == quote) quote = 0; else cur.append(c); continue; }
      if (c == '\'' || c == '"') { quote = c; continue; }
      if (Character.isWhitespace(c)) { if (!cur.isEmpty()) { out.add(cur.toString()); cur.setLength(0); } continue; }
      cur.append(c);
    }
    if (quote != 0) throw new IllegalArgumentException("unsupported shell syntax: unterminated quote");
    if (!cur.isEmpty()) out.add(cur.toString());
    return out;
  }
}
