package com.apisec.curl;

import com.apisec.model.RequestModel;
import java.io.ByteArrayOutputStream;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class CurlParser {
  public static RequestModel parse(String curl) {
    List<String> t = tokenize(curl);
    if (t.isEmpty()) throw new IllegalArgumentException("curl command is required");
    if (!"curl".equals(t.get(0))) t.add(0, "curl");
    RequestModel r = new RequestModel();
    String url = null;
    List<FormPart> formParts = new ArrayList<>();
    List<UrlEncodedField> urlEncodedFields = new ArrayList<>();
    for (int i=1; i<t.size(); i++) {
      String a = t.get(i);
      String opt = optionName(a);
      String inlineValue = optionInlineValue(a);
      switch (a) {
        case "-X", "--request" -> r.method = require(t, ++i, a).toUpperCase(Locale.ROOT);
        case "-H", "--header" -> addHeader(r, require(t, ++i, a));
        case "-d", "--data", "--data-raw", "--data-binary" -> { r.body = require(t, ++i, a).getBytes(StandardCharsets.UTF_8); if ("GET".equals(r.method)) r.method = "POST"; }
        case "--data-urlencode" -> {
          urlEncodedFields.add(parseUrlEncodedField(require(t, ++i, a)));
          if ("GET".equals(r.method)) r.method = "POST";
        }
        case "-F", "--form", "--form-string" -> {
          formParts.add(parseFormPart(require(t, ++i, a), "--form-string".equals(a)));
          if ("GET".equals(r.method)) r.method = "POST";
        }
        case "-b", "--cookie" -> addCookie(r, require(t, ++i, a));
        case "--location", "-L", "-s", "-i", "--include", "--silent", "--show-error", "--compressed",
             "--globoff", "-g", "-k", "--insecure", "--http1.1", "--http2", "--path-as-is", "-v", "--verbose",
             "-f", "--fail" -> {}
        default -> {
          if ("--request".equals(opt)) {
            String value = inlineValue != null ? inlineValue : require(t, ++i, opt);
            r.method = value.toUpperCase(Locale.ROOT);
          } else if ("--header".equals(opt) || "-H".equals(opt)) {
            addHeader(r, inlineValue != null ? inlineValue : require(t, ++i, opt));
          } else if ("--data".equals(opt) || "--data-raw".equals(opt) || "--data-binary".equals(opt) || "-d".equals(opt)) {
            String value = inlineValue != null ? inlineValue : require(t, ++i, opt);
            r.body = value.getBytes(StandardCharsets.UTF_8);
            if ("GET".equals(r.method)) r.method = "POST";
          } else if ("--data-urlencode".equals(opt)) {
            String value = inlineValue != null ? inlineValue : require(t, ++i, opt);
            urlEncodedFields.add(parseUrlEncodedField(value));
            if ("GET".equals(r.method)) r.method = "POST";
          } else if ("--form".equals(opt) || "--form-string".equals(opt)) {
            String value = inlineValue != null ? inlineValue : require(t, ++i, opt);
            formParts.add(parseFormPart(value, "--form-string".equals(opt)));
            if ("GET".equals(r.method)) r.method = "POST";
          } else if ("--cookie".equals(opt) || "-b".equals(opt)) {
            addCookie(r, inlineValue != null ? inlineValue : require(t, ++i, opt));
          } else if ("--url".equals(opt)) {
            url = inlineValue != null ? inlineValue : require(t, ++i, opt);
          } else if (expectsValue(opt)) {
            if (inlineValue == null) require(t, ++i, opt);
          } else if (a.startsWith("-")) {
            throw new IllegalArgumentException("unsupported curl option: " + a);
          } else {
            url = a;
          }
        }
      }
    }
    if (url == null) throw new IllegalArgumentException("curl URL is required");
    if (!formParts.isEmpty()) {
      applyMultipartBody(r, formParts);
    } else if (!urlEncodedFields.isEmpty()) {
      applyUrlEncodedBody(r, urlEncodedFields);
    }
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
  private static String optionName(String token) {
    if (token == null || !token.startsWith("--")) return token;
    int idx = token.indexOf('=');
    return idx > 0 ? token.substring(0, idx) : token;
  }
  private static String optionInlineValue(String token) {
    if (token == null || !token.startsWith("--")) return null;
    int idx = token.indexOf('=');
    return idx > 0 ? token.substring(idx + 1) : null;
  }
  private static boolean expectsValue(String option) {
    return "--url".equals(option)
        || "--user-agent".equals(option)
        || "-A".equals(option)
        || "--user".equals(option)
        || "-u".equals(option)
        || "--connect-timeout".equals(option)
        || "--max-time".equals(option)
        || "-m".equals(option)
        || "--request-target".equals(option);
  }

  private static void applyMultipartBody(RequestModel r, List<FormPart> formParts) {
    String boundary = "----ApiSecBoundary" + UUID.randomUUID().toString().replace("-", "");
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    try {
      for (FormPart part : formParts) {
        writeAscii(out, "--" + boundary + "\r\n");
        writeAscii(out, "Content-Disposition: form-data; name=\"" + escapeQuoted(part.name) + "\"");
        if (part.filename != null && !part.filename.isBlank()) {
          writeAscii(out, "; filename=\"" + escapeQuoted(part.filename) + "\"");
        }
        writeAscii(out, "\r\n");
        if (part.contentType != null && !part.contentType.isBlank()) {
          writeAscii(out, "Content-Type: " + part.contentType + "\r\n");
        }
        writeAscii(out, "\r\n");
        out.write(part.value);
        writeAscii(out, "\r\n");
      }
      writeAscii(out, "--" + boundary + "--\r\n");
    } catch (Exception e) {
      throw new IllegalArgumentException("failed to build multipart form body", e);
    }
    r.body = out.toByteArray();
    r.formEncoding = "multipart/form-data";
    r.formFields = new ArrayList<>();
    for (FormPart part : formParts) {
      RequestModel.FormField field = new RequestModel.FormField();
      field.name = part.name;
      field.value = part.textValue;
      field.contentType = part.contentType;
      field.filename = part.filename;
      r.formFields.add(field);
    }
    if (!hasHeader(r, "Content-Type")) {
      r.headers.computeIfAbsent("Content-Type", key -> new ArrayList<>())
          .add("multipart/form-data; boundary=" + boundary);
    }
  }

  private static void applyUrlEncodedBody(RequestModel r, List<UrlEncodedField> urlEncodedFields) {
    List<String> urlEncodedParts = new ArrayList<>();
    r.formFields = new ArrayList<>();
    for (UrlEncodedField field : urlEncodedFields) {
      urlEncodedParts.add(URLEncoder.encode(field.name, StandardCharsets.UTF_8) + "=" + URLEncoder.encode(field.value, StandardCharsets.UTF_8));
      RequestModel.FormField formField = new RequestModel.FormField();
      formField.name = field.name;
      formField.value = field.value;
      r.formFields.add(formField);
    }
    r.body = String.join("&", urlEncodedParts).getBytes(StandardCharsets.UTF_8);
    r.formEncoding = "application/x-www-form-urlencoded";
    if (!hasHeader(r, "Content-Type")) {
      r.headers.computeIfAbsent("Content-Type", key -> new ArrayList<>())
          .add("application/x-www-form-urlencoded");
    }
  }

  private static FormPart parseFormPart(String spec, boolean stringOnly) {
    int idx = spec.indexOf('=');
    if (idx <= 0) throw new IllegalArgumentException("form field must be 'name=value'");
    String name = stripQuotes(spec.substring(0, idx).trim());
    String valueSpec = spec.substring(idx + 1);
    List<String> segments = splitFormSegments(valueSpec);
    String valueToken = stripQuotes(segments.get(0).trim());
    String contentType = null;
    String filename = null;
    for (int i = 1; i < segments.size(); i++) {
      String segment = segments.get(i).trim();
      int attrIdx = segment.indexOf('=');
      if (attrIdx <= 0) continue;
      String attrName = segment.substring(0, attrIdx).trim();
      String attrValue = stripQuotes(segment.substring(attrIdx + 1).trim());
      if ("type".equalsIgnoreCase(attrName)) {
        contentType = attrValue;
      } else if ("filename".equalsIgnoreCase(attrName)) {
        filename = attrValue;
      }
    }

    if (!stringOnly && valueToken.startsWith("@")) {
      Path path = Path.of(stripQuotes(valueToken.substring(1)));
      try {
        byte[] bytes = Files.readAllBytes(path);
        String resolvedFilename = filename != null ? filename : path.getFileName().toString();
        return new FormPart(name, bytes, null, contentType == null ? "application/octet-stream" : contentType, resolvedFilename);
      } catch (Exception e) {
        throw new IllegalArgumentException("failed to read form file: " + path, e);
      }
    }

    if (!stringOnly && valueToken.startsWith("<")) {
      Path path = Path.of(stripQuotes(valueToken.substring(1)));
      try {
        byte[] bytes = Files.readAllBytes(path);
        return new FormPart(name, bytes, null, contentType, filename);
      } catch (Exception e) {
        throw new IllegalArgumentException("failed to read form file: " + path, e);
      }
    }

    return new FormPart(name, valueToken.getBytes(StandardCharsets.UTF_8), valueToken, contentType, filename);
  }

  private static List<String> splitFormSegments(String valueSpec) {
    List<String> segments = new ArrayList<>();
    StringBuilder current = new StringBuilder();
    char quote = 0;
    for (int i = 0; i < valueSpec.length(); i++) {
      char c = valueSpec.charAt(i);
      if (quote != 0) {
        if (c == quote) quote = 0;
        current.append(c);
        continue;
      }
      if (c == '\'' || c == '"') {
        quote = c;
        current.append(c);
        continue;
      }
      if (c == ';') {
        segments.add(current.toString());
        current.setLength(0);
        continue;
      }
      current.append(c);
    }
    segments.add(current.toString());
    return segments;
  }

  private static boolean hasHeader(RequestModel r, String name) {
    return r.headers.keySet().stream().anyMatch(key -> key.equalsIgnoreCase(name));
  }

  private static UrlEncodedField parseUrlEncodedField(String spec) {
    String trimmed = stripQuotes(spec.trim());
    int idx = trimmed.indexOf('=');
    if (idx < 0) {
      return new UrlEncodedField(trimmed, "");
    }
    String name = trimmed.substring(0, idx);
    String value = trimmed.substring(idx + 1);
    return new UrlEncodedField(name, value);
  }

  private static String stripQuotes(String value) {
    if (value == null || value.length() < 2) return value;
    char first = value.charAt(0);
    char last = value.charAt(value.length() - 1);
    return (first == '\'' && last == '\'') || (first == '"' && last == '"')
        ? value.substring(1, value.length() - 1)
        : value;
  }

  private static String escapeQuoted(String value) {
    return value.replace("\\", "\\\\").replace("\"", "\\\"");
  }

  private static void writeAscii(ByteArrayOutputStream out, String value) {
    out.writeBytes(value.getBytes(StandardCharsets.UTF_8));
  }

  private record FormPart(String name, byte[] value, String textValue, String contentType, String filename) {}
  private record UrlEncodedField(String name, String value) {}

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
