package com.apisec.rules;

import com.apisec.rules.RuleModels.*;
import com.fasterxml.jackson.databind.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class RuleLoader {
  private static final ObjectMapper MAPPER = new ObjectMapper();

  public static Group loadFile(Path p) throws IOException {
    Group g = MAPPER.readValue(Files.readString(p), Group.class);
    g.sourceName = fileKey(p);
    normalize(g);
    validate(g);
    return g;
  }

  public static List<Group> loadDir(String dir, List<String> active) throws IOException {
    Set<String> activeSet = new HashSet<>(active == null ? List.of() : active);
    List<Group> out = new ArrayList<>();
    if (!Files.exists(Path.of(dir))) return out;
    try (var stream = Files.list(Path.of(dir))) {
      for (Path p : stream.filter(x -> x.toString().endsWith(".json")).toList()) {
        Group g = loadFile(p);
        if (activeSet.isEmpty() || activeSet.contains(g.id) || activeSet.contains(g.name) || activeSet.contains(g.sourceName)) out.add(g);
      }
    }
    return out;
  }

  public static void validate(Group g) {
    normalize(g);
    if (blank(g.id) || blank(g.name) || blank(g.description)) throw new IllegalArgumentException("rule group requires id, name, description");
    if (g.precondition == null) throw new IllegalArgumentException("precondition is required");
    if (g.rules == null || g.rules.isEmpty()) throw new IllegalArgumentException("rules must not be empty");
    Set<String> ids = new HashSet<>();
    for (Rule r: g.rules) {
      if (blank(r.id) || blank(r.ruleId) || blank(r.name) || blank(r.description)) {
        throw new IllegalArgumentException("rule requires id, ruleId, name, description: ruleId=" + s(r.ruleId) + ", name=" + s(r.name));
      }
      if (!ids.add(r.ruleId)) throw new IllegalArgumentException("duplicate ruleId " + r.ruleId);
    }
  }

  public static void normalize(Group g) {
    if (g == null) return;
    if (blank(g.id) && g._id != null) g.id = s(g._id);
    if (blank(g.description) && !blank(g.name)) g.description = g.name;
    if (blank(g.sourceName) && !blank(g.name)) g.sourceName = slugify(g.name);
    if (g.rules == null) return;
    for (Rule r: g.rules) {
      if (r == null) continue;
      if (blank(r.id) && r._id != null) r.id = s(r._id);
      if (blank(r.id) && !blank(r.ruleId)) r.id = generatedRuleId(g, r);
      if (blank(r.description) && !blank(r.name)) r.description = r.name;
    }
  }

  public static String displayKey(Group g) {
    if (g == null) return "";
    if (!blank(g.sourceName)) return g.sourceName;
    if ("OWASP API Security Top 10 2023 Backup".equals(g.name)) return "owasp-api-2023-backup";
    if (!blank(g.name)) return slugify(g.name);
    if (!blank(g.id)) return g.id;
    return "";
  }

  public static String fileKey(Path p) {
    if (p == null) return "";
    String name = p.getFileName().toString();
    return name.endsWith(".json") ? name.substring(0, name.length() - 5) : name;
  }

  public static ScannerMetadata metadata(Rule r) {
    ScannerMetadata m = new ScannerMetadata();
    if (r.assertion == null || r.assertion.metadata == null) return m;
    ObjectMapper mapper = new ObjectMapper();
    for (MetadataEntry e: r.assertion.metadata) {
      String k = e.key == null ? "" : e.key;
      Object v = e.value;
      switch (k) {
        case "owasp" -> m.owasp = s(v);
        case "cwe" -> m.cwe = list(v);
        case "cves" -> m.cves = list(v);
        case "scanType" -> m.scanType = s(v);
        case "destructive" -> m.destructive = Boolean.parseBoolean(s(v));
        case "requiresAuthContext" -> m.requiresAuthContext = Boolean.parseBoolean(s(v));
        case "requiresAltContext" -> m.requiresAltContext = Boolean.parseBoolean(s(v));
        case "passive" -> m.passive = Boolean.parseBoolean(s(v));
        case "remediation" -> m.remediation = s(v);
        case "curlMutations" -> {
          try {
            m.mutations = Arrays.asList(mapper.readValue(s(v), Mutation[].class));
          } catch (Exception ignored) { m.mutations = new ArrayList<>(); }
        }
      }
    }
    return m;
  }

  public static class ScannerMetadata {
    public String owasp = "";
    public List<String> cwe = new ArrayList<>();
    public List<String> cves = new ArrayList<>();
    public String scanType = "";
    public boolean destructive;
    public boolean requiresAuthContext;
    public boolean requiresAltContext;
    public boolean passive;
    public String remediation = "";
    public List<Mutation> mutations = new ArrayList<>();
  }

  private static boolean blank(String s) { return s == null || s.isBlank(); }
  private static String s(Object v) { return v == null ? "" : String.valueOf(v); }
  private static String generatedRuleId(Group g, Rule r) {
    String seed = firstNonBlank(safe(g == null ? null : g.id), safe(g == null ? null : g.name), "group")
        + "::" + firstNonBlank(safe(r == null ? null : r.ruleId), safe(r == null ? null : r.name), "rule");
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-1");
      byte[] hash = md.digest(seed.getBytes(StandardCharsets.UTF_8));
      StringBuilder out = new StringBuilder();
      for (byte b : hash) out.append(String.format("%02x", b));
      return out.substring(0, 24);
    } catch (Exception e) {
      return UUID.nameUUIDFromBytes(seed.getBytes(StandardCharsets.UTF_8)).toString().replace("-", "").substring(0, 24);
    }
  }
  private static String slugify(String value) {
    if (blank(value)) return "";
    String slug = value.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "-");
    return slug.replaceAll("(^-+|-+$)", "");
  }
  private static String firstNonBlank(String... values) {
    for (String value : values) if (!blank(value)) return value;
    return "";
  }
  private static String safe(String value) { return value == null ? "" : value; }
  private static List<String> list(Object v) {
    if (v instanceof List<?> l) return l.stream().map(String::valueOf).toList();
    return new ArrayList<>();
  }
}
