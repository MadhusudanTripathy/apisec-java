package com.apisec.rules;

import com.apisec.rules.RuleModels.*;
import com.fasterxml.jackson.databind.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;

public class RuleLoader {
  private static final ObjectMapper MAPPER = new ObjectMapper();

  public static Group loadFile(Path p) throws IOException {
    Group g = MAPPER.readValue(Files.readString(p), Group.class);
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
        if (activeSet.isEmpty() || activeSet.contains(g.id) || activeSet.contains(g.name)) out.add(g);
      }
    }
    return out;
  }

  public static void validate(Group g) {
    if (blank(g.id) || blank(g.name) || blank(g.description)) throw new IllegalArgumentException("rule group requires id, name, description");
    if (g.precondition == null) throw new IllegalArgumentException("precondition is required");
    if (g.rules == null || g.rules.isEmpty()) throw new IllegalArgumentException("rules must not be empty");
    Set<String> ids = new HashSet<>();
    for (Rule r: g.rules) {
      if (blank(r.id) || blank(r.ruleId) || blank(r.name) || blank(r.description)) throw new IllegalArgumentException("rule requires id, ruleId, name, description");
      if (!ids.add(r.ruleId)) throw new IllegalArgumentException("duplicate ruleId " + r.ruleId);
    }
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
  private static List<String> list(Object v) {
    if (v instanceof List<?> l) return l.stream().map(String::valueOf).toList();
    return new ArrayList<>();
  }
}
