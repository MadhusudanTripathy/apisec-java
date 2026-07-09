package com.apisec.rules;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.*;

public class RuleModels {
  @JsonIgnoreProperties(ignoreUnknown = false)
  public static class Group {
    public Object _id;
    public String id;
    public String sourceName;
    public String name;
    public String description;
    public boolean predefined;
    public Assertion precondition;
    public List<Rule> rules = new ArrayList<>();
    public Object action;
    public boolean anyActionExecuted;
    public String scope;
    public List<Object> apis = new ArrayList<>();
    public Map<String,Object> metadata = new LinkedHashMap<>();
    public boolean success;
    public boolean enforced;
    public boolean blockOnThreat;
    public boolean editable;
    public int passedRules;
    public int skippedRules;
    public String _class;
    public String version() { return metadata == null ? "" : String.valueOf(metadata.getOrDefault("version", "")); }
  }

  public static class Rule {
    public Object _id;
    public String id;
    public String ruleId;
    public String name;
    public String description;
    public Assertion assertion;
    public Map<String,Object> rateLimitConfig = new LinkedHashMap<>();
    public List<Object> actions = new ArrayList<>();
    public String priority;
    public boolean success;
    public boolean enforced;
    public boolean blockOnThreat;
  }

  public static class Assertion {
    public String expression = "";
    public List<Placeholder> placeholders = new ArrayList<>();
    public boolean success;
    public String type = "Field";
    public String serviceRegistryId = "";
    public List<MetadataEntry> metadata = new ArrayList<>();
  }

  public static class Placeholder {
    public String rule;
    public String key;
    public Object value;
    public String resolvedValue;
    public String valueDataType;
    public Boolean successful;
  }

  public static class MetadataEntry {
    public String key;
    public Object value;
    public boolean required;
    public String type;
  }

  public static class Mutation {
    public String name;
    public String operation;
    public String key;
    public String value;
  }
}
