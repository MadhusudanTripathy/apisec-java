package com.apisec.report;

import java.time.Instant;
import java.util.*;

public class ReportModels {
  public static class Report {
    public String scanId;
    public Instant startedAt;
    public Instant finishedAt;
    public long durationMs;
    public String maxSeverity;
    public int totalFindings;
    public boolean aiUsed;
    public String aiStatus = "DISABLED";
    public String aiError;
    public AiSummary aiSummary;
    public Application application;
    public Resource resource;
    public Target target = new Target();
    public Map<String,Object> baseline = new LinkedHashMap<>();
    public List<RuleGroupInfo> ruleGroups = new ArrayList<>();
    public Summary summary = new Summary();
    public List<Finding> findings = new ArrayList<>();
    public WebhookStatus webhook = new WebhookStatus();
  }
  public static class Application {
    public String applicationProfileId;
    public String applicationId;
    public String name;
    public String description;
    public List<String> swaggerIds = new ArrayList<>();
  }
  public static class Resource {
    public String resourceId;
    public String swaggerDocumentId;
    public String swaggerId;
    public String swaggerName;
    public Integer revision;
    public String status;
    public String baseUrl;
    public String path;
    public String method;
    public String operationId;
    public String summary;
    public List<String> tags = new ArrayList<>();
    public List<String> servers = new ArrayList<>();
  }
  public static class Target { public String method; public String url; public String host; }
  public static class RuleGroupInfo { public String name; public String version; }
  public static class Summary {
    public int totalRules, passed, failed, skipped, errors, critical, high, medium, low;
  }
  public static class AiSummary {
    public String model;
    public Instant generatedAt;
    public String overview;
  }
  public static class Finding {
    public String ruleId, name, description, impact, severity, owasp, status, confidence = "NONE", certainty = "UNKNOWN", remediation;
    public List<String> cwe = new ArrayList<>();
    public List<String> cves = new ArrayList<>();
    public FindingAiSummary ai;
    public Map<String,Object> evidence = new LinkedHashMap<>();
  }
  public static class FindingAiSummary {
    public String whyDangerous;
    public String remediation;
    public String businessImpact;
    public String evidenceTitle;
    public String evidenceSummary;
  }
  public static class WebhookStatus {
    public boolean enabled, delivered;
    public int statusCode, attempts;
    public String error = "";
  }
}
