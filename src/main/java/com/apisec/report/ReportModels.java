package com.apisec.report;

import java.time.Instant;
import java.util.*;

public class ReportModels {
  public static class Report {
    public String scanId;
    public Instant startedAt;
    public Instant finishedAt;
    public long durationMs;
    public Target target = new Target();
    public List<RuleGroupInfo> ruleGroups = new ArrayList<>();
    public Summary summary = new Summary();
    public List<Finding> findings = new ArrayList<>();
    public WebhookStatus webhook = new WebhookStatus();
  }
  public static class Target { public String method; public String url; public String host; }
  public static class RuleGroupInfo { public String name; public String version; }
  public static class Summary {
    public int totalRules, passed, failed, skipped, errors, critical, high, medium, low;
  }
  public static class Finding {
    public String ruleId, name, severity, owasp, status, remediation;
    public List<String> cwe = new ArrayList<>();
    public List<String> cves = new ArrayList<>();
    public Map<String,Object> evidence = new LinkedHashMap<>();
  }
  public static class WebhookStatus {
    public boolean enabled, delivered;
    public int statusCode, attempts;
    public String error = "";
  }
}
