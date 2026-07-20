package com.apisec.cli;

import com.apisec.engine.ScannerEngine.ProgressSink;
import com.apisec.report.ReportModels.Report;

import java.util.Locale;

class PlainApplicationScanProgress implements ApplicationProgress {
  private static final long RULE_PRINT_INTERVAL_MS = 800L;

  private final long started = System.currentTimeMillis();
  private final int totalResources;
  private final String applicationLabel;
  private int currentIndex;
  private String currentMethod = "GET";
  private String currentTarget = "";
  private int completedResources;
  private int skippedResources;
  private int failedResources;
  private int totalFindings;
  private int critical;
  private int high;
  private int medium;
  private int low;
  private long lastRulePrintedAt;
  private int lastRuleCurrent = -1;
  private int lastRuleTotal = -1;
  private String lastRuleId = "";
  private String lastStage = "";
  private int lastPercent = -1;

  PlainApplicationScanProgress(int totalResources, String applicationLabel) {
    this.totalResources = Math.max(0, totalResources);
    this.applicationLabel = ProgressSupport.firstNonBlank(applicationLabel, "Application Scan");
    System.out.printf("Application %s  resources=%d%n", this.applicationLabel, this.totalResources);
  }

  @Override public void resourceStarted(int index, int total, String method, String target, String operationId) {
    currentIndex = index;
    currentMethod = ProgressSupport.firstNonBlank(method, "GET");
    currentTarget = ProgressSupport.firstNonBlank(target, operationId, "unknown");
    lastStage = "";
    lastPercent = -1;
    lastRuleCurrent = -1;
    lastRuleTotal = -1;
    lastRuleId = "";
    System.out.printf("[%d/%d] %s %s%n", currentIndex, Math.max(total, totalResources), currentMethod, currentTarget);
  }

  @Override public void resourceSkipped(String reason) {
    skippedResources++;
    System.out.printf("  skipped   %s%n", ProgressSupport.compact(reason));
  }

  @Override public void resourceCompleted(Report report) {
    completedResources++;
    if (report != null && report.summary != null) {
      totalFindings += report.totalFindings;
      critical += report.summary.critical;
      high += report.summary.high;
      medium += report.summary.medium;
      low += report.summary.low;
      System.out.printf(
          "  completed findings=%d max=%s elapsed=%s%n",
          report.totalFindings,
          ProgressSupport.firstNonBlank(report.maxSeverity, "NONE"),
          ProgressSupport.elapsed(started));
    } else {
      System.out.println("  completed");
    }
  }

  @Override public void resourceFailed(String reason) {
    failedResources++;
    System.out.printf("  failed    %s%n", ProgressSupport.compact(reason));
  }

  @Override public synchronized void stage(int percent, String message) {
    int safePercent = ProgressSupport.clamp(percent);
    String stage = describeStage(message);
    if (safePercent == lastPercent && stage.equals(lastStage)) return;
    lastPercent = safePercent;
    lastStage = stage;
    System.out.printf("  progress  %3d%%  %s%n", safePercent, stage);
  }

  @Override public synchronized void rules(int current, int total, String ruleId) {
    long now = System.currentTimeMillis();
    String safeRuleId = ProgressSupport.safeRule(ruleId);
    boolean shouldPrint = current <= 1
        || total <= 0
        || current >= total
        || current != lastRuleCurrent + 1
        || now - lastRulePrintedAt >= RULE_PRINT_INTERVAL_MS;
    lastRuleCurrent = current;
    lastRuleTotal = total;
    lastRuleId = safeRuleId;
    if (!shouldPrint) return;
    lastRulePrintedAt = now;
    if (total > 0) {
      System.out.printf("  rules     %d/%d  %s%n", current, total, safeRuleId);
    } else {
      System.out.printf("  rules     %d  %s%n", current, safeRuleId);
    }
  }

  @Override public void done() {
  }

  @Override public void close() {
    System.out.printf(
        "Application summary  completed=%d skipped=%d failed=%d findings=%d critical=%d high=%d medium=%d low=%d elapsed=%s%n",
        completedResources,
        skippedResources,
        failedResources,
        totalFindings,
        critical,
        high,
        medium,
        low,
        ProgressSupport.elapsed(started));
  }

  private String describeStage(String message) {
    String compact = ProgressSupport.compact(message);
    if (compact.isBlank()) return "Working";
    String lower = compact.toLowerCase(Locale.ROOT);
    if (lower.contains("parsing")) return "Parsing curl request";
    if (lower.contains("baseline")) return "Executing baseline request";
    if (lower.contains("loading rule")) return "Loading rule groups";
    if (lower.contains("preparing report")) return "Preparing report";
    if (lower.contains("generating ai")) return "Generating AI summary";
    if (lower.contains("writing json")) return "Writing JSON report";
    if (lower.contains("sending webhook")) return "Sending webhook";
    if (lower.contains("completed")) return "Completed";
    return ProgressSupport.titleCase(compact);
  }
}
