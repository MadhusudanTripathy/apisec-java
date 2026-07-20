package com.apisec.cli;

import com.apisec.engine.ScannerEngine.ProgressSink;

import java.util.Locale;

class PlainProgress implements ProgressSink, AutoCloseable {
  private static final long RULE_PRINT_INTERVAL_MS = 800L;

  private final long started = System.currentTimeMillis();
  private int lastPercent = -1;
  private String lastStage = "";
  private int lastRuleCurrent = -1;
  private int lastRuleTotal = -1;
  private String lastRuleId = "";
  private long lastRulePrintedAt;
  private boolean completed;

  @Override public synchronized void stage(int percent, String message) {
    int safePercent = ProgressSupport.clamp(percent);
    String stage = describeStage(message);
    if (safePercent == lastPercent && stage.equals(lastStage)) return;
    lastPercent = safePercent;
    lastStage = stage;
    System.out.printf("Progress %3d%%  %s%n", safePercent, stage);
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
      System.out.printf("Rules    %d/%d  %s%n", current, total, safeRuleId);
    } else {
      System.out.printf("Rules    %d  %s%n", current, safeRuleId);
    }
  }

  @Override public synchronized void done() {
    if (completed) return;
    completed = true;
    System.out.printf("Completed in %s%n", ProgressSupport.elapsed(started));
  }

  @Override public void close() {
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
