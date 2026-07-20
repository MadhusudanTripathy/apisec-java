package com.apisec.cli;

import com.apisec.cli.ProgressSupport.PhaseState;
import com.apisec.cli.ProgressSupport.PhaseTracker;
import com.apisec.engine.ScannerEngine.ProgressSink;
import com.apisec.report.ReportModels.Report;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

class ApplicationScanProgress implements ApplicationProgress {
  private final boolean ansi = ProgressSupport.supportsLiveDashboard();
  private final boolean unicode = ProgressSupport.supportsUnicode();
  private final AtomicBoolean running = new AtomicBoolean(true);
  private final long started = System.currentTimeMillis();
  private final Thread painter;
  private final PhaseTracker tracker = new PhaseTracker();

  private final String applicationLabel;
  private volatile boolean screenInitialized;
  private volatile int renderedLines;
  private volatile int renderedRows;
  private volatile int maxRenderedLines;
  private volatile int maxRenderedRows;
  private volatile int frame;
  private volatile int totalResources;
  private volatile int completedResources;
  private volatile int skippedResources;
  private volatile int failedResources;
  private volatile int currentResourceIndex;
  private volatile int currentEndpointPercent;
  private volatile String currentMethod = "GET";
  private volatile String currentTarget = "";
  private volatile String currentOperationId = "";
  private volatile String currentStage = "Preparing application scan";
  private volatile String currentStatus = "Waiting";
  private volatile String latestCompleted = "None";
  private volatile int totalFindings;
  private volatile int critical;
  private volatile int high;
  private volatile int medium;
  private volatile int low;

  ApplicationScanProgress(int totalResources, String applicationLabel) {
    this.totalResources = Math.max(0, totalResources);
    this.applicationLabel = ProgressSupport.firstNonBlank(applicationLabel, "Application Scan");
    painter = new Thread(this::paintLoop, "apisec-application-progress");
    painter.setDaemon(true);
    painter.start();
  }

  @Override public void resourceStarted(int index, int total, String method, String target, String operationId) {
    totalResources = Math.max(totalResources, total);
    currentResourceIndex = index;
    currentEndpointPercent = 0;
    currentMethod = ProgressSupport.firstNonBlank(method, "GET");
    currentTarget = ProgressSupport.compact(target);
    currentOperationId = ProgressSupport.compact(operationId);
    currentStage = "Scanning endpoint";
    currentStatus = "Initializing request";
    tracker.initialise();
    paint();
  }

  @Override public void resourceSkipped(String reason) {
    skippedResources++;
    currentStage = "Skipping endpoint";
    currentStatus = ProgressSupport.compact(reason);
    currentEndpointPercent = 100;
    latestCompleted = ProgressSupport.clipFromMiddle("Skipped  " + currentMethod + " " + currentTarget, 120);
    paint();
  }

  @Override public void resourceCompleted(Report report) {
    completedResources++;
    currentEndpointPercent = 100;
    currentStage = "Endpoint completed";
    currentStatus = summarize(report);
    if (report != null && report.summary != null) {
      totalFindings += report.totalFindings;
      critical += report.summary.critical;
      high += report.summary.high;
      medium += report.summary.medium;
      low += report.summary.low;
    }
    latestCompleted = ProgressSupport.clipFromMiddle(
        currentMethod + " " + currentTarget + "  " + summarize(report) + aiSuffix(report), 140);
    paint();
  }

  @Override public void resourceFailed(String reason) {
    failedResources++;
    currentEndpointPercent = 100;
    currentStage = "Endpoint failed";
    currentStatus = ProgressSupport.compact(reason);
    latestCompleted = ProgressSupport.clipFromMiddle("Failed   " + currentMethod + " " + currentTarget + "  " + currentStatus, 140);
    paint();
  }

  @Override public void stage(int percent, String message) {
    currentEndpointPercent = ProgressSupport.clamp(percent);
    currentStage = ProgressSupport.titleCase(message);
    currentStatus = actionStatus(message);
    tracker.stage(currentEndpointPercent, message);
    paint();
  }

  @Override public void rules(int current, int total, String ruleId) {
    currentEndpointPercent = total <= 0 ? currentEndpointPercent : ProgressSupport.clamp(18 + (int) Math.round((current * 70.0) / total));
    currentStage = "Evaluating rules";
    currentStatus = total <= 0 ? "Evaluating rules" : "Rule " + current + "/" + total + "  " + ProgressSupport.safeRule(ruleId);
    tracker.rules(current, total, ruleId, currentEndpointPercent);
    paint();
  }

  @Override public void done() {
    currentEndpointPercent = 100;
    tracker.stage(100, "Completed");
    paint();
  }

  @Override public void close() {
    running.set(false);
    painter.interrupt();
    try {
      painter.join(1000);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
    clearScreen();
  }

  private void paintLoop() {
    while (running.get()) {
      try {
        Thread.sleep(120);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        return;
      }
      if (running.get()) paint();
    }
  }

  private synchronized void paint() {
    if (!screenInitialized) {
      if (ansi) {
        System.err.print("\033[?25l\033[2J\033[H");
      } else {
        System.err.println();
      }
      screenInitialized = true;
    }
    if (ansi) {
      System.err.print("\033[H");
    }

    int width = Math.max(90, ProgressSupport.dashboardWidth());
    int contentWidth = Math.max(82, width - 4);
    int finished = completedResources + skippedResources + failedResources;
    int resourcesPercent = totalResources <= 0 ? 0 : ProgressSupport.clamp((int) Math.round((finished * 100.0) / totalResources));
    String resourcesSuffix = ProgressSupport.padLeft(finished + "/" + Math.max(totalResources, 1), 7)
        + "  skipped " + skippedResources + "  errors " + failedResources;
    int resourcesBarWidth = Math.max(12, contentWidth - "Resources  ".length() - 1 - resourcesSuffix.length());
    String endpointSuffix = ProgressSupport.padLeft(currentEndpointPercent + "%", 4)
        + "  resource " + currentResourceIndex + "/" + Math.max(totalResources, 1);
    int endpointBarWidth = Math.max(12, contentWidth - "Endpoint   ".length() - 1 - endpointSuffix.length());
    String spinner = ProgressSupport.SPINNER[Math.floorMod(frame++, ProgressSupport.SPINNER.length)];

    List<String> lines = new ArrayList<>();
    lines.add(ProgressSupport.color(spinner, "36", ansi) + " "
        + ProgressSupport.color("Application API Security Scan", "1;37", ansi) + "  "
        + ProgressSupport.color(resourcesPercent >= 100 ? "Completed" : "Running", "36", ansi));
    lines.add("App       " + ProgressSupport.clip(applicationLabel, contentWidth - 10));
    lines.add("Resources  "
        + ProgressSupport.renderBar(resourcesPercent, resourcesBarWidth, ansi, unicode, resourcesPercent >= 100 ? "32" : "33")
        + " " + resourcesSuffix);
    lines.add("Endpoint   "
        + ProgressSupport.renderBar(currentEndpointPercent, endpointBarWidth, ansi, unicode, ProgressSupport.overallColor(currentEndpointPercent))
        + " " + endpointSuffix);
    lines.add("");
    lines.add("Current");
    lines.add("  " + ProgressSupport.urlHostLine(currentMethod, currentTarget, contentWidth - 2));
    lines.add("  " + ProgressSupport.urlPathLine(currentTarget, currentOperationId, contentWidth - 2));
    lines.add("Now      " + ProgressSupport.clip(liveStatusLine(), contentWidth - 9));
    lines.add("");
    lines.add("Phases");
    for (PhaseState state : tracker.orderedStates()) {
      lines.add(renderPhaseLine(state, contentWidth));
    }
    lines.add("");
    lines.add("Running");
    lines.add("  Findings  total " + totalFindings + "  critical " + critical + "  high " + high + "  medium " + medium + "  low " + low);
    if (completedResources + failedResources > 0) {
      lines.add("  Latest    " + ProgressSupport.clipFromMiddle(latestCompleted, contentWidth - 12));
    }
    lines.add("  Elapsed   " + ProgressSupport.elapsed(started));

    renderedLines = lines.size();
    renderedRows = 0;
    for (String line : lines) {
      renderedRows += ProgressSupport.renderedRows(line, width);
      System.err.print("\r\033[2K" + line + "\n");
    }
    for (int i = renderedRows; i < maxRenderedRows; i++) {
      System.err.print("\r\033[2K\n");
    }
    maxRenderedLines = Math.max(maxRenderedLines, renderedLines);
    maxRenderedRows = Math.max(maxRenderedRows, renderedRows);
  }

  private String renderPhaseLine(PhaseState state, int contentWidth) {
    int indentWidth = 2;
    int labelWidth = 8;
    int percentWidth = 4;
    int stateWidth = 7;
    int fixedWidth = indentWidth + labelWidth + 1 + 2 + 1 + percentWidth + 2 + stateWidth + 2;
    int available = Math.max(20, contentWidth - fixedWidth);
    int detailWidth = Math.min(48, Math.max(18, available / 3));
    int phaseBarWidth = Math.max(18, available - detailWidth);
    int remainingDetailWidth = Math.max(0, available - phaseBarWidth);

    if (remainingDetailWidth < 18 && available > 36) {
      phaseBarWidth = Math.max(18, available - 18);
      remainingDetailWidth = Math.max(0, available - phaseBarWidth);
    }

    String detail = "Rules".equals(state.label) && tracker.totalRules() > 0
        ? "Rule " + tracker.currentRule() + "/" + tracker.totalRules() + "  " + tracker.currentRuleId()
        : state.detail;
    String plainLeft = "  "
        + ProgressSupport.padRight(state.label, labelWidth)
        + " [" + " ".repeat(Math.max(8, phaseBarWidth)) + "] "
        + ProgressSupport.padLeft(state.percent + "%", percentWidth)
        + "  " + ProgressSupport.padRight(ProgressSupport.shortState(state.state).toUpperCase(), 7)
        + "  ";
    String left = "  "
        + ProgressSupport.padRight(state.label, labelWidth)
        + " "
        + ProgressSupport.renderBar(state.percent, phaseBarWidth, ansi, unicode, ProgressSupport.phaseStateColor(state.state))
        + " " + ProgressSupport.padLeft(state.percent + "%", percentWidth)
        + "  " + ProgressSupport.color(
            ProgressSupport.padRight(ProgressSupport.shortState(state.state).toUpperCase(), 7),
            ProgressSupport.phaseStateColor(state.state),
            ansi)
        + "  ";
    return left + ProgressSupport.clip(detail, Math.max(0, contentWidth - plainLeft.length()));
  }

  private String liveStatusLine() {
    if (tracker.totalRules() > 0) {
      return "Rules " + tracker.currentRule() + "/" + tracker.totalRules() + "  " + tracker.currentRuleId();
    }
    return ProgressSupport.firstNonBlank(currentStatus, currentStage, "Working");
  }

  private String summarize(Report report) {
    if (report == null) return "No report";
    return "findings " + report.totalFindings + "  max " + ProgressSupport.firstNonBlank(report.maxSeverity, "NONE");
  }

  private String aiSuffix(Report report) {
    if (report == null || report.aiStatus == null || report.aiStatus.isBlank()) return "";
    return "  ai " + report.aiStatus;
  }

  private String actionStatus(String message) {
    String compact = ProgressSupport.compact(message);
    if (compact.isBlank()) return "Working";
    String lower = compact.toLowerCase();
    if (lower.contains("parsing")) return "Preparing request from generated curl";
    if (lower.contains("baseline")) return "Sending baseline request";
    if (lower.contains("ai")) return "Waiting for AI enrichment";
    if (lower.contains("json") || lower.contains("report")) return "Writing JSON report artifact";
    if (lower.contains("webhook")) return "Delivering webhook payload";
    return compact;
  }

  private void clearScreen() {
    if (!screenInitialized || maxRenderedRows <= 0) return;
    if (ansi) {
      System.err.print("\033[H");
      for (int i = 0; i < maxRenderedRows; i++) {
        System.err.print("\r\033[2K");
        if (i < maxRenderedRows - 1) System.err.print("\n");
      }
      System.err.print("\033[H\033[?25h");
    } else {
      System.err.println();
    }
  }
}
