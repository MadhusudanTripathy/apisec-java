package com.apisec.cli;

import com.apisec.engine.ScannerEngine.ProgressSink;
import com.apisec.cli.ProgressSupport.PhaseState;
import com.apisec.cli.ProgressSupport.PhaseTracker;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

class ProgressBar implements ProgressSink, AutoCloseable {
  private final AtomicInteger overallPercent = new AtomicInteger();
  private final AtomicInteger frame = new AtomicInteger();
  private final AtomicReference<String> currentStage = new AtomicReference<>("Starting");
  private final AtomicReference<String> statusLine = new AtomicReference<>("Preparing scan");
  private final AtomicBoolean running = new AtomicBoolean(true);
  private final boolean ansi = ProgressSupport.supportsLiveDashboard();
  private final boolean unicode = ProgressSupport.supportsUnicode();
  private final long started = System.currentTimeMillis();
  private final Thread painter;
  private final PhaseTracker tracker = new PhaseTracker();

  private volatile boolean screenInitialized;
  private volatile int renderedLines;

  static boolean isInteractive() {
    return ProgressSupport.supportsLiveDashboard();
  }

  ProgressBar() {
    painter = new Thread(this::paintLoop, "apisec-progress");
    painter.setDaemon(true);
    painter.start();
  }

  @Override public void stage(int percent, String message) {
    overallPercent.set(ProgressSupport.clamp(percent));
    String text = message == null || message.isBlank() ? "Working" : message;
    currentStage.set(ProgressSupport.titleCase(text));
    statusLine.set(text);
    tracker.stage(overallPercent.get(), text);
    paint();
  }

  @Override public void rules(int current, int total, String ruleId) {
    if (total <= 0) {
      stage(25, "Evaluating rules");
      return;
    }
    overallPercent.set(ProgressSupport.clamp(20 + (int) Math.round((current * 68.0) / total)));
    currentStage.set("Evaluating Rules");
    statusLine.set("Evaluating " + current + "/" + total + " rules");
    tracker.rules(current, total, ruleId, overallPercent.get());
    paint();
  }

  @Override public void done() {
    stage(100, "Completed");
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
      System.err.println();
      screenInitialized = true;
    }
    if (ansi && renderedLines > 0) {
      System.err.print("\033[" + renderedLines + "A\r");
    }

    int width = Math.max(80, ProgressSupport.terminalWidth());
    int contentWidth = Math.max(76, width - 2);
    int overall = overallPercent.get();
    int barWidth = Math.max(18, Math.min(72, contentWidth - 28));
    int phaseBarWidth = Math.max(12, Math.min(48, contentWidth / 4));
    String spinner = ProgressSupport.SPINNER[Math.floorMod(frame.getAndIncrement(), ProgressSupport.SPINNER.length)];

    List<String> lines = new java.util.ArrayList<>();
    lines.add(ProgressSupport.color(spinner, "36", ansi) + " "
        + ProgressSupport.color("API Security Scan", "1;37", ansi) + "  "
        + ProgressSupport.color(currentStage.get(), "36", ansi));
    lines.add("Overall  "
        + ProgressSupport.renderBar(overall, barWidth, ansi, unicode, ProgressSupport.overallColor(overall))
        + " " + ProgressSupport.padLeft(overall + "%", 4)
        + "  " + ProgressSupport.color(ProgressSupport.overallLabel(overall), ProgressSupport.overallColor(overall), ansi));
    lines.add("Status   " + ProgressSupport.clip(statusLine.get(), contentWidth - 9));
    lines.add("Phases   " + compactPhases(contentWidth - 9));
    for (PhaseState state : tracker.orderedStates()) {
      lines.add(renderPhaseLine(state, phaseBarWidth, contentWidth));
    }
    lines.add("Elapsed  " + ProgressSupport.elapsed(started));

    renderedLines = lines.size();
    for (String line : lines) {
      System.err.print("\r\033[2K" + line + "\n");
    }
  }

  private String compactPhases(int width) {
    StringBuilder out = new StringBuilder();
    for (PhaseState state : tracker.orderedStates()) {
      if (!out.isEmpty()) out.append("  ");
      out.append(ProgressSupport.color(state.label, "1;37", ansi))
          .append(":")
          .append(ProgressSupport.color(ProgressSupport.shortState(state.state), ProgressSupport.phaseStateColor(state.state), ansi));
    }
    return out.toString();
  }

  private String renderPhaseLine(PhaseState state, int phaseBarWidth, int contentWidth) {
    String detail = "Rules".equals(state.label) && tracker.totalRules() > 0
        ? "Rule " + tracker.currentRule() + "/" + tracker.totalRules() + "  " + tracker.currentRuleId()
        : state.detail;
    String plainLeft = ProgressSupport.padRight(state.label, 8)
        + "[" + " ".repeat(Math.max(8, phaseBarWidth)) + "] "
        + ProgressSupport.padLeft(state.percent + "%", 4)
        + "  " + ProgressSupport.padRight(state.state.toUpperCase(), 7)
        + "  ";
    String left = ProgressSupport.padRight(state.label, 8)
        + ProgressSupport.renderBar(state.percent, phaseBarWidth, ansi, unicode, ProgressSupport.phaseStateColor(state.state))
        + " " + ProgressSupport.padLeft(state.percent + "%", 4)
        + "  " + ProgressSupport.color(ProgressSupport.padRight(state.state.toUpperCase(), 7), ProgressSupport.phaseStateColor(state.state), ansi)
        + "  ";
    return left + ProgressSupport.clip(detail, Math.max(12, contentWidth - plainLeft.length()));
  }

  private void clearScreen() {
    if (!screenInitialized || renderedLines <= 0) return;
    if (ansi) {
      System.err.print("\033[" + renderedLines + "A");
      for (int i = 0; i < renderedLines; i++) {
        System.err.print("\r\033[2K");
        if (i < renderedLines - 1) System.err.print("\n");
      }
      System.err.print("\033[" + Math.max(0, renderedLines - 1) + "A\r");
    } else {
      System.err.println();
    }
  }
}
