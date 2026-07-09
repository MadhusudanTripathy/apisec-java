package com.apisec.cli;

import com.apisec.engine.ScannerEngine.ProgressSink;

import java.nio.charset.Charset;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

class ProgressBar implements ProgressSink, AutoCloseable {
  private static final int OVERALL_BAR_WIDTH = 42;
  private static final int PHASE_BAR_WIDTH = 18;
  private static final String[] SPINNER = {"|", "/", "-", "\\"};
  private static final int SCREEN_LINES = 11;

  private final AtomicInteger overallPercent = new AtomicInteger();
  private final AtomicInteger currentRule = new AtomicInteger();
  private final AtomicInteger totalRules = new AtomicInteger();
  private final AtomicInteger frame = new AtomicInteger();
  private final AtomicReference<String> currentRuleId = new AtomicReference<>("");
  private final AtomicReference<String> currentStage = new AtomicReference<>("Starting");
  private final AtomicReference<String> statusLine = new AtomicReference<>("Preparing scan");
  private final AtomicReference<Phase> activePhase = new AtomicReference<>(Phase.INPUT);
  private final AtomicBoolean running = new AtomicBoolean(true);
  private final boolean ansi = supportsAnsi();
  private final boolean unicode = supportsUnicode();
  private final long started = System.currentTimeMillis();
  private final Thread painter;

  private volatile boolean screenInitialized;

  private final PhaseState input = new PhaseState("Input");
  private final PhaseState baseline = new PhaseState("Baseline");
  private final PhaseState rules = new PhaseState("Rules");
  private final PhaseState ai = new PhaseState("AI");
  private final PhaseState report = new PhaseState("Report");
  private final PhaseState webhook = new PhaseState("Webhook");

  static boolean isInteractive() {
    String disabled = System.getenv("APISEC_PROGRESS");
    return System.console() != null && (disabled == null || !"false".equalsIgnoreCase(disabled));
  }

  ProgressBar() {
    painter = new Thread(this::paintLoop, "apisec-progress");
    painter.setDaemon(true);
    initialisePhases();
    painter.start();
  }

  @Override public void stage(int percent, String message) {
    overallPercent.set(clamp(percent));
    String text = message == null || message.isBlank() ? "Working" : message;
    Phase phase = phaseFor(text);
    activePhase.set(phase);
    currentStage.set(titleCase(text));
    statusLine.set(text);
    updatePhaseStates(phase, clamp(phaseProgress(phase, percent)), text);
    paint();
  }

  @Override public void rules(int current, int total, String ruleId) {
    if (total <= 0) {
      stage(25, "Evaluating rules");
      return;
    }
    currentRule.set(current);
    totalRules.set(total);
    currentRuleId.set(safeRule(ruleId));
    overallPercent.set(clamp(20 + (int) Math.round((current * 68.0) / total)));
    activePhase.set(Phase.RULES);
    currentStage.set("Evaluating Rules");
    statusLine.set("Evaluating " + current + "/" + total + " rules");
    updatePhaseStates(Phase.RULES, clamp((int) Math.round((current * 100.0) / total)), "Rule " + current + "/" + total + "  " + safeRule(ruleId));
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

  private void initialisePhases() {
    for (PhaseState state : phaseStates().values()) {
      state.percent = 0;
      state.state = "pending";
      state.detail = "Waiting";
    }
    input.state = "active";
    input.detail = "Preparing scan";
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
    if (ansi) {
      System.err.print("\033[" + SCREEN_LINES + "A");
      System.err.print("\r");
    }

    String spinner = SPINNER[Math.floorMod(frame.getAndIncrement(), SPINNER.length)];
    int overall = overallPercent.get();
    String heading = color(spinner, "36") + " " + color("API Security Scan", "1;37") + "  " + color(currentStage.get(), "36");
    String overallLine = "Overall  " + renderBar(overall, OVERALL_BAR_WIDTH) + " " + padLeft(overall + "%", 4) + "  " + color(overallLabel(overall), overallColor(overall));
    String summaryLine = "Status   " + clip(statusLine.get(), 96);
    String lanes = "Phases   " + compactPhase(input) + "  " + compactPhase(baseline) + "  " + compactPhase(rules) + "  " + compactPhase(ai) + "  " + compactPhase(report) + "  " + compactPhase(webhook);

    writeLine(heading);
    writeLine(overallLine);
    writeLine(summaryLine);
    writeLine(lanes);
    writeLine(renderPhaseLine(input));
    writeLine(renderPhaseLine(baseline));
    writeLine(renderPhaseLine(rules));
    writeLine(renderPhaseLine(ai));
    writeLine(renderPhaseLine(report));
    writeLine(renderPhaseLine(webhook));
    writeLine("Elapsed  " + elapsed());
  }

  private void updatePhaseStates(Phase active, int phasePercent, String detail) {
    for (Map.Entry<Phase, PhaseState> entry : phaseStates().entrySet()) {
      Phase phase = entry.getKey();
      PhaseState state = entry.getValue();
      if (phase.ordinal() < active.ordinal()) {
        state.percent = 100;
        state.state = "done";
        if (state.detail == null || state.detail.isBlank() || "Waiting".equals(state.detail)) state.detail = "Completed";
      } else if (phase == active) {
        state.percent = phasePercent;
        state.state = overallPercent.get() >= 100 ? "done" : "active";
        state.detail = detail;
      } else if (!"pending".equals(state.state)) {
        state.percent = 0;
        state.state = "pending";
        state.detail = "Waiting";
      }
    }
    if (active != Phase.RULES) {
      currentRule.set(0);
      totalRules.set(0);
      currentRuleId.set("");
    }
  }

  private String renderPhaseLine(PhaseState state) {
    return padRight(state.label, 8)
        + renderBar(state.percent, PHASE_BAR_WIDTH)
        + " "
        + padLeft(state.percent + "%", 4)
        + "  "
        + color(padRight(state.state.toUpperCase(Locale.ROOT), 7), phaseStateColor(state.state))
        + "  "
        + clip(phaseDetail(state), 72);
  }

  private String phaseDetail(PhaseState state) {
    if ("Rules".equals(state.label) && totalRules.get() > 0) {
      return "Rule " + currentRule.get() + "/" + totalRules.get() + "  " + currentRuleId.get();
    }
    return state.detail == null ? "" : state.detail;
  }

  private String compactPhase(PhaseState state) {
    return color(state.label, "1;37") + ":" + color(shortState(state.state), phaseStateColor(state.state));
  }

  private String renderBar(int percent, int width) {
    int filled = Math.max(0, Math.min(width, (percent * width) / 100));
    String fill = unicode ? "█" : "#";
    String empty = unicode ? "░" : "-";
    String bar = fill.repeat(filled) + empty.repeat(Math.max(0, width - filled));
    return "[" + color(bar, overallColor(percent)) + "]";
  }

  private static int phaseProgress(Phase phase, int overallPercent) {
    return switch (phase) {
      case INPUT -> Math.min(100, overallPercent * 100 / 10);
      case BASELINE -> Math.max(0, Math.min(100, (overallPercent - 10) * 100 / 8));
      case RULES -> Math.max(0, Math.min(100, (overallPercent - 18) * 100 / 70));
      case AI -> Math.max(0, Math.min(100, (overallPercent - 88) * 100 / 4));
      case REPORT -> Math.max(0, Math.min(100, (overallPercent - 92) * 100 / 4));
      case WEBHOOK -> Math.max(0, Math.min(100, (overallPercent - 96) * 100 / 4));
      case DONE -> 100;
    };
  }

  private static Phase phaseFor(String message) {
    String m = message == null ? "" : message.toLowerCase(Locale.ROOT);
    if (m.contains("curl")) return Phase.INPUT;
    if (m.contains("baseline")) return Phase.BASELINE;
    if (m.contains("rule")) return Phase.RULES;
    if (m.contains("ai")) return Phase.AI;
    if (m.contains("json") || m.contains("report")) return Phase.REPORT;
    if (m.contains("webhook")) return Phase.WEBHOOK;
    if (m.contains("completed")) return Phase.DONE;
    return Phase.INPUT;
  }

  private Map<Phase, PhaseState> phaseStates() {
    return Map.of(
        Phase.INPUT, input,
        Phase.BASELINE, baseline,
        Phase.RULES, rules,
        Phase.AI, ai,
        Phase.REPORT, report,
        Phase.WEBHOOK, webhook
    );
  }

  private void writeLine(String line) {
    String cleared = clip(line, 140);
    System.err.print("\r\033[2K" + cleared + "\n");
  }

  private void clearScreen() {
    if (!screenInitialized) return;
    if (ansi) {
      System.err.print("\033[" + SCREEN_LINES + "A");
      for (int i = 0; i < SCREEN_LINES; i++) {
        System.err.print("\r\033[2K");
        if (i < SCREEN_LINES - 1) System.err.print("\n");
      }
      System.err.print("\033[" + (SCREEN_LINES - 1) + "A\r");
    } else {
      System.err.println();
    }
  }

  private String color(String text, String code) {
    return ansi ? "\033[" + code + "m" + text + "\033[0m" : text;
  }

  private String elapsed() {
    long total = Math.max(0, (System.currentTimeMillis() - started) / 1000);
    long minutes = total / 60;
    long seconds = total % 60;
    return minutes > 0 ? minutes + "m" + String.format("%02ds", seconds) : seconds + "s";
  }

  private static String overallLabel(int p) {
    if (p >= 100) return "done";
    if (p >= 94) return "writing output";
    if (p >= 90) return "finalizing";
    if (p >= 18) return "evaluating";
    if (p >= 10) return "probing";
    return "starting";
  }

  private static String overallColor(int p) {
    if (p >= 100) return "32";
    if (p >= 90) return "36";
    if (p >= 18) return "33";
    return "37";
  }

  private static String phaseStateColor(String state) {
    return switch (String.valueOf(state).toLowerCase(Locale.ROOT)) {
      case "done" -> "32";
      case "active" -> "36";
      default -> "90";
    };
  }

  private static String shortState(String state) {
    return switch (String.valueOf(state).toLowerCase(Locale.ROOT)) {
      case "done" -> "ok";
      case "active" -> "run";
      default -> "..";
    };
  }

  private static String titleCase(String text) {
    if (text == null || text.isBlank()) return "Working";
    String[] parts = text.trim().split("\\s+");
    StringBuilder out = new StringBuilder();
    for (String part : parts) {
      if (!out.isEmpty()) out.append(' ');
      out.append(part.substring(0, 1).toUpperCase(Locale.ROOT));
      if (part.length() > 1) out.append(part.substring(1));
    }
    return out.toString();
  }

  private static String safeRule(String ruleId) {
    return ruleId == null ? "" : ruleId.replaceAll("[^A-Za-z0-9:_-]", "");
  }

  private static int clamp(int value) {
    return Math.max(0, Math.min(100, value));
  }

  private static String clip(String s, int max) {
    if (s == null) return "";
    String compact = s.replaceAll("\\s+", " ");
    return compact.length() > max ? compact.substring(0, Math.max(0, max - 3)) + "..." : compact;
  }

  private static String padLeft(String text, int width) {
    return " ".repeat(Math.max(0, width - text.length())) + text;
  }

  private static String padRight(String text, int width) {
    return text + " ".repeat(Math.max(0, width - text.length()));
  }

  private static boolean supportsAnsi() {
    String term = System.getenv("TERM");
    return System.console() != null
        && System.getenv("NO_COLOR") == null
        && term != null
        && !"dumb".equalsIgnoreCase(term);
  }

  private static boolean supportsUnicode() {
    String ascii = System.getenv("APISEC_ASCII_PROGRESS");
    return (ascii == null || !Boolean.parseBoolean(ascii))
        && Charset.defaultCharset().name().toLowerCase(Locale.ROOT).contains("utf");
  }

  private enum Phase {
    INPUT, BASELINE, RULES, AI, REPORT, WEBHOOK, DONE
  }

  private static final class PhaseState {
    private final String label;
    private volatile int percent;
    private volatile String state;
    private volatile String detail;

    private PhaseState(String label) {
      this.label = label;
    }
  }
}
