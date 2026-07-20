package com.apisec.cli;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

final class ProgressSupport {
  static final String[] SPINNER = {"|", "/", "-", "\\"};
  private static final Pattern ANSI_ESCAPE = Pattern.compile("\u001B\\[[;?0-9]*[ -/]*[@-~]");
  static final String APIWIZ_ASCII_ART = """
           ▗▄▖ ▗▄▄▖▗▄▄▄▖▗▖ ▗▖▗▄▄▄▖▗▄▄▄▄▖
          ▐▌ ▐▌▐▌ ▐▌ █  ▐▌ ▐▌  █     ▗▞▘
          ▐▛▀▜▌▐▛▀▘  █  ▐▌ ▐▌  █   ▗▞▘ \s
          ▐▌ ▐▌▐▌  ▗▄█▄▖▐▙█▟▌▗▄█▄▖▐▙▄▄▄▖                                     \s
          """;

  private ProgressSupport() {}

  static boolean isInteractive() {
    String disabled = System.getenv("APISEC_PROGRESS");
    String forced = System.getenv("APISEC_FORCE_INTERACTIVE");
    if (forced != null && Boolean.parseBoolean(forced)) return true;
    return System.console() != null && (disabled == null || !"false".equalsIgnoreCase(disabled));
  }

  static boolean supportsAnsi() {
    String term = System.getenv("TERM");
    String forced = System.getenv("APISEC_FORCE_INTERACTIVE");
    if (forced != null && Boolean.parseBoolean(forced)) {
      return System.getenv("NO_COLOR") == null
          && term != null
          && !"dumb".equalsIgnoreCase(term);
    }
    return System.console() != null
        && System.getenv("NO_COLOR") == null
        && term != null
        && !"dumb".equalsIgnoreCase(term);
  }

  static boolean supportsLiveDashboard() {
    if (!isInteractive() || !supportsAnsi()) return false;
    String forced = System.getenv("APISEC_FORCE_LIVE_DASHBOARD");
    if (forced != null) return Boolean.parseBoolean(forced);
    if (!isWindows()) return true;

    return isGitBashLikeWindows()
        || isPresent("WT_SESSION")
        || isPresent("TERM_PROGRAM")
        || isPresent("ConEmuANSI")
        || isPresent("ANSICON");
  }

  static boolean supportsUnicode() {
    String ascii = System.getenv("APISEC_ASCII_PROGRESS");
    return (ascii == null || !Boolean.parseBoolean(ascii))
        && Charset.defaultCharset().name().toLowerCase(Locale.ROOT).contains("utf");
  }

  static int terminalWidth() {
    String columns = System.getenv("COLUMNS");
    if (columns != null && columns.matches("\\d+")) {
      int parsed = Integer.parseInt(columns);
      if (parsed >= 60) return parsed;
    }
    Integer tputWidth = posixCommandWidth("tput cols 2>/dev/null");
    if (tputWidth != null && tputWidth >= 60) {
      return tputWidth;
    }
    Integer sttyWidth = sttyWidth();
    if (sttyWidth != null && sttyWidth >= 60) {
      return sttyWidth;
    }
    if (isGitBashLikeWindows()) {
      return 80;
    }
    if (isWindows()) {
      Integer modeWidth = commandWidth("cmd", "/c", "mode con");
      if (modeWidth != null && modeWidth >= 60) {
        return modeWidth;
      }
      Integer powershellWidth = commandWidth(
          "powershell", "-NoProfile", "-Command",
          "$Host.UI.RawUI.WindowSize.Width");
      if (powershellWidth != null && powershellWidth >= 60) {
        return powershellWidth;
      }
    }
    return isWindows() ? 100 : 140;
  }

  static int dashboardWidth() {
    int margin = isGitBashLikeWindows() ? 12 : (isWindows() ? 8 : 4);
    int width = terminalWidth() - margin;
    return Math.max(72, width);
  }

  private static Integer sttyWidth() {
    try {
      Process process = posixShell("stty size < /dev/tty").start();
      try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
        String line = reader.readLine();
        process.waitFor();
        if (line != null) {
          String[] parts = line.trim().split("\\s+");
          if (parts.length == 2 && parts[1].matches("\\d+")) {
            int parsed = Integer.parseInt(parts[1]);
            if (parsed >= 60) return parsed;
          }
        }
      }
    } catch (Exception ignored) {
    }
    return null;
  }

  private static Integer posixCommandWidth(String command) {
    try {
      Process process = posixShell(command).start();
      try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
        String line = reader.readLine();
        process.waitFor();
        if (line == null) return null;
        String trimmed = line.trim();
        if (trimmed.matches("\\d+")) {
          return Integer.parseInt(trimmed);
        }
      }
    } catch (Exception ignored) {
    }
    return null;
  }

  private static ProcessBuilder posixShell(String command) {
    if (isWindows()) {
      if (isPresent("MSYSTEM")) {
        return new ProcessBuilder("sh", "-lc", command);
      }
      return new ProcessBuilder("bash", "-lc", command);
    }
    return new ProcessBuilder("/bin/sh", "-lc", command);
  }

  private static Integer commandWidth(String... command) {
    try {
      Process process = new ProcessBuilder(command).start();
      try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
        String line = reader.readLine();
        process.waitFor();
        if (line == null) return null;
        String trimmed = line.trim();
        if (trimmed.matches("\\d+")) {
          return Integer.parseInt(trimmed);
        }
        if (trimmed.toLowerCase(Locale.ROOT).contains("columns:")) {
          String digits = trimmed.replaceAll(".*columns:\\s*", "").replaceAll("[^0-9].*", "");
          if (digits.matches("\\d+")) {
            return Integer.parseInt(digits);
          }
        }
      }
    } catch (Exception ignored) {
    }
    return null;
  }

  static int clamp(int value) {
    return Math.max(0, Math.min(100, value));
  }

  static String titleCase(String text) {
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

  static String safeRule(String ruleId) {
    return ruleId == null ? "" : ruleId.replaceAll("[^A-Za-z0-9:_-]", "");
  }

  static String compact(String text) {
    return text == null ? "" : text.replaceAll("\\s+", " ").trim();
  }

  static String clip(String text, int max) {
    String compact = compact(text);
    if (compact.length() <= max) return compact;
    return compact.substring(0, Math.max(0, max - 3)) + "...";
  }

  static int renderedRows(String text, int width) {
    int safeWidth = Math.max(1, width);
    int visibleLength = stripAnsi(text).length();
    return Math.max(1, (visibleLength + safeWidth - 1) / safeWidth);
  }

  static String stripAnsi(String text) {
    if (text == null || text.isEmpty()) return "";
    return ANSI_ESCAPE.matcher(text).replaceAll("");
  }

  static String clipFromMiddle(String text, int max) {
    String compact = compact(text);
    if (compact.length() <= max) return compact;
    if (max <= 5) return clip(compact, max);
    int keep = max - 3;
    int left = keep / 2;
    int right = keep - left;
    return compact.substring(0, left) + "..." + compact.substring(compact.length() - right);
  }

  static String truncateFromStart(String text, int max) {
    String compact = compact(text);
    if (compact.length() <= max) return compact;
    if (max <= 3) return clip(compact, max);
    return "..." + compact.substring(compact.length() - (max - 3));
  }

  static int asciiArtWidth() {
    return asciiArtLines().stream().mapToInt(String::length).max().orElse(0);
  }

  static List<String> centeredAsciiArt(int width) {
    List<String> lines = new ArrayList<>();
    for (String line : asciiArtLines()) {
      int left = Math.max(0, (width - line.length()) / 2);
      lines.add(" ".repeat(left) + line);
    }
    return lines;
  }

  static List<String> asciiArtLines() {
    return APIWIZ_ASCII_ART.lines().toList();
  }

  static String padLeft(String text, int width) {
    return " ".repeat(Math.max(0, width - text.length())) + text;
  }

  static String padRight(String text, int width) {
    return text + " ".repeat(Math.max(0, width - text.length()));
  }

  static String color(String text, String code, boolean ansi) {
    return ansi ? "\033[" + code + "m" + text + "\033[0m" : text;
  }

  static String renderBar(int percent, int width, boolean ansi, boolean unicode, String code) {
    int safeWidth = Math.max(8, width);
    int filled = Math.max(0, Math.min(safeWidth, (percent * safeWidth) / 100));
    String fill = unicode ? "█" : "#";
    String empty = unicode ? "░" : "-";
    String bar = fill.repeat(filled) + empty.repeat(Math.max(0, safeWidth - filled));
    return "[" + color(bar, code, ansi) + "]";
  }

  static String elapsed(long startedAt) {
    long total = Math.max(0, (System.currentTimeMillis() - startedAt) / 1000);
    long minutes = total / 60;
    long seconds = total % 60;
    return minutes > 0 ? minutes + "m" + String.format("%02ds", seconds) : seconds + "s";
  }

  static String overallLabel(int p) {
    if (p >= 100) return "done";
    if (p >= 94) return "writing output";
    if (p >= 90) return "finalizing";
    if (p >= 18) return "evaluating";
    if (p >= 10) return "probing";
    return "starting";
  }

  static String overallColor(int p) {
    if (p >= 100) return "32";
    if (p >= 90) return "36";
    if (p >= 18) return "33";
    return "37";
  }

  static String phaseStateColor(String state) {
    return switch (String.valueOf(state).toLowerCase(Locale.ROOT)) {
      case "done" -> "32";
      case "active" -> "36";
      default -> "90";
    };
  }

  static String shortState(String state) {
    return switch (String.valueOf(state).toLowerCase(Locale.ROOT)) {
      case "done" -> "ok";
      case "active" -> "run";
      default -> "..";
    };
  }

  static String urlHostLine(String method, String url, int width) {
    String compact = compact(url);
    int scheme = compact.indexOf("://");
    if (scheme < 0) return clipFromMiddle(firstNonBlank(method, "GET") + " " + compact, width);
    int hostStart = scheme + 3;
    int slash = compact.indexOf('/', hostStart);
    String host = slash < 0 ? compact : compact.substring(0, slash);
    return clipFromMiddle(firstNonBlank(method, "GET") + " " + host, width);
  }

  static String urlPathLine(String url, String operationId, int width) {
    String compact = compact(url);
    int scheme = compact.indexOf("://");
    String path = compact;
    if (scheme >= 0) {
      int hostStart = scheme + 3;
      int slash = compact.indexOf('/', hostStart);
      if (slash >= 0) path = compact.substring(slash);
    }
    String op = compact(operationId);
    if (!op.isBlank()) path = path + "  op=" + op;
    return clipFromMiddle(path, width);
  }

  static String firstNonBlank(String... values) {
    for (String value : values) {
      if (value != null && !value.isBlank()) return value;
    }
    return "";
  }

  static boolean progressDebugEnabled() {
    String value = System.getenv("APISEC_PROGRESS_DEBUG");
    return value != null && Boolean.parseBoolean(value);
  }

  static void debug(String component, String message) {
    if (!progressDebugEnabled()) return;
    try {
      Path logs = Path.of("").toAbsolutePath().normalize().resolve("logs");
      Files.createDirectories(logs);
      Files.writeString(
          logs.resolve("progress-debug.log"),
          "[progress-debug] " + component + " " + message + System.lineSeparator(),
          StandardCharsets.UTF_8,
          StandardOpenOption.CREATE,
          StandardOpenOption.APPEND);
    } catch (Exception ignored) {
    }
  }

  static String terminalSummary() {
    return "os=" + System.getProperty("os.name", "")
        + " term=" + firstNonBlank(System.getenv("TERM"))
        + " msystem=" + firstNonBlank(System.getenv("MSYSTEM"))
        + " wtSession=" + firstNonBlank(System.getenv("WT_SESSION"))
        + " termProgram=" + firstNonBlank(System.getenv("TERM_PROGRAM"))
        + " conEmuAnsi=" + firstNonBlank(System.getenv("ConEmuANSI"))
        + " ansicon=" + firstNonBlank(System.getenv("ANSICON"))
        + " noColor=" + firstNonBlank(System.getenv("NO_COLOR"))
        + " console=" + (System.console() != null)
        + " interactive=" + isInteractive()
        + " ansi=" + supportsAnsi()
        + " live=" + supportsLiveDashboard()
        + " unicode=" + supportsUnicode()
        + " width=" + terminalWidth()
        + " dashboardWidth=" + dashboardWidth();
  }

  private static boolean isWindows() {
    return System.getProperty("os.name", "")
        .toLowerCase(Locale.ROOT)
        .contains("win");
  }

  static boolean isGitBashLikeWindows() {
    if (!isWindows()) return false;
    return isPresent("MSYSTEM")
        || "xterm".equalsIgnoreCase(System.getenv("TERM"))
        || firstNonBlank(System.getenv("TERM")).toLowerCase(Locale.ROOT).contains("mintty");
  }

  private static boolean isPresent(String key) {
    String value = System.getenv(key);
    return value != null && !value.isBlank();
  }

  enum Phase {
    INPUT("Input"),
    BASELINE("Baseline"),
    RULES("Rules"),
    AI("AI"),
    REPORT("Report"),
    WEBHOOK("Webhook"),
    DONE("Done");

    final String label;

    Phase(String label) {
      this.label = label;
    }
  }

  static final class PhaseState {
    final String label;
    int percent;
    String state;
    String detail;

    PhaseState(String label) {
      this.label = label;
      this.percent = 0;
      this.state = "pending";
      this.detail = "Waiting";
    }
  }

  static final class PhaseTracker {
    private final Map<Phase, PhaseState> phaseStates = new LinkedHashMap<>();
    private int currentRule;
    private int totalRules;
    private String currentRuleId = "";

    PhaseTracker() {
      phaseStates.put(Phase.INPUT, new PhaseState(Phase.INPUT.label));
      phaseStates.put(Phase.BASELINE, new PhaseState(Phase.BASELINE.label));
      phaseStates.put(Phase.RULES, new PhaseState(Phase.RULES.label));
      phaseStates.put(Phase.AI, new PhaseState(Phase.AI.label));
      phaseStates.put(Phase.REPORT, new PhaseState(Phase.REPORT.label));
      phaseStates.put(Phase.WEBHOOK, new PhaseState(Phase.WEBHOOK.label));
      initialise();
    }

    void initialise() {
      for (PhaseState state : phaseStates.values()) {
        state.percent = 0;
        state.state = "pending";
        state.detail = "Waiting";
      }
      phaseStates.get(Phase.INPUT).state = "active";
      phaseStates.get(Phase.INPUT).detail = "Preparing scan";
      currentRule = 0;
      totalRules = 0;
      currentRuleId = "";
    }

    void stage(int overallPercent, String message) {
      String text = message == null || message.isBlank() ? "Working" : message;
      Phase phase = phaseFor(text);
      updatePhaseStates(phase, clamp(phaseProgress(phase, overallPercent)), text, overallPercent);
    }

    void rules(int current, int total, String ruleId, int overallPercent) {
      currentRule = current;
      totalRules = total;
      currentRuleId = safeRule(ruleId);
      updatePhaseStates(Phase.RULES, total <= 0 ? 0 : clamp((int) Math.round((current * 100.0) / total)),
          total <= 0 ? "Evaluating rules" : "Rule " + current + "/" + total + "  " + currentRuleId,
          overallPercent);
    }

    List<PhaseState> orderedStates() {
      return new ArrayList<>(phaseStates.values());
    }

    int currentRule() { return currentRule; }
    int totalRules() { return totalRules; }
    String currentRuleId() { return currentRuleId; }

    private void updatePhaseStates(Phase active, int phasePercent, String detail, int overallPercent) {
      for (Map.Entry<Phase, PhaseState> entry : phaseStates.entrySet()) {
        Phase phase = entry.getKey();
        PhaseState state = entry.getValue();
        if (phase.ordinal() < active.ordinal()) {
          state.percent = 100;
          state.state = "done";
          if (state.detail == null || state.detail.isBlank() || "Waiting".equals(state.detail)) state.detail = "Completed";
        } else if (phase == active) {
          state.percent = phasePercent;
          state.state = overallPercent >= 100 ? "done" : "active";
          state.detail = detail;
        } else {
          state.percent = 0;
          state.state = "pending";
          state.detail = "Waiting";
        }
      }
      if (active != Phase.RULES) {
        currentRule = 0;
        totalRules = 0;
        currentRuleId = "";
      }
    }

    private static Phase phaseFor(String message) {
      String m = message == null ? "" : message.toLowerCase(Locale.ROOT);
      if (m.contains("curl") || m.contains("parsing")) return Phase.INPUT;
      if (m.contains("baseline")) return Phase.BASELINE;
      if (m.contains("rule")) return Phase.RULES;
      if (m.contains("ai")) return Phase.AI;
      if (m.contains("json") || m.contains("report")) return Phase.REPORT;
      if (m.contains("webhook")) return Phase.WEBHOOK;
      if (m.contains("completed")) return Phase.DONE;
      return Phase.INPUT;
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
  }
}
