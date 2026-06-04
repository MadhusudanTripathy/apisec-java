package com.apisec.config;

import org.yaml.snakeyaml.Yaml;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.Pattern;

public class AppConfig {
  public Scanner scanner = new Scanner();
  public Rules rules = new Rules();
  public Reports reports = new Reports();
  public Webhook webhook = new Webhook();

  public static class Scanner {
    public String mode = "safe";
    public int timeoutSeconds = 10;
    public int maxRequestsPerRule = 3;
    public boolean redactSecrets = true;
    public boolean allowDangerous = false;
  }
  public static class Rules {
    public String directory = "~/.apisec/rules";
    public List<String> activeGroups = new ArrayList<>(List.of("owasp-api-2023"));
  }
  public static class Reports {
    public String directory = "~/.apisec/reports";
    public String fileNamePattern = "scan_{timestamp}_{scanId}.json";
    public boolean redactSecrets = true;
  }
  public static class Webhook {
    public boolean enabled = false;
    public String url = "";
    public String secret = "";
    public String tenant = "";
    public int timeoutSeconds = 5;
    public int retries = 3;
  }

  public static AppConfig defaults() {
    AppConfig c = new AppConfig();
    c.rules.directory = expand(c.rules.directory);
    c.reports.directory = expand(c.reports.directory);
    return c;
  }

  public static AppConfig resolve(String configPath, String rulesDir, String reportDir, String webhookUrl,
                                  String webhookSecret, String webhookTenant, Integer timeout, Integer maxRequests,
                                  Boolean redact, Boolean allowDangerous) throws IOException {
    AppConfig c = defaults();
    String path = firstNonBlank(configPath, System.getenv("APISEC_CONFIG"), "~/.apisec/apisec-java.properties");
    Path p = Paths.get(expand(path));
    if (Files.exists(p)) mergeConfigFile(c, p);
    overrideEnv(c);
    if (rulesDir != null && !rulesDir.isBlank()) c.rules.directory = expand(rulesDir);
    if (reportDir != null && !reportDir.isBlank()) c.reports.directory = expand(reportDir);
    if (webhookUrl != null && !webhookUrl.isBlank()) { c.webhook.enabled = true; c.webhook.url = webhookUrl; }
    if (webhookSecret != null && !webhookSecret.isBlank()) c.webhook.secret = webhookSecret;
    if (webhookTenant != null && !webhookTenant.isBlank()) c.webhook.tenant = webhookTenant;
    if (timeout != null) c.scanner.timeoutSeconds = timeout;
    if (maxRequests != null) c.scanner.maxRequestsPerRule = maxRequests;
    if (redact != null) { c.scanner.redactSecrets = redact; c.reports.redactSecrets = redact; }
    if (allowDangerous != null) c.scanner.allowDangerous = allowDangerous;
    return c;
  }

  public static void initDefault() throws IOException {
    AppConfig c = defaults();
    Files.createDirectories(Paths.get(c.rules.directory));
    Files.createDirectories(Paths.get(c.reports.directory));
    Files.createDirectories(Paths.get(expand("~/.apisec/cache")));
    Path cfg = Paths.get(expand("~/.apisec/config.yaml"));
    Files.createDirectories(cfg.getParent());
    Path props = Paths.get(expand("~/.apisec/apisec-java.properties"));
    if (!Files.exists(props)) Files.writeString(props, DEFAULT_PROPERTIES);
    if (!Files.exists(cfg)) Files.writeString(cfg, DEFAULT_YAML);
  }

  private static void mergeConfigFile(AppConfig c, Path path) throws IOException {
    String lower = path.getFileName().toString().toLowerCase(Locale.ROOT);
    if (lower.endsWith(".properties")) {
      Properties props = new Properties();
      try (InputStream in = Files.newInputStream(path)) {
        props.load(in);
      }
      mergeProperties(c, props);
      return;
    }
    merge(c, new Yaml().load(Files.newInputStream(path)));
  }

  private static void mergeProperties(AppConfig c, Properties p) {
    c.scanner.mode = prop(p, "scanner.mode", c.scanner.mode);
    c.scanner.timeoutSeconds = intVal(p.getProperty("scanner.timeoutSeconds"), c.scanner.timeoutSeconds);
    c.scanner.maxRequestsPerRule = intVal(p.getProperty("scanner.maxRequestsPerRule"), c.scanner.maxRequestsPerRule);
    c.scanner.redactSecrets = boolVal(p.getProperty("scanner.redactSecrets"), c.scanner.redactSecrets);
    c.scanner.allowDangerous = boolVal(p.getProperty("scanner.allowDangerous"), c.scanner.allowDangerous);
    c.rules.directory = expand(prop(p, "rules.directory", c.rules.directory));
    String activeGroups = p.getProperty("rules.activeGroups");
    if (activeGroups != null && !activeGroups.isBlank()) {
      c.rules.activeGroups = Arrays.stream(activeGroups.split(",")).map(String::trim).filter(s -> !s.isBlank()).toList();
    }
    c.reports.directory = expand(prop(p, "reports.directory", c.reports.directory));
    c.reports.fileNamePattern = prop(p, "reports.fileNamePattern", c.reports.fileNamePattern);
    c.reports.redactSecrets = boolVal(p.getProperty("reports.redactSecrets"), c.reports.redactSecrets);
    c.webhook.enabled = boolVal(p.getProperty("webhook.enabled"), c.webhook.enabled);
    c.webhook.url = expandEnv(prop(p, "webhook.url", c.webhook.url));
    c.webhook.secret = expandEnv(prop(p, "webhook.secret", c.webhook.secret));
    c.webhook.tenant = expandEnv(prop(p, "webhook.tenant", c.webhook.tenant));
    c.webhook.timeoutSeconds = intVal(p.getProperty("webhook.timeoutSeconds"), c.webhook.timeoutSeconds);
    c.webhook.retries = intVal(p.getProperty("webhook.retries"), c.webhook.retries);
  }

  @SuppressWarnings("unchecked")
  private static void merge(AppConfig c, Object yaml) {
    if (!(yaml instanceof Map<?,?> root)) return;
    Map<String,Object> scanner = (Map<String,Object>) root.get("scanner");
    if (scanner != null) {
      c.scanner.timeoutSeconds = intVal(scanner.get("timeoutSeconds"), c.scanner.timeoutSeconds);
      c.scanner.maxRequestsPerRule = intVal(scanner.get("maxRequestsPerRule"), c.scanner.maxRequestsPerRule);
      c.scanner.redactSecrets = boolVal(scanner.get("redactSecrets"), c.scanner.redactSecrets);
      c.scanner.allowDangerous = boolVal(scanner.get("allowDangerous"), c.scanner.allowDangerous);
    }
    Map<String,Object> rules = (Map<String,Object>) root.get("rules");
    if (rules != null) {
      if (rules.get("directory") != null) c.rules.directory = expand(String.valueOf(rules.get("directory")));
      if (rules.get("activeGroups") instanceof List<?> l) c.rules.activeGroups = l.stream().map(String::valueOf).toList();
    }
    Map<String,Object> reports = (Map<String,Object>) root.get("reports");
    if (reports != null) {
      if (reports.get("directory") != null) c.reports.directory = expand(String.valueOf(reports.get("directory")));
      c.reports.redactSecrets = boolVal(reports.get("redactSecrets"), c.reports.redactSecrets);
    }
    Map<String,Object> webhook = (Map<String,Object>) root.get("webhook");
    if (webhook != null) {
      c.webhook.enabled = boolVal(webhook.get("enabled"), c.webhook.enabled);
      if (webhook.get("url") != null) c.webhook.url = String.valueOf(webhook.get("url"));
      if (webhook.get("secret") != null) c.webhook.secret = String.valueOf(webhook.get("secret"));
      if (webhook.get("tenant") != null) c.webhook.tenant = String.valueOf(webhook.get("tenant"));
      c.webhook.timeoutSeconds = intVal(webhook.get("timeoutSeconds"), c.webhook.timeoutSeconds);
      c.webhook.retries = intVal(webhook.get("retries"), c.webhook.retries);
    }
  }

  private static void overrideEnv(AppConfig c) {
    if (env("APISEC_RULES_DIR") != null) c.rules.directory = expand(env("APISEC_RULES_DIR"));
    if (env("APISEC_REPORT_DIR") != null) c.reports.directory = expand(env("APISEC_REPORT_DIR"));
    if (env("APISEC_WEBHOOK_URL") != null) { c.webhook.enabled = true; c.webhook.url = env("APISEC_WEBHOOK_URL"); }
    if (env("APISEC_WEBHOOK_SECRET") != null) c.webhook.secret = env("APISEC_WEBHOOK_SECRET");
    if (env("APISEC_WEBHOOK_TENANT") != null) c.webhook.tenant = env("APISEC_WEBHOOK_TENANT");
    if (env("APISEC_TIMEOUT_SECONDS") != null) c.scanner.timeoutSeconds = Integer.parseInt(env("APISEC_TIMEOUT_SECONDS"));
    if (env("APISEC_MAX_REQUESTS_PER_RULE") != null) c.scanner.maxRequestsPerRule = Integer.parseInt(env("APISEC_MAX_REQUESTS_PER_RULE"));
    if (env("APISEC_REDACT_SECRETS") != null) c.scanner.redactSecrets = Boolean.parseBoolean(env("APISEC_REDACT_SECRETS"));
  }

  public static String expand(String p) {
    return p == null ? "" : p.replaceFirst("^~", System.getProperty("user.home"));
  }
  public static String expandEnv(String p) {
    if (p == null) return "";
    String out = p;
    for (Map.Entry<String, String> e : System.getenv().entrySet()) {
      out = out.replace("${" + e.getKey() + "}", e.getValue());
    }
    return Pattern.compile("\\$\\{[A-Za-z_][A-Za-z0-9_]*}").matcher(out).replaceAll("");
  }
  private static String env(String k) { return System.getenv(k); }
  private static String prop(Properties p, String k, String d) { String v = p.getProperty(k); return v == null || v.isBlank() ? d : v; }
  private static String firstNonBlank(String... vals) { for (String v: vals) if (v != null && !v.isBlank()) return v; return ""; }
  private static int intVal(Object v, int d) { return v == null ? d : Integer.parseInt(String.valueOf(v)); }
  private static boolean boolVal(Object v, boolean d) { return v == null ? d : Boolean.parseBoolean(String.valueOf(v)); }

  public static final String DEFAULT_PROPERTIES = """
scanner.mode=safe
scanner.timeoutSeconds=10
scanner.maxRequestsPerRule=3
scanner.redactSecrets=true
scanner.allowDangerous=false

rules.directory=~/.apisec/rules
rules.activeGroups=owasp-api-2023

reports.directory=~/.apisec/reports
reports.fileNamePattern=scan_{timestamp}_{scanId}.json
reports.redactSecrets=true

webhook.enabled=false
webhook.url=
webhook.secret=
webhook.tenant=
webhook.timeoutSeconds=5
webhook.retries=3
""";

  public static final String DEFAULT_YAML = """
scanner:
  mode: safe
  timeoutSeconds: 10
  maxRequestsPerRule: 3
  redactSecrets: true
  allowDangerous: false
rules:
  directory: "~/.apisec/rules"
  activeGroups: ["owasp-api-2023"]
reports:
  directory: "~/.apisec/reports"
  fileNamePattern: "scan_{timestamp}_{scanId}.json"
  redactSecrets: true
webhook:
  enabled: false
  url: ""
  secret: ""
  tenant: ""
  timeoutSeconds: 5
  retries: 3
""";
}
