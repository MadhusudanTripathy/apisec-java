package com.apisec.config;

import org.yaml.snakeyaml.Yaml;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.Pattern;

public class AppConfig {
  public static final List<String> DEFAULT_ACTIVE_RULE_GROUPS = List.of(
      "api1-broken-object-level-authorization",
      "api2-broken-authentication",
      "api3-broken-object-property-level-authorization",
      "api4-unrestricted-resource-consumption",
      "api5-broken-function-level-authorization",
      "api6-unrestricted-access-to-sensitive-business-flows",
      "api7-server-side-request-forgery",
      "api8-security-misconfiguration",
      "api9-improper-inventory-management",
      "api10-unsafe-consumption-of-apis"
  );
  public Apiwiz apiwiz = new Apiwiz();
  public Scanner scanner = new Scanner();
  public Application application = new Application();
  public OpenAI openai = new OpenAI();
  public Rules rules = new Rules();
  public Reports reports = new Reports();
  public Webhook webhook = new Webhook();

  public static class Apiwiz {
    public String tenant = "";
    public String xApiKey = "";
  }
  public static class Scanner {
    public String mode = "safe";
    public int timeoutSeconds = 10;
    public int maxRequestsPerRule = 3;
    public boolean redactSecrets = true;
    public boolean allowDangerous = false;
  }
  public static class Application {
    public Scan scan = new Scan();
  }
  public static class Scan {
    public String sourceUrl = "";
  }
  public static class OpenAI {
    public boolean enabled = false;
    public String baseUrl = "https://api.openai.com/v1/chat/completions";
    public String apiKey = "";
    public String model = "gpt-4o-mini";
    public int timeoutSeconds = 20;
    public int maxFindings = 10;
    public double temperature = 0.2d;
    public boolean includeRawEvidence = false;
    public boolean failOpen = true;
  }
  public static class Rules {
    public String directory = "./rules";
    public List<String> activeGroups = new ArrayList<>(DEFAULT_ACTIVE_RULE_GROUPS);
    public Pull pull = new Pull();
  }
  public static class Pull {
    public boolean enabled = true;
    public String sourceUrl = "https://api.apiwiz.io/itorix/v2/api-security/cli/pull/rule-group";
    public String tenant = "";
  }
  public static class Reports {
    public String directory = "./reports";
    public String fileNamePattern = "scan_{timestamp}_{scanId}.json";
    public boolean redactSecrets = true;
  }
  public static class Webhook {
    public boolean enabled = false;
    public String url = "https://api.apiwiz.io/itorix/v2/api-security/cli/webhook";
    public String tenant = "";
    public int timeoutSeconds = 5;
    public int retries = 3;
    public int endpointReportRetention = 0;
  }

  public static AppConfig defaults() {
    AppConfig c = new AppConfig();
    c.rules.directory = expand(c.rules.directory);
    c.reports.directory = expand(c.reports.directory);
    return c;
  }

  public static AppConfig resolve(String rulesDir, String reportDir, String webhookUrl,
                                  String webhookApiKey, Integer timeout, Integer maxRequests,
                                  Boolean redact, Boolean allowDangerous) throws IOException {
    AppConfig c = defaults();
    Path p = resolveConfigPath();
    if (Files.exists(p)) mergeConfigFile(c, p);
    if (Files.exists(p)) resolveConfigRelativePaths(c, p.getParent());
//    overrideEnv(c);//always take from the adjacent config property file
    if (rulesDir != null && !rulesDir.isBlank()) c.rules.directory = expand(rulesDir);
    if (reportDir != null && !reportDir.isBlank()) c.reports.directory = expand(reportDir);
    if (webhookUrl != null && !webhookUrl.isBlank()) { c.webhook.enabled = true; c.webhook.url = webhookUrl; }
    if (webhookApiKey != null && !webhookApiKey.isBlank()) c.apiwiz.xApiKey = webhookApiKey;
    if (timeout != null) c.scanner.timeoutSeconds = timeout;
    if (maxRequests != null) c.scanner.maxRequestsPerRule = maxRequests;
    if (redact != null) { c.scanner.redactSecrets = redact; c.reports.redactSecrets = redact; }
    if (allowDangerous != null) c.scanner.allowDangerous = allowDangerous;
    applyTenantDefaults(c);
    applyEndpointDefaults(c);
    return c;
  }

  public static Path resolveConfigPath() {
    return Paths.get("config.properties").toAbsolutePath().normalize();
  }

  private static void resolveConfigRelativePaths(AppConfig c, Path configDir) {
    if (configDir == null) return;
    c.rules.directory = resolveConfigPathValue(c.rules.directory, configDir);
    c.reports.directory = resolveConfigPathValue(c.reports.directory, configDir);
  }

  private static String resolveConfigPathValue(String value, Path configDir) {
    if (value == null || value.isBlank() || value.startsWith("~")) return expand(value);
    Path p = Paths.get(expand(value));
    if (p.isAbsolute()) return p.normalize().toString();
    return configDir.resolve(p).normalize().toString();
  }

  public static void initDefault() throws IOException {
    AppConfig c = defaults();
    Files.createDirectories(Paths.get(c.rules.directory));
    Files.createDirectories(Paths.get(c.reports.directory));
    Path props = Paths.get("config.properties").toAbsolutePath().normalize();
    if (!Files.exists(props)) Files.writeString(props, DEFAULT_PROPERTIES);
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
    c.apiwiz.tenant = expandEnv(prop(p, "apiwiz.tenant", c.apiwiz.tenant));
    c.apiwiz.xApiKey = expandEnv(prop(p, "apiwiz.x-apikey", c.apiwiz.xApiKey));
    c.scanner.mode = prop(p, "scanner.mode", c.scanner.mode);
    c.scanner.timeoutSeconds = intVal(p.getProperty("scanner.timeoutSeconds"), c.scanner.timeoutSeconds);
    c.scanner.maxRequestsPerRule = intVal(p.getProperty("scanner.maxRequestsPerRule"), c.scanner.maxRequestsPerRule);
    c.scanner.redactSecrets = boolVal(p.getProperty("scanner.redactSecrets"), c.scanner.redactSecrets);
    c.scanner.allowDangerous = boolVal(p.getProperty("scanner.allowDangerous"), c.scanner.allowDangerous);
    c.application.scan.sourceUrl = expandEnv(prop(p, "application.scan.sourceUrl", c.application.scan.sourceUrl));
    c.openai.enabled = boolVal(p.getProperty("openai.enabled"), c.openai.enabled);
    c.openai.baseUrl = expandEnv(prop(p, "openai.baseUrl", c.openai.baseUrl));
    c.openai.apiKey = expandEnv(prop(p, "openai.apiKey", c.openai.apiKey));
    c.openai.model = expandEnv(prop(p, "openai.model", c.openai.model));
    c.openai.timeoutSeconds = intVal(p.getProperty("openai.timeoutSeconds"), c.openai.timeoutSeconds);
    c.openai.maxFindings = intVal(p.getProperty("openai.maxFindings"), c.openai.maxFindings);
    c.openai.temperature = doubleVal(p.getProperty("openai.temperature"), c.openai.temperature);
    c.openai.includeRawEvidence = boolVal(p.getProperty("openai.includeRawEvidence"), c.openai.includeRawEvidence);
    c.openai.failOpen = boolVal(p.getProperty("openai.failOpen"), c.openai.failOpen);
    c.rules.directory = expand(prop(p, "rules.directory", c.rules.directory));
    String activeGroups = p.getProperty("rules.activeGroups");
    if (activeGroups != null && !activeGroups.isBlank()) {
      c.rules.activeGroups = Arrays.stream(activeGroups.split(",")).map(String::trim).filter(s -> !s.isBlank()).toList();
    }
    c.rules.pull.enabled = boolVal(p.getProperty("rules.pull.enabled"), c.rules.pull.enabled);
    c.rules.pull.sourceUrl = expandEnv(prop(p, "rules.pull.sourceUrl", c.rules.pull.sourceUrl));
    c.rules.pull.tenant = expandEnv(prop(p, "rules.pull.tenant", c.rules.pull.tenant));
    c.reports.directory = expand(prop(p, "reports.directory", c.reports.directory));
    c.reports.fileNamePattern = prop(p, "reports.fileNamePattern", c.reports.fileNamePattern);
    c.reports.redactSecrets = boolVal(p.getProperty("reports.redactSecrets"), c.reports.redactSecrets);
    c.webhook.enabled = boolVal(p.getProperty("webhook.enabled"), c.webhook.enabled);
    c.webhook.url = expandEnv(prop(p, "webhook.url", c.webhook.url));
    c.webhook.tenant = expandEnv(prop(p, "webhook.tenant", c.webhook.tenant));
    c.webhook.timeoutSeconds = intVal(p.getProperty("webhook.timeoutSeconds"), c.webhook.timeoutSeconds);
    c.webhook.retries = intVal(p.getProperty("webhook.retries"), c.webhook.retries);
    c.webhook.endpointReportRetention = intVal(p.getProperty("webhook.endpointReportRetention"), c.webhook.endpointReportRetention);
  }

  @SuppressWarnings("unchecked")
  private static void merge(AppConfig c, Object yaml) {
    if (!(yaml instanceof Map<?,?> root)) return;
    Map<String,Object> apiwiz = (Map<String,Object>) root.get("apiwiz");
    if (apiwiz != null && apiwiz.get("tenant") != null) {
      c.apiwiz.tenant = expandEnv(String.valueOf(apiwiz.get("tenant")));
    }
    if (apiwiz != null && apiwiz.get("x-apikey") != null) {
      c.apiwiz.xApiKey = expandEnv(String.valueOf(apiwiz.get("x-apikey")));
    }
    Map<String,Object> scanner = (Map<String,Object>) root.get("scanner");
    if (scanner != null) {
      c.scanner.timeoutSeconds = intVal(scanner.get("timeoutSeconds"), c.scanner.timeoutSeconds);
      c.scanner.maxRequestsPerRule = intVal(scanner.get("maxRequestsPerRule"), c.scanner.maxRequestsPerRule);
      c.scanner.redactSecrets = boolVal(scanner.get("redactSecrets"), c.scanner.redactSecrets);
      c.scanner.allowDangerous = boolVal(scanner.get("allowDangerous"), c.scanner.allowDangerous);
    }
    Map<String,Object> application = (Map<String,Object>) root.get("application");
    if (application != null && application.get("scan") instanceof Map<?,?> scan) {
      if (scan.get("sourceUrl") != null) c.application.scan.sourceUrl = expandEnv(String.valueOf(scan.get("sourceUrl")));
    }
    Map<String,Object> openai = (Map<String,Object>) root.get("openai");
    if (openai != null) {
      c.openai.enabled = boolVal(openai.get("enabled"), c.openai.enabled);
      if (openai.get("baseUrl") != null) c.openai.baseUrl = expandEnv(String.valueOf(openai.get("baseUrl")));
      if (openai.get("apiKey") != null) c.openai.apiKey = expandEnv(String.valueOf(openai.get("apiKey")));
      if (openai.get("model") != null) c.openai.model = expandEnv(String.valueOf(openai.get("model")));
      c.openai.timeoutSeconds = intVal(openai.get("timeoutSeconds"), c.openai.timeoutSeconds);
      c.openai.maxFindings = intVal(openai.get("maxFindings"), c.openai.maxFindings);
      c.openai.temperature = doubleVal(openai.get("temperature"), c.openai.temperature);
      c.openai.includeRawEvidence = boolVal(openai.get("includeRawEvidence"), c.openai.includeRawEvidence);
      c.openai.failOpen = boolVal(openai.get("failOpen"), c.openai.failOpen);
    }
    Map<String,Object> rules = (Map<String,Object>) root.get("rules");
    if (rules != null) {
      if (rules.get("directory") != null) c.rules.directory = expand(String.valueOf(rules.get("directory")));
      if (rules.get("activeGroups") instanceof List<?> l) c.rules.activeGroups = l.stream().map(String::valueOf).toList();
      if (rules.get("pull") instanceof Map<?,?> pull) {
        c.rules.pull.enabled = boolVal(pull.get("enabled"), c.rules.pull.enabled);
        if (pull.get("sourceUrl") != null) c.rules.pull.sourceUrl = expandEnv(String.valueOf(pull.get("sourceUrl")));
        if (pull.get("tenant") != null) c.rules.pull.tenant = expandEnv(String.valueOf(pull.get("tenant")));
      }
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
      if (webhook.get("tenant") != null) c.webhook.tenant = expandEnv(String.valueOf(webhook.get("tenant")));
      c.webhook.timeoutSeconds = intVal(webhook.get("timeoutSeconds"), c.webhook.timeoutSeconds);
      c.webhook.retries = intVal(webhook.get("retries"), c.webhook.retries);
      c.webhook.endpointReportRetention = intVal(webhook.get("endpointReportRetention"), c.webhook.endpointReportRetention);
    }
  }

  private static void overrideEnv(AppConfig c) {
    if (env("APISEC_TENANT") != null) c.apiwiz.tenant = env("APISEC_TENANT");
    if (env("APISEC_X_APIKEY") != null) c.apiwiz.xApiKey = env("APISEC_X_APIKEY");
    if (env("APISEC_APPLICATION_SCAN_SOURCE_URL") != null) c.application.scan.sourceUrl = env("APISEC_APPLICATION_SCAN_SOURCE_URL");
    if (env("APISEC_OPENAI_ENABLED") != null) c.openai.enabled = Boolean.parseBoolean(env("APISEC_OPENAI_ENABLED"));
    if (env("APISEC_OPENAI_BASE_URL") != null) c.openai.baseUrl = env("APISEC_OPENAI_BASE_URL");
    if (env("OPENAI_API_KEY") != null) c.openai.apiKey = env("OPENAI_API_KEY");
    if (env("APISEC_OPENAI_API_KEY") != null) c.openai.apiKey = env("APISEC_OPENAI_API_KEY");
    if (env("APISEC_OPENAI_MODEL") != null) c.openai.model = env("APISEC_OPENAI_MODEL");
    if (env("APISEC_OPENAI_TIMEOUT_SECONDS") != null) c.openai.timeoutSeconds = Integer.parseInt(env("APISEC_OPENAI_TIMEOUT_SECONDS"));
    if (env("APISEC_OPENAI_MAX_FINDINGS") != null) c.openai.maxFindings = Integer.parseInt(env("APISEC_OPENAI_MAX_FINDINGS"));
    if (env("APISEC_OPENAI_TEMPERATURE") != null) c.openai.temperature = Double.parseDouble(env("APISEC_OPENAI_TEMPERATURE"));
    if (env("APISEC_OPENAI_INCLUDE_RAW_EVIDENCE") != null) c.openai.includeRawEvidence = Boolean.parseBoolean(env("APISEC_OPENAI_INCLUDE_RAW_EVIDENCE"));
    if (env("APISEC_OPENAI_FAIL_OPEN") != null) c.openai.failOpen = Boolean.parseBoolean(env("APISEC_OPENAI_FAIL_OPEN"));
    if (env("APISEC_RULES_DIR") != null) c.rules.directory = expand(env("APISEC_RULES_DIR"));
    if (env("APISEC_RULES_SOURCE_URL") != null) c.rules.pull.sourceUrl = env("APISEC_RULES_SOURCE_URL");
    if (env("APISEC_RULES_TENANT") != null) c.rules.pull.tenant = env("APISEC_RULES_TENANT");
    if (env("APISEC_REPORT_DIR") != null) c.reports.directory = expand(env("APISEC_REPORT_DIR"));
    if (env("APISEC_WEBHOOK_URL") != null) { c.webhook.enabled = true; c.webhook.url = env("APISEC_WEBHOOK_URL"); }
    if (env("APISEC_WEBHOOK_TENANT") != null) c.webhook.tenant = env("APISEC_WEBHOOK_TENANT");
    if (env("APISEC_TIMEOUT_SECONDS") != null) c.scanner.timeoutSeconds = Integer.parseInt(env("APISEC_TIMEOUT_SECONDS"));
    if (env("APISEC_MAX_REQUESTS_PER_RULE") != null) c.scanner.maxRequestsPerRule = Integer.parseInt(env("APISEC_MAX_REQUESTS_PER_RULE"));
    if (env("APISEC_REDACT_SECRETS") != null) c.scanner.redactSecrets = Boolean.parseBoolean(env("APISEC_REDACT_SECRETS"));
  }

  private static void applyTenantDefaults(AppConfig c) {
    if ((c.rules.pull.tenant == null || c.rules.pull.tenant.isBlank()) && c.apiwiz.tenant != null && !c.apiwiz.tenant.isBlank()) {
      c.rules.pull.tenant = c.apiwiz.tenant;
    }
    if ((c.webhook.tenant == null || c.webhook.tenant.isBlank()) && c.apiwiz.tenant != null && !c.apiwiz.tenant.isBlank()) {
      c.webhook.tenant = c.apiwiz.tenant;
    }
  }

  private static void applyEndpointDefaults(AppConfig c) {
    if (c.application.scan.sourceUrl == null || c.application.scan.sourceUrl.isBlank()) {
      c.application.scan.sourceUrl = deriveApplicationScanSource(c.rules.pull.sourceUrl, c.webhook.url);
    }
  }

  private static String deriveApplicationScanSource(String pullUrl, String webhookUrl) {
    String fromPull = replaceSuffix(pullUrl, "/cli/pull/rule-group", "/application");
    if (!fromPull.isBlank()) return fromPull;
    return replaceSuffix(webhookUrl, "/cli/webhook", "/application");
  }

  private static String replaceSuffix(String value, String suffix, String replacement) {
    if (value == null || value.isBlank()) return "";
    int idx = value.indexOf(suffix);
    if (idx < 0) return "";
    return value.substring(0, idx) + replacement;
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
  private static double doubleVal(Object v, double d) { return v == null ? d : Double.parseDouble(String.valueOf(v)); }
  private static boolean boolVal(Object v, boolean d) { return v == null ? d : Boolean.parseBoolean(String.valueOf(v)); }

  public static final String DEFAULT_PROPERTIES = """
apiwiz.tenant=
apiwiz.x-apikey=

scanner.mode=safe
scanner.timeoutSeconds=10
scanner.maxRequestsPerRule=3
scanner.redactSecrets=true
scanner.allowDangerous=false

application.scan.sourceUrl=https://api.apiwiz.io/itorix/v2/api-security/application

openai.enabled=false
openai.baseUrl=https://api.openai.com/v1/chat/completions
openai.apiKey=
openai.model=gpt-4o-mini
openai.timeoutSeconds=20
openai.maxFindings=10
openai.temperature=0.2
openai.includeRawEvidence=false
openai.failOpen=true

rules.directory=./rules
rules.pull.enabled=true
rules.pull.sourceUrl=https://api.apiwiz.io/itorix/v2/api-security/cli/pull/rule-group

reports.directory=./reports
reports.fileNamePattern=scan_{timestamp}_{scanId}.json
reports.redactSecrets=true

webhook.enabled=false
webhook.url=https://api.apiwiz.io/itorix/v2/api-security/cli/webhook
webhook.tenant=
webhook.timeoutSeconds=5
webhook.retries=3
webhook.endpointReportRetention=0
""";

  public static final String DEFAULT_YAML = """
apiwiz:
  tenant: ""
  x-apikey: ""
scanner:
  mode: safe
  timeoutSeconds: 10
  maxRequestsPerRule: 3
  redactSecrets: true
  allowDangerous: false
application:
  scan:
    sourceUrl: "https://api.apiwiz.io/itorix/v2/api-security/application"
openai:
  enabled: false
  baseUrl: "https://api.openai.com/v1/chat/completions"
  apiKey: ""
  model: "gpt-4o-mini"
  timeoutSeconds: 20
  maxFindings: 10
  temperature: 0.2
  includeRawEvidence: false
  failOpen: true
rules:
  directory: "./rules"
  pull:
    enabled: true
    sourceUrl: "https://api.apiwiz.io/itorix/v2/api-security/cli/pull/rule-group"
reports:
  directory: "./reports"
  fileNamePattern: "scan_{timestamp}_{scanId}.json"
  redactSecrets: true
webhook:
  enabled: false
  url: "https://api.apiwiz.io/itorix/v2/api-security/cli/webhook"
  tenant: ""
  timeoutSeconds: 5
  retries: 3
  endpointReportRetention: 0
""";
}
