package com.apisec.cli;

import com.apisec.client.ApplicationScanClient;
import com.apisec.client.ApplicationScanModels.ApplicationScanResources;
import com.apisec.client.ApplicationScanModels.ResourceTarget;
import com.apisec.config.AppConfig;
import com.apisec.engine.ScannerEngine;
import com.apisec.report.ReportModels;
import com.apisec.report.Reporter;
import picocli.CommandLine;
import picocli.CommandLine.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.Callable;

@Command(name = "scan", mixinStandardHelpOptions = true, description = "Run an authorized API security scan from a curl command",
    subcommands = {ScanCommand.CurlCmd.class})
public class ScanCommand implements Callable<Integer> {
  @Parameters(index = "0", arity = "0..1", description = "Application profile id to scan") String applicationId;
  @Option(names="--curl") String curl;
  @Option(names="--curl-file") Path curlFile;
  @Option(names="--application-source") String applicationSource;
  @Option(names="--config") String config;
  @Option(names="--rules-dir") String rulesDir;
  @Option(names="--rules") String rules;
  @Option(names="--report-dir") String reportDir;
  @Option(names="--export", defaultValue="json") String export;
  @Option(names="--webhook") String webhook;
  @Option(names="--webhook-api-key") String webhookApiKey;
  @Option(names="--safe", defaultValue="true") boolean safe;
  @Option(names="--allow-dangerous", defaultValue="false") boolean allowDangerous;
  @Option(names="--max-requests-per-rule") Integer maxRequests;
  @Option(names="--timeout") Integer timeout;
  @Option(names="--json") boolean json;
  @Option(names="--redact-secrets") Boolean redactSecrets;
  @Option(names="--alt-curl") String altCurl;
  @Option(names="--alt-curl-file") Path altCurlFile;
  @Option(names="--show-passed") boolean showPassed;
  @Option(names="--show-skipped") boolean showSkipped;
  @Option(names="--verbose") boolean verbose;
  @Unmatched List<String> inlineCurlArgs = new ArrayList<>();

  @Override public Integer call() throws Exception {
    AppConfig cfg = AppConfig.resolve(config, rulesDir, reportDir, webhook, webhookApiKey, timeout, maxRequests, redactSecrets, allowDangerous);
    String inlineCurl = resolveInlineCurl(applicationId, inlineCurlArgs);
    if (inlineCurl != null) {
      curl = inlineCurl;
      applicationId = null;
    }
    if (applicationId != null && !applicationId.isBlank()) {
      if ((curl != null && !curl.isBlank()) || curlFile != null) throw new ParameterException(new CommandLine(this), "application scan cannot be combined with --curl or --curl-file");
      if (altCurl != null && !altCurl.isBlank()) throw new ParameterException(new CommandLine(this), "application scan does not support --alt-curl");
      if (altCurlFile != null) throw new ParameterException(new CommandLine(this), "application scan does not support --alt-curl-file");
      return runApplicationScan(cfg);
    }
    if ((curl == null || curl.isBlank()) && curlFile == null) throw new ParameterException(new CommandLine(this), "either --curl or --curl-file is required");
    if (curl != null && !curl.isBlank() && curlFile != null) throw new ParameterException(new CommandLine(this), "use only one of --curl or --curl-file");
    if (curlFile != null) curl = Files.readString(curlFile);
    if (altCurlFile != null) altCurl = Files.readString(altCurlFile);
    if (!"json".equals(export)) throw new IllegalArgumentException("unsupported export format " + export);
    ScannerEngine.Result result = runScan(cfg, new ScannerEngine.Options(curl, altCurl, rules), json);
    Reporter.print(result.report(), result.path(), new Reporter.DisplayOptions(json, showPassed, showSkipped, verbose));
    return 0;
  }

  private Integer runApplicationScan(AppConfig cfg) throws Exception {
    if (!"json".equals(export)) throw new IllegalArgumentException("unsupported export format " + export);
    long started = System.currentTimeMillis();
    String applicationRunScanId = "scan_" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    ApplicationScanResources resources = ApplicationScanClient.fetch(cfg, firstNonBlank(applicationSource, cfg.application.scan.sourceUrl), applicationId);
    if (resources == null || resources.resources == null || resources.resources.isEmpty()) {
      System.out.println("No scan resources found for application " + applicationId);
      return 0;
    }
    int attempted = 0;
    int skipped = 0;
    int failures = 0;
    List<Reporter.ApplicationScanEntry> entries = new ArrayList<>();
    boolean liveDashboard = !json && ProgressBar.isInteractive();
    if (!liveDashboard && !json) {
      System.out.printf("Application %s resolved to %d resource(s)%n", firstNonBlank(resources.applicationId, applicationId), resources.resources.size());
    }
    try (ApplicationProgress progress = liveDashboard
        ? new ApplicationScanProgress(resources.resources.size(), firstNonBlank(resources.name, resources.applicationId, applicationId))
        : (!json ? new PlainApplicationScanProgress(resources.resources.size(), firstNonBlank(resources.name, resources.applicationId, applicationId)) : null)) {
      for (ResourceTarget resource : resources.resources) {
        if (resource == null) {
          skipped++;
          if (progress != null) progress.resourceSkipped("resource definition was empty");
          continue;
        }
        String generatedCurl = toApplicationCurl(resource, cfg.apiwiz.xApiKey);
        if (generatedCurl == null) {
          skipped++;
          if (progress != null) progress.resourceSkipped("no concrete target URL could be generated");
          continue;
        }
        attempted++;
        if (progress != null) {
          progress.resourceStarted(
              attempted,
              resources.resources.size(),
              safeMethod(resource.method),
              safeUrl(resource),
              firstNonBlank(resource.operationId));
        } else {
          System.out.printf("[%d/%d] %s %s%n", attempted, resources.resources.size(), safeMethod(resource.method), safeUrl(resource));
        }
        try {
          ScannerEngine.Result result = runScan(cfg, new ScannerEngine.Options(
              generatedCurl,
              null,
              rules,
              toApplicationContext(resources),
              toResourceContext(resource),
              applicationRunScanId
          ), json, progress);
          entries.add(Reporter.applicationEntry(result.report(), result.path()));
          if (progress != null) progress.resourceCompleted(result.report());
        } catch (Exception e) {
          failures++;
          if (progress != null) progress.resourceFailed(e.getMessage());
          entries.add(Reporter.failedApplicationEntry(
              firstNonBlank(resources.applicationId, applicationId),
              firstNonBlank(resources.name, resources.applicationId, applicationId),
              firstNonBlank(resource.resourceId),
              safeMethod(resource.method),
              firstNonBlank(resource.path, safeUrl(resource)),
              firstNonBlank(resource.operationId),
              e.getMessage()));
        }
      }
    }
    if (json) {
      System.out.println("Application scan completed for " + firstNonBlank(resources.applicationId, applicationId));
    } else if (entries.isEmpty()) {
      System.out.printf("Application %s resolved to %d resource(s), but none produced a runnable scan target. Skipped %d resource(s).%n",
          firstNonBlank(resources.applicationId, applicationId),
          resources.resources.size(),
          skipped);
    } else {
      Reporter.printApplicationSummary(
          firstNonBlank(resources.applicationId, applicationId),
          entries,
          resources.resources.size(),
          skipped,
          System.currentTimeMillis() - started);
    }
    return attempted > 0 && failures == 0 ? 0 : 1;
  }

  private static ScannerEngine.Result runScan(AppConfig cfg, ScannerEngine.Options options, boolean json) throws Exception {
    if (json) return ScannerEngine.run(cfg, options);
    if (ProgressBar.isInteractive()) {
      try (ProgressBar progress = new ProgressBar()) {
        return ScannerEngine.run(cfg, options, progress);
      }
    }
    try (PlainProgress progress = new PlainProgress()) {
      return ScannerEngine.run(cfg, options, progress);
    }
  }

  private static ScannerEngine.Result runScan(AppConfig cfg, ScannerEngine.Options options, boolean json, ScannerEngine.ProgressSink progress) throws Exception {
    if (progress != null) return ScannerEngine.run(cfg, options, progress);
    return runScan(cfg, options, json);
  }

  @Command(name = "curl", mixinStandardHelpOptions = true, description = "Scan using curl-style arguments without wrapping them in --curl")
  static class CurlCmd implements Callable<Integer> {
    @Option(names="--config") String config;
    @Option(names="--rules-dir") String rulesDir;
    @Option(names="--rules") String rules;
    @Option(names="--report-dir") String reportDir;
    @Option(names="--export", defaultValue="json") String export;
    @Option(names="--webhook") String webhook;
    @Option(names="--webhook-api-key") String webhookApiKey;
    @Option(names="--safe", defaultValue="true") boolean safe;
    @Option(names="--allow-dangerous", defaultValue="false") boolean allowDangerous;
    @Option(names="--max-requests-per-rule") Integer maxRequests;
    @Option(names="--timeout") Integer timeout;
    @Option(names="--json") boolean json;
    @Option(names="--redact-secrets") Boolean redactSecrets;
    @Option(names="--alt-curl") String altCurl;
    @Option(names="--alt-curl-file") Path altCurlFile;
    @Option(names="--show-passed") boolean showPassed;
    @Option(names="--show-skipped") boolean showSkipped;
    @Option(names="--verbose") boolean verbose;
    @Parameters(index = "0", description = "Target URL") String url;
    @Unmatched List<String> curlArgs = new ArrayList<>();

    @Override public Integer call() throws Exception {
      if (!"json".equals(export)) throw new IllegalArgumentException("unsupported export format " + export);
      if (altCurlFile != null) altCurl = Files.readString(altCurlFile);
      AppConfig cfg = AppConfig.resolve(config, rulesDir, reportDir, webhook, webhookApiKey, timeout, maxRequests, redactSecrets, allowDangerous);
      String curl = toCurlCommand(url, curlArgs);
      ScannerEngine.Result result = runScan(cfg, new ScannerEngine.Options(curl, altCurl, rules), json);
      Reporter.print(result.report(), result.path(), new Reporter.DisplayOptions(json, showPassed, showSkipped, verbose));
      return 0;
    }

    private static String toCurlCommand(String url, List<String> args) {
      List<String> parts = new ArrayList<>();
      parts.add("curl");
      parts.add(url);
      if (args != null) parts.addAll(args);
      return parts.stream().map(CurlCmd::shellQuote).reduce((a, b) -> a + " " + b).orElse("curl");
    }

    private static String shellQuote(String s) {
      if (s == null || s.isEmpty()) return "''";
      if (s.matches("[A-Za-z0-9_./:=+,%@?&-]+")) return s;
      return "'" + s.replace("'", "'\"'\"'") + "'";
    }
  }

  private static ReportModels.Application toApplicationContext(ApplicationScanResources resources) {
    ReportModels.Application application = new ReportModels.Application();
    application.applicationProfileId = resources.applicationProfileId;
    application.applicationId = resources.applicationId;
    application.name = resources.name;
    application.description = resources.description;
    application.swaggerIds = resources.swaggerIds == null ? new ArrayList<>() : new ArrayList<>(resources.swaggerIds);
    return application;
  }

  private static ReportModels.Resource toResourceContext(ResourceTarget resource) {
    ReportModels.Resource out = new ReportModels.Resource();
    out.resourceId = resource.resourceId;
    out.swaggerDocumentId = resource.swaggerDocumentId;
    out.swaggerId = resource.swaggerId;
    out.swaggerName = resource.swaggerName;
    out.revision = resource.revision;
    out.status = resource.status;
    out.baseUrl = resource.baseUrl;
    out.path = resource.path;
    out.method = resource.method;
    out.operationId = resource.operationId;
    out.summary = resource.summary;
    out.tags = resource.tags == null ? new ArrayList<>() : new ArrayList<>(resource.tags);
    out.servers = resource.servers == null ? new ArrayList<>() : new ArrayList<>(resource.servers);
    return out;
  }

  private static String toApplicationCurl(ResourceTarget resource, String apiKey) {
    String url = safeUrl(resource);
    if (url == null || url.isBlank() || url.startsWith("/")) return null;
    List<String> parts = new ArrayList<>();
    parts.add("curl");
    parts.add(url);
    String method = safeMethod(resource.method);
    if (!"GET".equals(method)) {
      parts.add("-X");
      parts.add(method);
    }
    if (apiKey != null && !apiKey.isBlank()) {
      parts.add("-H");
      parts.add("x-apikey: " + apiKey);
    }
    if (Set.of("POST", "PUT", "PATCH").contains(method)) {
      parts.add("-H");
      parts.add("Content-Type: application/json");
      parts.add("--data-raw");
      parts.add("{}");
    }
    return parts.stream().map(CurlCmd::shellQuote).reduce((a, b) -> a + " " + b).orElse("curl");
  }

  private static String safeMethod(String method) {
    return method == null || method.isBlank() ? "GET" : method.toUpperCase(Locale.ROOT);
  }

  private static String safeUrl(ResourceTarget resource) {
    String raw = resource == null ? "" : firstNonBlank(resource.url, resource.baseUrl);
    if (raw.isBlank()) return "";
    return raw.replaceAll("\\{[^/}]+}", "1");
  }

  private static String firstNonBlank(String... values) {
    for (String value : values) {
      if (value != null && !value.isBlank()) return value;
    }
    return "";
  }

  static String resolveInlineCurl(String firstArg, List<String> extraArgs) {
    List<String> tokens = new ArrayList<>();
    if (firstArg != null && !firstArg.isBlank()) tokens.add(firstArg);
    if (extraArgs != null) tokens.addAll(extraArgs);
    if (tokens.isEmpty()) return null;

    boolean explicitCurl = "curl".equals(tokens.get(0));
    boolean curlLike = explicitCurl || looksLikeUrl(tokens.get(0)) || tokens.stream().anyMatch(ScanCommand::isCurlOption);
    if (!curlLike) return null;

    List<String> parts = new ArrayList<>();
    parts.add("curl");
    if (explicitCurl) {
      parts.addAll(tokens.subList(1, tokens.size()));
    } else {
      parts.addAll(tokens);
    }
    return parts.stream().map(CurlCmd::shellQuote).reduce((a, b) -> a + " " + b).orElse("curl");
  }

  private static boolean looksLikeUrl(String value) {
    if (value == null || value.isBlank()) return false;
    String lower = value.toLowerCase(Locale.ROOT);
    return lower.startsWith("http://") || lower.startsWith("https://");
  }

  private static boolean isCurlOption(String value) {
    return value != null && value.startsWith("-");
  }
}
