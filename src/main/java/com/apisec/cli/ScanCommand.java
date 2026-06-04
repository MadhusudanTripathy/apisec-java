package com.apisec.cli;

import com.apisec.config.AppConfig;
import com.apisec.engine.ScannerEngine;
import com.apisec.report.Reporter;
import picocli.CommandLine;
import picocli.CommandLine.*;
import java.nio.file.*;
import java.util.concurrent.Callable;

@Command(name = "scan", mixinStandardHelpOptions = true, description = "Run an authorized API security scan from a curl command")
public class ScanCommand implements Callable<Integer> {
  @Option(names="--curl") String curl;
  @Option(names="--curl-file") Path curlFile;
  @Option(names="--config") String config;
  @Option(names="--rules-dir") String rulesDir;
  @Option(names="--rules") String rules;
  @Option(names="--report-dir") String reportDir;
  @Option(names="--export", defaultValue="json") String export;
  @Option(names="--webhook") String webhook;
  @Option(names="--webhook-secret") String webhookSecret;
  @Option(names="--webhook-tenant") String webhookTenant;
  @Option(names="--safe", defaultValue="true") boolean safe;
  @Option(names="--allow-dangerous", defaultValue="false") boolean allowDangerous;
  @Option(names="--max-requests-per-rule") Integer maxRequests;
  @Option(names="--timeout") Integer timeout;
  @Option(names="--json") boolean json;
  @Option(names="--redact-secrets", defaultValue="true") boolean redactSecrets;
  @Option(names="--alt-curl") String altCurl;
  @Option(names="--alt-curl-file") Path altCurlFile;
  @Option(names="--show-passed") boolean showPassed;
  @Option(names="--show-skipped") boolean showSkipped;
  @Option(names="--verbose") boolean verbose;

  @Override public Integer call() throws Exception {
    if ((curl == null || curl.isBlank()) && curlFile == null) throw new ParameterException(new CommandLine(this), "either --curl or --curl-file is required");
    if (curl != null && !curl.isBlank() && curlFile != null) throw new ParameterException(new CommandLine(this), "use only one of --curl or --curl-file");
    if (curlFile != null) curl = Files.readString(curlFile);
    if (altCurlFile != null) altCurl = Files.readString(altCurlFile);
    if (!"json".equals(export)) throw new IllegalArgumentException("unsupported export format " + export);
    AppConfig cfg = AppConfig.resolve(config, rulesDir, reportDir, webhook, webhookSecret, webhookTenant, timeout, maxRequests, redactSecrets, allowDangerous);
    ScannerEngine.Result result = ScannerEngine.run(cfg, new ScannerEngine.Options(curl, altCurl, rules));
    Reporter.print(result.report(), result.path(), new Reporter.DisplayOptions(json, showPassed, showSkipped, verbose));
    return 0;
  }
}
