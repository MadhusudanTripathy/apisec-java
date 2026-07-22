package com.apisec;

import com.apisec.cli.ApiSec;
import com.apisec.config.AppConfig;
import com.apisec.cli.PullCommand;
import com.apisec.curl.CurlParser;
import com.apisec.engine.ScannerEngine;
import com.apisec.model.RequestModel;
import com.apisec.redact.Redactor;
import com.apisec.rules.RuleLoader;
import com.apisec.rules.RuleModels.Group;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;

class JavaCliTest {
  private static final Path BACKUP_RULE_FILE = Path.of("../apisec/rules/owasp-api-2023-backup.json");
  private static final List<String> DEFAULT_ACTIVE_GROUPS = AppConfig.DEFAULT_ACTIVE_RULE_GROUPS;

  @Test void parsesCurlWithApiKey() {
    RequestModel r = CurlParser.parse("curl --location 'https://api.example.com/users/123?api_key=q' -H 'x-apikey: abc' -d '{\"a\":1}'");
    assertEquals("POST", r.method);
    assertEquals("/users/123", r.path);
    assertTrue(r.headers.containsKey("x-apikey"));
    assertEquals("q", r.query.get("api_key").get(0));
  }

  @Test void validatesSharedOwaspRuleGroup() throws Exception {
    Group g = RuleLoader.loadFile(BACKUP_RULE_FILE);
    assertTrue(g.id.matches("[0-9a-f]{24}"));
    assertEquals("owasp-api-2023-backup", RuleLoader.displayKey(g));
    assertEquals(61, g.rules.size());
    assertTrue(g.rules.stream().allMatch(rule -> rule.id != null && rule.id.matches("[0-9a-f]{24}")));
    assertTrue(g.rules.stream().noneMatch(rule -> rule.id.equals(rule.ruleId)));
    int splitTotal = 0;
    for (String groupId : DEFAULT_ACTIVE_GROUPS) {
      Group split = RuleLoader.loadFile(Path.of("../apisec/rules/" + groupId + ".json"));
      assertEquals(groupId, RuleLoader.displayKey(split));
      assertTrue(split.id.matches("[0-9a-f]{24}"));
      splitTotal += split.rules.size();
    }
    assertEquals(61, splitTotal);
  }

  @Test void loadsScannerMetadataFromRuleGroup() throws Exception {
    Path ruleFile = scannerMetadataRuleFile();
    Group g = RuleLoader.loadFile(ruleFile);

    var md = RuleLoader.metadata(g.rules.get(0));
    assertTrue(md.scannerEnabled);
    assertEquals("THREAT_MATCH", md.evaluationMode);
    assertEquals("active", md.scannerMode);
    assertEquals("AUTHZ_BYPASS", md.successCriteria.get("type"));
    assertEquals(1, md.mutations.size());
    assertEquals("ADD_QUERY_PARAM", md.mutations.get(0).operation);
  }

  @Test void activeScannerMetadataUsesDastSuccessCriteria() throws Exception {
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/v1/orders/123", ex -> {
      byte[] body = "{\"status\":\"ok\"}".getBytes(StandardCharsets.UTF_8);
      ex.getResponseHeaders().set("Content-Type", "application/json");
      ex.sendResponseHeaders(200, body.length);
      ex.getResponseBody().write(body);
      ex.close();
    });
    server.setExecutor(Executors.newSingleThreadExecutor());
    server.start();
    try {
      AppConfig cfg = AppConfig.defaults();
      cfg.reports.directory = Files.createTempDirectory("apisec-java-dast-metadata-reports").toString();

      ScannerEngine.Result result = ScannerEngine.run(cfg, new ScannerEngine.Options(
          "curl http://127.0.0.1:" + server.getAddress().getPort() + "/v1/orders/123",
          null,
          scannerMetadataRuleFile().toString()
      ));

      var finding = result.report().findings.stream().filter(f -> "TEST-DAST-001".equals(f.ruleId)).findFirst().orElseThrow();
      assertEquals("FAILED", finding.status);
      assertEquals("AUTHZ_BYPASS", finding.evidence.get("dastCriteria"));
      assertTrue(String.valueOf(finding.evidence.get("reason")).contains("Mutated authorization request"));
    } finally {
      server.stop(0);
    }
  }

  @Test void successCriteriaDefaultsToThreatMatchWhenEvaluationModeIsMissing() throws Exception {
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/v1/orders/123", ex -> {
      byte[] body = "{\"status\":\"ok\"}".getBytes(StandardCharsets.UTF_8);
      ex.getResponseHeaders().set("Content-Type", "application/json");
      ex.sendResponseHeaders(200, body.length);
      ex.getResponseBody().write(body);
      ex.close();
    });
    server.setExecutor(Executors.newSingleThreadExecutor());
    server.start();
    try {
      AppConfig cfg = AppConfig.defaults();
      cfg.reports.directory = Files.createTempDirectory("apisec-java-dast-default-reports").toString();

      ScannerEngine.Result result = ScannerEngine.run(cfg, new ScannerEngine.Options(
          "curl http://127.0.0.1:" + server.getAddress().getPort() + "/v1/orders/123",
          null,
          scannerMetadataRuleFile(false).toString()
      ));

      var finding = result.report().findings.stream().filter(f -> "TEST-DAST-001".equals(f.ruleId)).findFirst().orElseThrow();
      assertEquals("FAILED", finding.status);
      assertEquals("AUTHZ_BYPASS", finding.evidence.get("dastCriteria"));
    } finally {
      server.stop(0);
    }
  }

  @Test void redactsSecrets() {
    assertTrue(Redactor.text("x-apikey: secret").contains("[REDACTED]"));
  }

  private static Path scannerMetadataRuleFile() throws Exception {
    return scannerMetadataRuleFile(true);
  }

  private static Path scannerMetadataRuleFile(boolean includeEvaluationMode) throws Exception {
    Path file = Files.createTempFile("apisec-java-scanner-metadata-rule", ".json");
    String evaluationModeMetadata = includeEvaluationMode ? """
                  {
                    "key": "scanner.evaluationMode",
                    "value": "THREAT_MATCH",
                    "type": "String"
                  },
        """ : "";
    Files.writeString(file, """
        {
          "id": "111111111111111111111111",
          "name": "Scanner Metadata Test Group",
          "description": "Scanner Metadata Test Group",
          "precondition": {
            "type": "Field",
            "expression": "true",
            "placeholders": [],
            "metadata": []
          },
          "rules": [
            {
              "id": "222222222222222222222222",
              "ruleId": "TEST-DAST-001",
              "name": "DAST success criteria test",
              "description": "DAST success criteria test",
              "priority": "HIGH",
              "assertion": {
                "type": "Field",
                "expression": "{0}",
                "placeholders": [
                  {
                    "rule": "REGEX",
                    "key": "request.path",
                    "value": "/admin"
                  }
                ],
                "metadata": [
                  {
                    "key": "owasp",
                    "value": "API5:2023",
                    "type": "String"
                  },
                  {
                    "key": "scanner.enabled",
                    "value": true,
                    "type": "Boolean"
                  },
                  {
                    "key": "scanner.mode",
                    "value": "active",
                    "type": "String"
                  },
                  %s
                  {
                    "key": "scanner.mutations",
                    "value": [
                      {
                        "name": "add-admin-query",
                        "operation": "ADD_QUERY_PARAM",
                        "key": "admin",
                        "value": "true"
                      }
                    ],
                    "type": "Array"
                  },
                  {
                    "key": "scanner.successCriteria",
                    "value": {
                      "type": "AUTHZ_BYPASS",
                      "successStatus": ["2xx"],
                      "bodySimilarityThreshold": 0.85
                    },
                    "type": "Object"
                  }
                ]
              }
            }
          ]
        }
        """.formatted(evaluationModeMetadata));
    return file;
  }

  @Test void loadsPropertiesConfig() throws Exception {
    Path cfg = Files.createTempFile("apisec-java", ".properties");
    Files.writeString(cfg, """
        apiwiz.tenant=acme-team-dev
        apiwiz.x-apikey=test-api-key
        scanner.timeoutSeconds=22
        scanner.maxRequestsPerRule=2
        rules.directory=../apisec/rules
        rules.activeGroups=%s
        application.scan.sourceUrl=http://localhost:8073/v2/api-security/application
        openai.enabled=true
        openai.baseUrl=http://localhost:8073/v1/chat/completions
        openai.apiKey=test-openai-key
        openai.model=gpt-4o-mini
        openai.timeoutSeconds=19
        openai.maxFindings=4
        openai.temperature=0.1
        openai.includeRawEvidence=true
        openai.failOpen=false
        rules.pull.sourceUrl=http://localhost:8073/v2/api-security/cli/pull/rule-group
        reports.directory=reports
        webhook.enabled=true
        webhook.url=http://localhost:8073/v2/api-security/cli/webhook
        webhook.timeoutSeconds=7
        webhook.retries=4
        webhook.endpointReportRetention=12
        """.formatted(String.join(",", DEFAULT_ACTIVE_GROUPS)));
    AppConfig cfgObj = AppConfig.resolve(cfg.toString(), null, null, null, null, null, null, null, null);
    assertEquals(22, cfgObj.scanner.timeoutSeconds);
    assertEquals(2, cfgObj.scanner.maxRequestsPerRule);
    assertEquals(cfg.getParent().resolve("../apisec/rules").normalize().toString(), cfgObj.rules.directory);
    assertEquals(DEFAULT_ACTIVE_GROUPS, cfgObj.rules.activeGroups);
    assertEquals("http://localhost:8073/v2/api-security/application", cfgObj.application.scan.sourceUrl);
    assertTrue(cfgObj.openai.enabled);
    assertEquals("http://localhost:8073/v1/chat/completions", cfgObj.openai.baseUrl);
    assertEquals("test-openai-key", cfgObj.openai.apiKey);
    assertEquals("gpt-4o-mini", cfgObj.openai.model);
    assertEquals(19, cfgObj.openai.timeoutSeconds);
    assertEquals(4, cfgObj.openai.maxFindings);
    assertEquals(0.1d, cfgObj.openai.temperature);
    assertTrue(cfgObj.openai.includeRawEvidence);
    assertFalse(cfgObj.openai.failOpen);
    assertEquals("http://localhost:8073/v2/api-security/cli/pull/rule-group", cfgObj.rules.pull.sourceUrl);
    assertEquals("acme-team-dev", cfgObj.apiwiz.tenant);
    assertEquals("test-api-key", cfgObj.apiwiz.xApiKey);
    assertEquals("acme-team-dev", cfgObj.rules.pull.tenant);
    assertEquals(cfg.getParent().resolve("reports").normalize().toString(), cfgObj.reports.directory);
    assertTrue(cfgObj.webhook.enabled);
    assertEquals("acme-team-dev", cfgObj.webhook.tenant);
    assertEquals(7, cfgObj.webhook.timeoutSeconds);
    assertEquals(4, cfgObj.webhook.retries);
    assertEquals(12, cfgObj.webhook.endpointReportRetention);
  }

  @Test void scannerUsesApiKeyRemovalAndSkipsNoIdBola() throws Exception {
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/v1/permissions", ex -> {
      byte[] body = (ex.getRequestHeaders().containsKey("x-apikey") ? "{\"auth\":true}" : "{\"auth\":false}").getBytes(StandardCharsets.UTF_8);
      ex.sendResponseHeaders(200, body.length);
      ex.getResponseBody().write(body);
      ex.close();
    });
    server.setExecutor(Executors.newSingleThreadExecutor());
    server.start();
    try {
      AppConfig cfg = AppConfig.defaults();
      cfg.reports.directory = java.nio.file.Files.createTempDirectory("apisec-java-reports").toString();
      ScannerEngine.Result result = ScannerEngine.run(cfg, new ScannerEngine.Options(
          "curl http://127.0.0.1:" + server.getAddress().getPort() + "/v1/permissions -H 'x-apikey: test'",
          null,
          BACKUP_RULE_FILE.toString()
      ));
      var auth = result.report().findings.stream().filter(f -> "API2-AUTH-001".equals(f.ruleId)).findFirst().orElseThrow();
      assertEquals("FAILED", auth.status);
      assertEquals("remove-x-apikey-header", auth.evidence.get("mutation"));
      var location = (java.util.Map<String, Object>) auth.evidence.get("location");
      assertEquals("header", location.get("requestPart"));
      assertEquals("x-apikey", location.get("field"));
      assertEquals("REMOVE_HEADER", location.get("operation"));
      assertEquals("remove-x-apikey-header", location.get("mutationName"));
      assertTrue(result.report().summary.skipped > 0);
      assertFalse(result.report().baseline.isEmpty());
      assertTrue(auth.evidence.containsKey("mutationExchange"));
      assertTrue(result.report().findings.stream().noneMatch(f -> "PASSED".equals(f.status) || "SKIPPED".equals(f.status)));
      assertFalse(result.report().aiUsed);
      assertEquals("DISABLED", result.report().aiStatus);
    } finally {
      server.stop(0);
    }
  }

  @SuppressWarnings("unchecked")
  @Test void reportCanIncludeUnredactedFullExchangeDataWhenConfigured() throws Exception {
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    String largeBody = "{\"token\":\"secret-value\",\"data\":\"" + "x".repeat(5000) + "\"}";
    server.createContext("/v1/permissions", ex -> {
      byte[] body = largeBody.getBytes(StandardCharsets.UTF_8);
      ex.getResponseHeaders().set("Content-Type", "application/json");
      ex.sendResponseHeaders(200, body.length);
      ex.getResponseBody().write(body);
      ex.close();
    });
    server.setExecutor(Executors.newSingleThreadExecutor());
    server.start();
    try {
      AppConfig cfg = AppConfig.defaults();
      cfg.reports.directory = Files.createTempDirectory("apisec-java-raw-reports").toString();
      cfg.reports.redactSecrets = false;
      cfg.scanner.redactSecrets = false;

      ScannerEngine.Result result = ScannerEngine.run(cfg, new ScannerEngine.Options(
          "curl http://127.0.0.1:" + server.getAddress().getPort() + "/v1/permissions -H 'x-apikey: secret-token'",
          null,
          BACKUP_RULE_FILE.toString()
      ));

      var baselineRequest = (java.util.Map<String, Object>) result.report().baseline.get("request");
      var baselineHeaders = (java.util.Map<String, java.util.List<String>>) baselineRequest.get("headers");
      assertEquals("secret-token", baselineHeaders.get("x-apikey").get(0));

      var auth = result.report().findings.stream().filter(f -> "API2-AUTH-001".equals(f.ruleId)).findFirst().orElseThrow();
      assertEquals("CRITICAL", result.report().maxSeverity);
      assertEquals(result.report().summary.failed, result.report().totalFindings);
      var exchange = (java.util.Map<String, Object>) auth.evidence.get("mutationExchange");
      var response = (java.util.Map<String, Object>) exchange.get("response");
      String body = String.valueOf(response.get("body"));
      assertTrue(body.contains("secret-value"));
      assertTrue(body.contains("x".repeat(5000)));
      assertFalse(body.contains("[REDACTED]"));
      assertFalse(body.contains("[truncated]"));
      assertTrue(result.report().findings.stream().allMatch(f -> "FAILED".equals(f.status)));
    } finally {
      server.stop(0);
    }
  }

  @SuppressWarnings("unchecked")
  @Test void baselineRequestSnapshotIncludesStructuredFormMetadata() throws Exception {
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/v1/form", ex -> {
      byte[] requestBody = ex.getRequestBody().readAllBytes();
      assertEquals("a=1&b=two+words", new String(requestBody, StandardCharsets.UTF_8));
      byte[] body = "{\"ok\":true}".getBytes(StandardCharsets.UTF_8);
      ex.getResponseHeaders().set("Content-Type", "application/json");
      ex.sendResponseHeaders(200, body.length);
      ex.getResponseBody().write(body);
      ex.close();
    });
    server.setExecutor(Executors.newSingleThreadExecutor());
    server.start();
    try {
      AppConfig cfg = AppConfig.defaults();
      cfg.reports.directory = Files.createTempDirectory("apisec-java-form-reports").toString();

      ScannerEngine.Result result = ScannerEngine.run(cfg, new ScannerEngine.Options(
          "curl http://127.0.0.1:" + server.getAddress().getPort() + "/v1/form " +
              "--header 'Content-Type: application/x-www-form-urlencoded' " +
              "--data-urlencode 'a=1' --data-urlencode 'b=two words'",
          null,
          BACKUP_RULE_FILE.toString()
      ));

      var baselineRequest = (java.util.Map<String, Object>) result.report().baseline.get("request");
      assertEquals("a=1&b=two+words", baselineRequest.get("body"));
      var form = (java.util.Map<String, Object>) baselineRequest.get("form");
      assertEquals("application/x-www-form-urlencoded", form.get("encoding"));
      var fields = (java.util.List<java.util.Map<String, Object>>) form.get("fields");
      assertEquals(2, fields.size());
      assertEquals("a", fields.get(0).get("name"));
      assertEquals("1", fields.get(0).get("value"));
      assertEquals("b", fields.get(1).get("name"));
      assertEquals("two words", fields.get(1).get("value"));
    } finally {
      server.stop(0);
    }
  }

  @Test void paymentEndpointUsesContextAwareApplicabilityAndConfidence() throws Exception {
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/v1/payments/transfer", ex -> {
      byte[] body = """
          {"transactionId":"tx-123","status":"SUCCESS","amount":"10","currency":"PHP"}
          """.getBytes(StandardCharsets.UTF_8);
      ex.getResponseHeaders().set("Content-Type", "application/json");
      ex.sendResponseHeaders(200, body.length);
      ex.getResponseBody().write(body);
      ex.close();
    });
    server.setExecutor(Executors.newSingleThreadExecutor());
    server.start();
    try {
      AppConfig cfg = AppConfig.defaults();
      cfg.reports.directory = Files.createTempDirectory("apisec-java-payment-reports").toString();

      ScannerEngine.Result result = ScannerEngine.run(cfg, new ScannerEngine.Options(
          "curl http://127.0.0.1:" + server.getAddress().getPort() + "/v1/payments/transfer -H 'Content-Type: application/json' -d '{\"amount\":\"10\",\"currency\":\"PHP\"}'",
          null,
          BACKUP_RULE_FILE.toString()
      ));

      assertTrue(result.report().findings.stream().noneMatch(f -> f.ruleId.equals("API4-RESOURCE-001")));
      assertTrue(result.report().findings.stream().noneMatch(f -> f.ruleId.equals("API4-RESOURCE-002")));
      assertTrue(result.report().findings.stream().noneMatch(f -> f.ruleId.equals("API4-RESOURCE-003")));
      assertTrue(result.report().findings.stream().noneMatch(f -> f.ruleId.equals("API6-BUSINESS-002")));
      assertTrue(result.report().findings.stream().noneMatch(f -> f.ruleId.startsWith("API7-SSRF")));

      var idempotency = result.report().findings.stream().filter(f -> f.ruleId.equals("API6-BUSINESS-003")).findFirst().orElseThrow();
      assertEquals("POTENTIAL", idempotency.certainty);
      assertTrue(String.valueOf(idempotency.evidence.get("reason")).contains("Payment/transfer endpoint"));

      var massAssignment = result.report().findings.stream().filter(f -> f.ruleId.equals("API3-BOPLA-003")).findFirst().orElseThrow();
      assertEquals("POTENTIAL", massAssignment.certainty);
      assertNotEquals("NONE", massAssignment.confidence);
      assertTrue(String.valueOf(massAssignment.evidence.get("reason")).contains("unexpected field mutation"));
      assertTrue(massAssignment.evidence.containsKey("responseSemantics"));
    } finally {
      server.stop(0);
    }
  }

  @SuppressWarnings("unchecked")
  @Test void passiveFindingsAlsoIncludeEvidenceLocation() throws Exception {
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/v1/info", ex -> {
      byte[] body = "{\"ok\":true}".getBytes(StandardCharsets.UTF_8);
      ex.getResponseHeaders().set("Content-Type", "application/json");
      ex.getResponseHeaders().set("Server", "apisec-test/1.0");
      ex.sendResponseHeaders(200, body.length);
      ex.getResponseBody().write(body);
      ex.close();
    });
    server.setExecutor(Executors.newSingleThreadExecutor());
    server.start();
    try {
      AppConfig cfg = AppConfig.defaults();
      cfg.reports.directory = Files.createTempDirectory("apisec-java-passive-location-reports").toString();

      ScannerEngine.Result result = ScannerEngine.run(cfg, new ScannerEngine.Options(
          "curl http://127.0.0.1:" + server.getAddress().getPort() + "/v1/info",
          null,
          BACKUP_RULE_FILE.toString()
      ));

      var finding = result.report().findings.stream().filter(f -> "API8-CONFIG-004".equals(f.ruleId)).findFirst().orElseThrow();
      assertEquals("FAILED", finding.status);
      var location = (java.util.Map<String, Object>) finding.evidence.get("location");
      assertNotNull(location);
      assertEquals("response-header", location.get("requestPart"));
      assertEquals("Server", location.get("field"));
      assertEquals("PRESENT_RESPONSE_HEADER", location.get("operation"));
      assertEquals("baseline-passive-check", location.get("mutationName"));
    } finally {
      server.stop(0);
    }
  }

  @Test void scanCurlSubcommandAcceptsCurlStyleArguments() throws Exception {
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/itorix/v1/permissions", ex -> {
      byte[] body = (ex.getRequestHeaders().containsKey("x-apikey") ? "{\"ok\":true}" : "{\"ok\":false}").getBytes(StandardCharsets.UTF_8);
      ex.getResponseHeaders().set("Content-Type", "application/json");
      ex.sendResponseHeaders(200, body.length);
      ex.getResponseBody().write(body);
      ex.close();
    });
    server.setExecutor(Executors.newSingleThreadExecutor());
    server.start();
    try {
      Path reportsDir = Files.createTempDirectory("apisec-java-scan-curl-reports");
      int code = new CommandLine(new ApiSec()).execute(
          "scan", "curl",
          "--rules", BACKUP_RULE_FILE.toString(),
          "--report-dir", reportsDir.toString(),
          "http://127.0.0.1:" + server.getAddress().getPort() + "/itorix/v1/permissions",
          "-H", "Content-Type: application/json",
          "-H", "x-apikey: test",
          "--data-raw", "{\"workspaceId\":\"stage-data\"}"
      );

      assertEquals(0, code);
      assertTrue(Files.list(reportsDir).anyMatch(p -> p.getFileName().toString().endsWith(".json")));
    } finally {
      server.stop(0);
    }
  }

  @Test void pullUsesConfiguredSourceAndTenantHeader() throws Exception {
    ObjectMapper mapper = new ObjectMapper();
    ObjectNode groupNode = (ObjectNode) mapper.readTree(Files.readString(BACKUP_RULE_FILE));
    String groupJson = mapper.writeValueAsString(groupNode);
    AtomicReference<String> observedTenant = new AtomicReference<>();
    AtomicReference<String> observedApiKey = new AtomicReference<>();
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/v2/api-security/cli/pull/rule-group", ex -> {
      observedTenant.set(ex.getRequestHeaders().getFirst("tenant"));
      observedApiKey.set(ex.getRequestHeaders().getFirst("x-apikey"));
      byte[] body = ("{\"ruleGroups\":[" + groupJson + "]}").getBytes(StandardCharsets.UTF_8);
      ex.getResponseHeaders().set("Content-Type", "application/json");
      ex.sendResponseHeaders(200, body.length);
      ex.getResponseBody().write(body);
      ex.close();
    });
    server.setExecutor(Executors.newSingleThreadExecutor());
    server.start();
    try {
      Path rulesDir = Files.createTempDirectory("apisec-java-pulled-rules");
      Path cfg = Files.createTempFile("apisec-java-pull", ".properties");
      Files.writeString(cfg, """
          apiwiz.tenant=acme-team-dev
          apiwiz.x-apikey=test-api-key
          rules.directory=%s
          rules.pull.sourceUrl=http://127.0.0.1:%d/v2/api-security/cli/pull/rule-group
          """.formatted(rulesDir, server.getAddress().getPort()));

      int code = new CommandLine(new PullCommand()).execute("--config", cfg.toString());

      assertEquals(0, code);
      assertEquals("acme-team-dev", observedTenant.get());
      assertEquals("test-api-key", observedApiKey.get());
      assertTrue(Files.exists(rulesDir.resolve("owasp-api-2023-backup.json")));
      Group pulled = RuleLoader.loadFile(rulesDir.resolve("owasp-api-2023-backup.json"));
      assertTrue(pulled.id.matches("[0-9a-f]{24}"));
      assertTrue(pulled.rules.get(0).id.matches("[0-9a-f]{24}"));
      assertNotEquals(pulled.rules.get(0).ruleId, pulled.rules.get(0).id);
    } finally {
      server.stop(0);
    }
  }

  @Test void pullOverwriteReplacesExistingRuleGroupFile() throws Exception {
    ObjectMapper mapper = new ObjectMapper();
    ObjectNode groupNode = (ObjectNode) mapper.readTree(Files.readString(BACKUP_RULE_FILE));
    String groupJson = mapper.writeValueAsString(groupNode);
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/v2/api-security/cli/pull/rule-group", ex -> {
      byte[] body = ("{\"ruleGroups\":[" + groupJson + "]}").getBytes(StandardCharsets.UTF_8);
      ex.getResponseHeaders().set("Content-Type", "application/json");
      ex.sendResponseHeaders(200, body.length);
      ex.getResponseBody().write(body);
      ex.close();
    });
    server.setExecutor(Executors.newSingleThreadExecutor());
    server.start();
    try {
      Path rulesDir = Files.createTempDirectory("apisec-java-pulled-rules-overwrite");
      Path existing = rulesDir.resolve("owasp-api-2023-backup.json");
      Files.writeString(existing, "{\"stale\":true}");
      Path cfg = Files.createTempFile("apisec-java-pull-overwrite", ".properties");
      Files.writeString(cfg, """
          rules.directory=%s
          rules.pull.sourceUrl=http://127.0.0.1:%d/v2/api-security/cli/pull/rule-group
          """.formatted(rulesDir, server.getAddress().getPort()));

      int code = new CommandLine(new PullCommand()).execute("--config", cfg.toString(), "--overwrite");

      assertEquals(0, code);
      String rewritten = Files.readString(existing);
      assertFalse(rewritten.contains("\"stale\":true"));
      Group pulled = RuleLoader.loadFile(existing);
      assertTrue(pulled.id.matches("[0-9a-f]{24}"));
      assertEquals("owasp-api-2023-backup", RuleLoader.displayKey(pulled));
    } finally {
      server.stop(0);
    }
  }

  @Test void scanFallsBackToAllLocalRuleGroupsWhenActiveGroupFilterMatchesNothing() throws Exception {
    Path rulesDir = Files.createTempDirectory("apisec-java-rules-fallback");
    Path sourceRule = BACKUP_RULE_FILE;
    ObjectMapper mapper = new ObjectMapper();
    ObjectNode groupNode = (ObjectNode) mapper.readTree(Files.readString(sourceRule));
    groupNode.put("id", "6a211ab00afd106e71e7f7f3");
    Files.writeString(rulesDir.resolve("6a211ab00afd106e71e7f7f3.json"), mapper.writerWithDefaultPrettyPrinter().writeValueAsString(groupNode));

    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/v1/permissions", ex -> {
      byte[] body = (ex.getRequestHeaders().containsKey("x-apikey") ? "{\"ok\":true}" : "{\"ok\":false}").getBytes(StandardCharsets.UTF_8);
      ex.getResponseHeaders().set("Content-Type", "application/json");
      ex.sendResponseHeaders(200, body.length);
      ex.getResponseBody().write(body);
      ex.close();
    });
    server.setExecutor(Executors.newSingleThreadExecutor());
    server.start();
    try {
      AppConfig cfg = AppConfig.defaults();
      cfg.rules.directory = rulesDir.toString();
      cfg.rules.activeGroups = DEFAULT_ACTIVE_GROUPS;
      cfg.reports.directory = Files.createTempDirectory("apisec-java-rules-fallback-reports").toString();

      ScannerEngine.Result result = ScannerEngine.run(cfg, new ScannerEngine.Options(
          "curl http://127.0.0.1:" + server.getAddress().getPort() + "/v1/permissions -H 'x-apikey: test'",
          null,
          null
      ));

      assertTrue(result.report().summary.totalRules > 0);
    } finally {
      server.stop(0);
    }
  }

  @Test void scanApplicationFetchesCliResourcesAndWritesContextualReports() throws Exception {
    AtomicReference<String> observedTenant = new AtomicReference<>();
    AtomicReference<String> observedApiKey = new AtomicReference<>();
    AtomicReference<String> observedXTenant = new AtomicReference<>();
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/v2/api-security/application/app-123/resources", ex -> {
      observedTenant.set(ex.getRequestHeaders().getFirst("tenant"));
      observedApiKey.set(ex.getRequestHeaders().getFirst("x-apikey"));
      observedXTenant.set(ex.getRequestHeaders().getFirst("x-tenant"));
      byte[] body = """
          {
            "applicationProfileId":"profile-1",
            "applicationId":"app-123",
            "name":"Payments App",
            "description":"Application with multiple swagger resources",
            "swaggerIds":["swagger-payments","swagger-banks"],
            "resources":[
              {
                "swaggerDocumentId":"doc-1",
                "swaggerId":"swagger-payments",
                "swaggerName":"Payments Swagger",
                "revision":3,
                "status":"Published",
                "baseUrl":"http://127.0.0.1:%d",
                "url":"http://127.0.0.1:%d/v1/payments/{paymentId}",
                "path":"/v1/payments/{paymentId}",
                "method":"GET",
                "operationId":"getPayment"
              }
            ]
          }
          """.formatted(server.getAddress().getPort(), server.getAddress().getPort()).getBytes(StandardCharsets.UTF_8);
      ex.getResponseHeaders().set("Content-Type", "application/json");
      ex.sendResponseHeaders(200, body.length);
      ex.getResponseBody().write(body);
      ex.close();
    });
    server.createContext("/v1/payments/1", ex -> {
      byte[] body = "{\"status\":\"SUCCESS\",\"paymentId\":\"1\"}".getBytes(StandardCharsets.UTF_8);
      ex.getResponseHeaders().set("Content-Type", "application/json");
      ex.sendResponseHeaders(200, body.length);
      ex.getResponseBody().write(body);
      ex.close();
    });
    server.setExecutor(Executors.newCachedThreadPool());
    server.start();
    try {
      Path reportsDir = Files.createTempDirectory("apisec-java-application-scan-reports");
      Path cfg = Files.createTempFile("apisec-java-application-scan", ".properties");
      Files.writeString(cfg, """
          apiwiz.tenant=acme-team-dev
          apiwiz.x-apikey=test-api-key
          application.scan.sourceUrl=http://127.0.0.1:%d/v2/api-security/application
          rules.directory=../apisec/rules
          reports.directory=%s
          webhook.enabled=false
          """.formatted(server.getAddress().getPort(), reportsDir));

      int code = new CommandLine(new ApiSec()).execute("scan", "app-123", "--config", cfg.toString(), "--rules", BACKUP_RULE_FILE.toString());

      assertEquals(0, code);
      assertNull(observedTenant.get());
      assertEquals("test-api-key", observedApiKey.get());
      assertEquals("acme-team-dev", observedXTenant.get());
      Path reportPath = Files.list(reportsDir).filter(p -> p.getFileName().toString().endsWith(".json")).findFirst().orElseThrow();
      ObjectNode report = (ObjectNode) new ObjectMapper().readTree(Files.readString(reportPath));
      assertEquals("app-123", report.path("application").path("applicationId").asText());
      assertEquals("swagger-payments", report.path("resource").path("swaggerId").asText());
      assertEquals("GET", report.path("target").path("method").asText());
      assertTrue(report.path("target").path("url").asText().endsWith("/v1/payments/1"));
    } finally {
      server.stop(0);
    }
  }

  @Test void aiSummaryIsAttachedBeforeReportWriteAndSensitiveBodiesAreNotSentWhenDisabled() throws Exception {
    AtomicReference<String> observedAuthorization = new AtomicReference<>();
    AtomicReference<String> observedOpenAiBody = new AtomicReference<>();
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    String sensitiveBody = "{\"token\":\"secret-value\",\"paymentId\":\"txn-123\"}";
    server.createContext("/v1/permissions", ex -> {
      byte[] body = sensitiveBody.getBytes(StandardCharsets.UTF_8);
      ex.getResponseHeaders().set("Content-Type", "application/json");
      ex.sendResponseHeaders(200, body.length);
      ex.getResponseBody().write(body);
      ex.close();
    });
    server.createContext("/v1/chat/completions", ex -> {
      observedAuthorization.set(ex.getRequestHeaders().getFirst("Authorization"));
      observedOpenAiBody.set(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
      byte[] body = """
          {
            "id":"chatcmpl-test",
            "object":"chat.completion",
            "model":"gpt-4o-mini",
            "choices":[
              {
                "index":0,
                "message":{
                  "role":"assistant",
                  "content":"{\\"overview\\":\\"AI generated overview\\",\\"findings\\":[{\\"ruleId\\":\\"API2-AUTH-001\\",\\"whyDangerous\\":\\"AI danger\\",\\"remediation\\":\\"AI remediation\\",\\"businessImpact\\":\\"AI business impact\\",\\"evidenceTitle\\":\\"AI evidence title\\",\\"evidenceSummary\\":\\"AI evidence summary\\"}]}"
                },
                "finish_reason":"stop"
              }
            ]
          }
          """.getBytes(StandardCharsets.UTF_8);
      ex.getResponseHeaders().set("Content-Type", "application/json");
      ex.sendResponseHeaders(200, body.length);
      ex.getResponseBody().write(body);
      ex.close();
    });
    server.setExecutor(Executors.newCachedThreadPool());
    server.start();
    try {
      AppConfig cfg = AppConfig.defaults();
      cfg.reports.directory = Files.createTempDirectory("apisec-java-ai-summary-reports").toString();
      cfg.openai.enabled = true;
      cfg.openai.apiKey = "test-openai-key";
      cfg.openai.baseUrl = "http://127.0.0.1:" + server.getAddress().getPort() + "/v1/chat/completions";
      cfg.openai.includeRawEvidence = false;

      ScannerEngine.Result result = ScannerEngine.run(cfg, new ScannerEngine.Options(
          "curl http://127.0.0.1:" + server.getAddress().getPort() + "/v1/permissions -H 'x-apikey: secret-token'",
          null,
          BACKUP_RULE_FILE.toString()
      ));

      assertTrue(result.report().aiUsed);
      assertEquals("USED", result.report().aiStatus);
      assertNotNull(result.report().aiSummary);
      assertEquals("AI generated overview", result.report().aiSummary.overview);
      var aiFinding = result.report().findings.stream().filter(f -> "API2-AUTH-001".equals(f.ruleId)).findFirst().orElseThrow();
      assertNotNull(aiFinding.ai);
      assertEquals("AI evidence title", aiFinding.ai.evidenceTitle);
      assertEquals("AI evidence summary", aiFinding.ai.evidenceSummary);
      assertEquals("Bearer test-openai-key", observedAuthorization.get());
      assertNotNull(observedOpenAiBody.get());
      assertFalse(observedOpenAiBody.get().contains("secret-token"));
      assertFalse(observedOpenAiBody.get().contains("secret-value"));

      ObjectNode report = (ObjectNode) new ObjectMapper().readTree(Files.readString(Path.of(result.path())));
      assertTrue(report.path("aiUsed").asBoolean());
      assertEquals("USED", report.path("aiStatus").asText());
      assertEquals("CRITICAL", report.path("maxSeverity").asText());
      assertEquals(report.path("summary").path("failed").asInt(), report.path("totalFindings").asInt());
      assertEquals("AI generated overview", report.path("aiSummary").path("overview").asText());
      var reportFinding = java.util.stream.StreamSupport.stream(report.path("findings").spliterator(), false)
          .filter(node -> "API2-AUTH-001".equals(node.path("ruleId").asText()))
          .findFirst()
          .orElseThrow();
      assertEquals("AI evidence summary", reportFinding.path("ai").path("evidenceSummary").asText());
    } finally {
      server.stop(0);
    }
  }

  @Test void aiSummaryFailureFallsBackToNormalReportWhenFailOpenIsEnabled() throws Exception {
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/v1/permissions", ex -> {
      byte[] body = "{\"auth\":true}".getBytes(StandardCharsets.UTF_8);
      ex.getResponseHeaders().set("Content-Type", "application/json");
      ex.sendResponseHeaders(200, body.length);
      ex.getResponseBody().write(body);
      ex.close();
    });
    server.createContext("/v1/chat/completions", ex -> {
      byte[] body = "{\"choices\":[{\"message\":{\"content\":\"not-json\"}}]}".getBytes(StandardCharsets.UTF_8);
      ex.getResponseHeaders().set("Content-Type", "application/json");
      ex.sendResponseHeaders(200, body.length);
      ex.getResponseBody().write(body);
      ex.close();
    });
    server.setExecutor(Executors.newCachedThreadPool());
    server.start();
    try {
      AppConfig cfg = AppConfig.defaults();
      cfg.reports.directory = Files.createTempDirectory("apisec-java-ai-failopen-reports").toString();
      cfg.openai.enabled = true;
      cfg.openai.apiKey = "test-openai-key";
      cfg.openai.baseUrl = "http://127.0.0.1:" + server.getAddress().getPort() + "/v1/chat/completions";
      cfg.openai.failOpen = true;

      ScannerEngine.Result result = ScannerEngine.run(cfg, new ScannerEngine.Options(
          "curl http://127.0.0.1:" + server.getAddress().getPort() + "/v1/permissions -H 'x-apikey: test'",
          null,
          BACKUP_RULE_FILE.toString()
      ));

      assertFalse(result.report().aiUsed);
      assertEquals("FAILED", result.report().aiStatus);
      assertNotNull(result.report().aiError);
      assertFalse(result.report().findings.isEmpty());
    } finally {
      server.stop(0);
    }
  }

  @Test void aiSummaryHttpFailureIncludesResponseBodyInError() throws Exception {
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/v1/permissions", ex -> {
      byte[] body = "{\"auth\":true}".getBytes(StandardCharsets.UTF_8);
      ex.getResponseHeaders().set("Content-Type", "application/json");
      ex.sendResponseHeaders(200, body.length);
      ex.getResponseBody().write(body);
      ex.close();
    });
    server.createContext("/v1/chat/completions", ex -> {
      byte[] body = """
          {"error":{"message":"Incorrect API key provided","type":"invalid_request_error"}}
          """.getBytes(StandardCharsets.UTF_8);
      ex.getResponseHeaders().set("Content-Type", "application/json");
      ex.sendResponseHeaders(401, body.length);
      ex.getResponseBody().write(body);
      ex.close();
    });
    server.setExecutor(Executors.newCachedThreadPool());
    server.start();
    try {
      AppConfig cfg = AppConfig.defaults();
      cfg.reports.directory = Files.createTempDirectory("apisec-java-ai-httpfail-reports").toString();
      cfg.openai.enabled = true;
      cfg.openai.apiKey = "test-openai-key";
      cfg.openai.baseUrl = "http://127.0.0.1:" + server.getAddress().getPort() + "/v1/chat/completions";
      cfg.openai.failOpen = true;

      ScannerEngine.Result result = ScannerEngine.run(cfg, new ScannerEngine.Options(
          "curl http://127.0.0.1:" + server.getAddress().getPort() + "/v1/permissions -H 'x-apikey: test'",
          null,
          BACKUP_RULE_FILE.toString()
      ));

      assertFalse(result.report().aiUsed);
      assertEquals("FAILED", result.report().aiStatus);
      assertNotNull(result.report().aiError);
      assertTrue(result.report().aiError.contains("401"));
      assertTrue(result.report().aiError.contains("Incorrect API key provided"));
    } finally {
      server.stop(0);
    }
  }
}
