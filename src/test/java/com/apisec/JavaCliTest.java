package com.apisec;

import com.apisec.config.AppConfig;
import com.apisec.curl.CurlParser;
import com.apisec.engine.ScannerEngine;
import com.apisec.model.RequestModel;
import com.apisec.redact.Redactor;
import com.apisec.rules.RuleLoader;
import com.apisec.rules.RuleModels.Group;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Executors;
import static org.junit.jupiter.api.Assertions.*;

class JavaCliTest {
  @Test void parsesCurlWithApiKey() {
    RequestModel r = CurlParser.parse("curl --location 'https://api.example.com/users/123?api_key=q' -H 'x-apikey: abc' -d '{\"a\":1}'");
    assertEquals("POST", r.method);
    assertEquals("/users/123", r.path);
    assertTrue(r.headers.containsKey("x-apikey"));
    assertEquals("q", r.query.get("api_key").get(0));
  }

  @Test void validatesSharedOwaspRuleGroup() throws Exception {
    Group g = RuleLoader.loadFile(Path.of("../rules/owasp-api-2023.json"));
    assertEquals("owasp-api-2023", g.id);
    assertEquals(61, g.rules.size());
  }

  @Test void redactsSecrets() {
    assertTrue(Redactor.text("x-apikey: secret").contains("[REDACTED]"));
  }

  @Test void loadsPropertiesConfig() throws Exception {
    Path cfg = Files.createTempFile("apisec-java", ".properties");
    Files.writeString(cfg, """
        scanner.timeoutSeconds=22
        scanner.maxRequestsPerRule=2
        rules.directory=../rules
        rules.activeGroups=owasp-api-2023
        reports.directory=~/apisec-test-reports
        webhook.enabled=true
        webhook.url=http://localhost:9002/v1/apiwiz-api-security/cli/webhook
        webhook.tenant=tenant-a
        webhook.timeoutSeconds=7
        webhook.retries=4
        """);
    AppConfig cfgObj = AppConfig.resolve(cfg.toString(), null, null, null, null, null, null, null, null, null);
    assertEquals(22, cfgObj.scanner.timeoutSeconds);
    assertEquals(2, cfgObj.scanner.maxRequestsPerRule);
    assertEquals("../rules", cfgObj.rules.directory);
    assertEquals("owasp-api-2023", cfgObj.rules.activeGroups.get(0));
    assertTrue(cfgObj.reports.directory.endsWith("apisec-test-reports"));
    assertTrue(cfgObj.webhook.enabled);
    assertEquals("tenant-a", cfgObj.webhook.tenant);
    assertEquals(7, cfgObj.webhook.timeoutSeconds);
    assertEquals(4, cfgObj.webhook.retries);
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
          "../rules/owasp-api-2023.json"
      ));
      var auth = result.report().findings.stream().filter(f -> "API2-AUTH-001".equals(f.ruleId)).findFirst().orElseThrow();
      assertEquals("FAILED", auth.status);
      assertEquals("remove-x-apikey-header", auth.evidence.get("mutation"));
      var bola = result.report().findings.stream().filter(f -> "API1-BOLA-001".equals(f.ruleId)).findFirst().orElseThrow();
      assertEquals("SKIPPED", bola.status);
      assertEquals("No object identifier detected.", bola.evidence.get("reason"));
    } finally {
      server.stop(0);
    }
  }
}
