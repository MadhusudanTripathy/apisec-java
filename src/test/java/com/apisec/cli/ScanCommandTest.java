package com.apisec.cli;

import com.apisec.client.ApplicationScanModels.ResourceTarget;
import com.apisec.client.ApplicationScanModels.EnvironmentTarget;
import com.apisec.curl.CurlParser;
import com.apisec.config.AppConfig;
import com.apisec.engine.EndpointClassifier;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.apisec.eval.Evaluator;
import com.apisec.model.RequestModel;
import com.apisec.model.ResponseModel;
import com.apisec.config.AppConfig;
import com.apisec.report.ReportModels;
import com.apisec.report.Reporter;
import com.apisec.rules.RuleModels;
import com.apisec.webhook.WebhookClient;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScanCommandTest {
  private static final ObjectMapper MAPPER = new ObjectMapper();

  @Test void resolvesInlineCurlSubcommandStyleInvocation() {
    String curl = ScanCommand.resolveInlineCurl(
        "curl",
        List.of("--location", "--request", "GET", "https://dev-api.apiwiz.io/itorix/v2/api-security/application/report/metainfo?abc=124&bvd=231")
    );

    RequestModel request = CurlParser.parse(curl);
    assertEquals("GET", request.method);
    assertEquals("https://dev-api.apiwiz.io/itorix/v2/api-security/application/report/metainfo?abc=124&bvd=231", request.url);
    assertEquals("/itorix/v2/api-security/application/report/metainfo", request.path);
    assertEquals("124", request.query.get("abc").get(0));
    assertEquals("231", request.query.get("bvd").get(0));
  }

  @Test void resolvesInlineCurlDirectUrlInvocation() {
    String curl = ScanCommand.resolveInlineCurl(
        "https://api.example.com/v1/books?id=7",
        List.of("--header", "Accept: application/json")
    );

    RequestModel request = CurlParser.parse(curl);
    assertEquals("GET", request.method);
    assertEquals("https://api.example.com/v1/books?id=7", request.url);
    assertEquals("application/json", request.headers.get("Accept").get(0));
  }

  @Test void returnsNullForApplicationIdShape() {
    assertNull(ScanCommand.resolveInlineCurl("6a4e16c99aa5317165ae03d7", List.of()));
  }

  @Test void parserSupportsInlineLongOptions() {
    RequestModel request = CurlParser.parse(
        "curl --request=POST --url=https://api.example.com/books?genre=fantasy " +
            "--header='Content-Type: application/xml' --data-raw='<inventory><book/></inventory>'"
    );

    assertEquals("POST", request.method);
    assertEquals("https://api.example.com/books?genre=fantasy", request.url);
    assertEquals("/books", request.path);
    assertEquals("fantasy", request.query.get("genre").get(0));
    assertEquals("application/xml", request.headers.get("Content-Type").get(0));
    assertEquals("<inventory><book/></inventory>", new String(request.body, StandardCharsets.UTF_8));
  }

  @Test void parserSupportsMultipartFormFields() {
    RequestModel request = CurlParser.parse(
        "curl https://api.example.com/upload --form 'abc=\"1\"' --form '2=\"3\"'"
    );

    assertEquals("POST", request.method);
    assertEquals("https://api.example.com/upload", request.url);
    assertTrue(request.headers.containsKey("Content-Type"));
    assertTrue(request.headers.get("Content-Type").get(0).startsWith("multipart/form-data; boundary="));
    String body = new String(request.body, StandardCharsets.UTF_8);
    assertTrue(body.contains("name=\"abc\""));
    assertTrue(body.contains("\r\n1\r\n"));
    assertTrue(body.contains("name=\"2\""));
    assertTrue(body.contains("\r\n3\r\n"));
    assertEquals("multipart/form-data", request.formEncoding);
    assertEquals(2, request.formFields.size());
    assertEquals("abc", request.formFields.get(0).name);
    assertEquals("1", request.formFields.get(0).value);
    assertEquals("2", request.formFields.get(1).name);
    assertEquals("3", request.formFields.get(1).value);
  }

  @Test void parserSupportsUrlEncodedBodyFields() {
    RequestModel request = CurlParser.parse(
        "curl https://api.example.com/form --header 'Content-Type: application/x-www-form-urlencoded' " +
            "--data-urlencode 'a=1' --data-urlencode 'b=two words'"
    );

    assertEquals("POST", request.method);
    assertEquals("application/x-www-form-urlencoded", request.headers.get("Content-Type").get(0));
    assertEquals("a=1&b=two+words", new String(request.body, StandardCharsets.UTF_8));
    assertEquals("application/x-www-form-urlencoded", request.formEncoding);
    assertEquals(2, request.formFields.size());
    assertEquals("a", request.formFields.get(0).name);
    assertEquals("1", request.formFields.get(0).value);
    assertEquals("b", request.formFields.get(1).name);
    assertEquals("two words", request.formFields.get(1).value);
  }

  @Test void endpointClassifierDetectsRestType() {
    RequestModel request = CurlParser.parse(
        "curl https://api.example.com/v1/books/7 --header 'Accept: application/json'"
    );

    assertEquals("REST", EndpointClassifier.classify(request).type());
  }

  @Test void endpointClassifierDetectsSoapType() {
    RequestModel request = CurlParser.parse(
        "curl https://api.example.com/soap --header 'Content-Type: text/xml' " +
            "--header 'SOAPAction: urn:getBook' " +
            "--data '<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"><soapenv:Body/></soapenv:Envelope>'"
    );

    assertEquals("SOAP", EndpointClassifier.classify(request).type());
  }

  @Test void endpointClassifierDetectsGraphqlType() {
    RequestModel request = CurlParser.parse(
        "curl https://api.example.com/graphql --header 'Content-Type: application/json' " +
            "--data '{\"query\":\"query { books { id } }\"}'"
    );

    assertEquals("GRAPHQL", EndpointClassifier.classify(request).type());
  }

  @Test void reportCarriesTopLevelEndpointType() {
    RequestModel request = CurlParser.parse(
        "curl https://api.example.com/graphql --header 'Content-Type: application/json' " +
            "--data '{\"query\":\"query { books { id } }\"}'"
    );

    ReportModels.Report report = Reporter.build(
        "scan_1234",
        Instant.parse("2026-07-15T00:00:00Z"),
        Instant.parse("2026-07-15T00:00:01Z"),
        request.method,
        request.url,
        request.host,
        java.util.Map.of(),
        List.of(),
        List.of(),
        new ReportModels.WebhookStatus()
    );
    report.type = EndpointClassifier.classify(request).type();

    assertEquals("GRAPHQL", report.type);
  }

  @Test void scannerOptionsCanCarrySharedRunScanId() {
    var options = new com.apisec.engine.ScannerEngine.Options(
        "curl https://api.example.com/graphql",
        null,
        null,
        null,
        null,
        "scan_shared_run"
    );

    assertEquals("scan_shared_run", options.scanId());
  }

  @Test void selectedServerOverridesResourceUrlForApplicationScanTarget() {
    ResourceTarget resource = new ResourceTarget();
    resource.selectedServer = "https://selected.example.com/api/";
    resource.url = "https://default.example.com/v1/books/{id}";
    resource.path = "/v1/books/{id}";

    assertEquals("https://selected.example.com/api/v1/books/1", ScanCommand.safeUrl(resource));
  }

  @Test void serverLabelsAppendEnvironmentNamesForPromptDisplay() {
    ResourceTarget first = new ResourceTarget();
    first.servers = List.of("http://35.154.57.83:8000/v1/loans/");
    first.environments = List.of(environment("DEV"), environment("UAT"));

    ResourceTarget second = new ResourceTarget();
    second.servers = List.of("http://35.154.57.83:8000/v1/loans");
    second.environments = List.of(environment("QA"));

    var labels = ScanCommand.serverLabels(List.of(first, second));

    assertEquals("http://35.154.57.83:8000/v1/loans (DEV, UAT, QA)", labels.get("http://35.154.57.83:8000/v1/loans"));
  }

  @Test void selectedServerIsSerializedInResourceReport() throws Exception {
    AppConfig cfg = AppConfig.defaults();
    Path reportDir = Files.createTempDirectory("apisec-java-selected-server");
    cfg.reports.directory = reportDir.toString();

    ReportModels.Report report = new ReportModels.Report();
    report.scanId = "scan_selected_server";
    report.startedAt = Instant.parse("2026-07-21T10:00:00Z");
    report.finishedAt = Instant.parse("2026-07-21T10:00:01Z");
    report.resource = new ReportModels.Resource();
    report.resource.resourceId = "resource-1";
    report.resource.selectedServer = "https://selected.example.com/api";

    var writeResult = Reporter.writeJson(report, cfg);
    JsonNode json = MAPPER.readTree(Path.of(writeResult.path()).toFile());

    assertEquals("https://selected.example.com/api", json.path("resource").path("selectedServer").asText());
  }

  @Test void reporterAvoidsFileNameCollisionsForSharedScanId() throws Exception {
    AppConfig cfg = AppConfig.defaults();
    Path reportDir = Files.createTempDirectory("apisec-java-shared-scanid");
    cfg.reports.directory = reportDir.toString();

    ReportModels.Report first = new ReportModels.Report();
    first.scanId = "scan_shared_run";
    first.startedAt = Instant.parse("2026-07-17T10:00:00Z");
    first.finishedAt = Instant.parse("2026-07-17T10:00:01Z");

    ReportModels.Report second = new ReportModels.Report();
    second.scanId = "scan_shared_run";
    second.startedAt = Instant.parse("2026-07-17T10:00:00Z");
    second.finishedAt = Instant.parse("2026-07-17T10:00:02Z");

    var firstWrite = Reporter.writeJson(first, cfg);
    var secondWrite = Reporter.writeJson(second, cfg);

    assertTrue(firstWrite.path().endsWith("scan_20260717_100000_scan_shared_run.json"));
    assertTrue(secondWrite.path().endsWith("scan_20260717_100000_scan_shared_run_2.json"));
  }

  private static EnvironmentTarget environment(String name) {
    EnvironmentTarget env = new EnvironmentTarget();
    env.environmentName = name;
    return env;
  }

  @Test void evaluatorTreatsRequestBodyNumericComparisonAsBodySimilarityAlias() {
    RuleModels.Assertion assertion = new RuleModels.Assertion();
    assertion.expression = "({0})";
    RuleModels.Placeholder placeholder = new RuleModels.Placeholder();
    placeholder.rule = "GREATER_THAN_EQUAL_TO";
    placeholder.key = "request.body";
    placeholder.value = "0.85";
    assertion.placeholders = List.of(placeholder);

    RequestModel request = new RequestModel();
    request.body = "{\"request\":\"payload\"}".getBytes(StandardCharsets.UTF_8);

    ResponseModel baseline = new ResponseModel();
    baseline.body = "{\"id\":1,\"status\":\"ok\"}".getBytes(StandardCharsets.UTF_8);

    ResponseModel response = new ResponseModel();
    response.body = "{\"id\":1,\"status\":\"ok\"}".getBytes(StandardCharsets.UTF_8);

    assertFalse(Evaluator.assertion(assertion, request, baseline, response).passed());
  }

  @Test void webhookConfigSupportsEndpointRetentionHeader() throws Exception {
    AppConfig cfg = AppConfig.defaults();
    cfg.webhook.url = "https://api.example.com/v2/api-security/cli/webhook";
    cfg.webhook.timeoutSeconds = 5;
    cfg.webhook.endpointReportRetention = 20;

    HttpRequest request = WebhookClient.buildRequest(cfg, "scan_1234", "{}".getBytes(StandardCharsets.UTF_8))
        .header(WebhookClient.ENDPOINT_REPORT_RETENTION_HEADER, String.valueOf(cfg.webhook.endpointReportRetention))
        .build();

    assertEquals("20", request.headers().firstValue(WebhookClient.ENDPOINT_REPORT_RETENTION_HEADER).orElseThrow());
  }

  @Test void defaultWebhookRetentionIsDisabledAtCliLevel() {
    AppConfig cfg = AppConfig.defaults();
    assertEquals(0, cfg.webhook.endpointReportRetention);
    assertFalse(cfg.webhook.endpointReportRetention > 0);
  }
}
