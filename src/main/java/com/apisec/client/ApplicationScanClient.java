package com.apisec.client;

import com.apisec.config.AppConfig;
import com.apisec.client.ApplicationScanModels.ApplicationScanResources;
import com.apisec.client.ApplicationScanModels.ResourceTarget;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.math.BigDecimal;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;

public class ApplicationScanClient {
  private static final ObjectMapper MAPPER = new ObjectMapper();

  public static ApplicationScanResources fetch(AppConfig cfg, String sourceUrl, String applicationId) throws Exception {
    String resolvedSource = normalizeSource(sourceUrl);
    if (resolvedSource.isBlank()) {
      throw new IllegalArgumentException("application scan source is required. Set application.scan.sourceUrl in config or pass --application-source");
    }
    if (cfg.apiwiz.xApiKey == null || cfg.apiwiz.xApiKey.isBlank()) {
      throw new IllegalArgumentException("application scan requires apiwiz.x-apikey in config or APISEC_X_APIKEY in the environment");
    }
    HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(resolvedSource + "/" + applicationId + "/resources"))
        .timeout(Duration.ofSeconds(cfg.scanner.timeoutSeconds))
        .GET();
    request.header("x-apikey", cfg.apiwiz.xApiKey);
    if (cfg.apiwiz.tenant != null && !cfg.apiwiz.tenant.isBlank()) request.header("x-tenant", cfg.apiwiz.tenant);
    HttpResponse<String> response = HttpClient.newHttpClient().send(request.build(), HttpResponse.BodyHandlers.ofString());
    if (response.statusCode() < 200 || response.statusCode() >= 300) {
      throw new IllegalStateException("application resources API returned " + response.statusCode());
    }
    return parseResources(response.body());
  }

  private static String normalizeSource(String sourceUrl) {
    if (sourceUrl == null) return "";
    String normalized = sourceUrl.trim();
    while (normalized.endsWith("/")) normalized = normalized.substring(0, normalized.length() - 1);
    return normalized;
  }

  private static ApplicationScanResources parseResources(String body) throws Exception {
    JsonNode root = MAPPER.readTree(body);
    ApplicationScanResources out = new ApplicationScanResources();
    out.applicationProfileId = text(root, "applicationProfileId");
    out.applicationId = text(root, "applicationId");
    out.name = text(root, "name");
    out.description = text(root, "description");
    out.swaggerIds = stringList(root.path("swaggerIds"));
    out.resources = new ArrayList<>();
    JsonNode resources = root.path("resources");
    if (resources.isArray()) {
      for (JsonNode node : resources) {
        ResourceTarget target = new ResourceTarget();
        target.resourceId = text(node, "resourceId");
        target.swaggerDocumentId = text(node, "swaggerDocumentId");
        target.swaggerId = text(node, "swaggerId");
        target.swaggerName = text(node, "swaggerName");
        target.revision = integer(node, "revision");
        target.status = text(node, "status");
        target.baseUrl = text(node, "baseUrl");
        target.url = text(node, "url");
        target.path = text(node, "path");
        target.method = text(node, "method");
        target.operationId = text(node, "operationId");
        target.summary = text(node, "summary");
        target.tags = stringList(node.path("tags"));
        target.servers = stringList(node.path("servers"));
        target.lastScannedAt = instant(node, "lastScannedAt");
        out.resources.add(target);
      }
    }
    return out;
  }

  private static String text(JsonNode node, String field) {
    JsonNode value = node.path(field);
    return value.isMissingNode() || value.isNull() ? null : value.asText();
  }

  private static Integer integer(JsonNode node, String field) {
    JsonNode value = node.path(field);
    return value.isInt() || value.isLong() ? value.asInt() : null;
  }

  private static Instant instant(JsonNode node, String field) {
    JsonNode value = node.path(field);
    if (value.isMissingNode() || value.isNull()) return null;
    String raw = value.asText();
    if (raw == null || raw.isBlank()) return null;
    try {
      return Instant.parse(raw);
    } catch (Exception ignored) {
      return parseEpochInstant(raw);
    }
  }

  private static Instant parseEpochInstant(String raw) {
    BigDecimal numeric = new BigDecimal(raw.trim());
    BigDecimal abs = numeric.abs();
    if (abs.compareTo(BigDecimal.valueOf(100_000_000_000L)) >= 0) {
      return Instant.ofEpochMilli(numeric.longValue());
    }
    long seconds = numeric.longValue();
    BigDecimal nanosFraction = numeric.subtract(BigDecimal.valueOf(seconds))
        .movePointRight(9);
    int nanos = nanosFraction.intValue();
    if (nanos < 0) {
      return Instant.ofEpochSecond(seconds - 1, 1_000_000_000L + nanos);
    }
    return Instant.ofEpochSecond(seconds, nanos);
  }

  private static ArrayList<String> stringList(JsonNode node) {
    ArrayList<String> out = new ArrayList<>();
    if (node != null && node.isArray()) {
      for (JsonNode value : node) {
        if (!value.isNull()) out.add(value.asText());
      }
    }
    return out;
  }
}
