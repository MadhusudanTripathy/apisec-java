package com.apisec.webhook;

import com.apisec.config.AppConfig;
import com.apisec.report.ReportModels.WebhookStatus;
import java.net.URI;
import java.net.http.*;
import java.time.Duration;

public class WebhookClient {
  public static final String ENDPOINT_REPORT_RETENTION_HEADER = "X-ApiSec-Endpoint-Report-Retention";

  public static WebhookStatus send(AppConfig cfg, String scanId, byte[] payload) {
    WebhookStatus ws = new WebhookStatus();
    ws.enabled = cfg.webhook.enabled || (cfg.webhook.url != null && !cfg.webhook.url.isBlank());
    if (!ws.enabled) return ws;
    int attempts = Math.max(1, cfg.webhook.retries);
    HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(cfg.webhook.timeoutSeconds)).build();
    for (int i=1; i<=attempts; i++) {
      ws.attempts = i;
      try {
        HttpRequest.Builder b = buildRequest(cfg, scanId, payload);
        if (cfg.apiwiz.xApiKey != null && !cfg.apiwiz.xApiKey.isBlank()) b.header("x-apikey", cfg.apiwiz.xApiKey);
        if (cfg.webhook.tenant != null && !cfg.webhook.tenant.isBlank()) b.header("tenant", cfg.webhook.tenant);
        if (cfg.webhook.endpointReportRetention > 0) {
          b.header(ENDPOINT_REPORT_RETENTION_HEADER, String.valueOf(cfg.webhook.endpointReportRetention));
        }
        HttpResponse<Void> r = client.send(b.build(), HttpResponse.BodyHandlers.discarding());
        ws.statusCode = r.statusCode();
        if (r.statusCode() >= 200 && r.statusCode() < 300) { ws.delivered = true; return ws; }
      } catch (Exception e) { ws.error = e.getMessage(); }
    }
    return ws;
  }

  public static HttpRequest.Builder buildRequest(AppConfig cfg, String scanId, byte[] payload) {
    return HttpRequest.newBuilder(URI.create(cfg.webhook.url)).timeout(Duration.ofSeconds(cfg.webhook.timeoutSeconds))
        .POST(HttpRequest.BodyPublishers.ofByteArray(payload)).header("Content-Type", "application/json").header("X-ApiSec-Scan-Id", scanId);
  }
}
