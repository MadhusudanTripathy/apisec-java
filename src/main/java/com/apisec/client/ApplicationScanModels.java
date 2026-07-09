package com.apisec.client;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public class ApplicationScanModels {
  @JsonIgnoreProperties(ignoreUnknown = true)
  public static class ApplicationScanResources {
    public String applicationProfileId;
    public String applicationId;
    public String name;
    public String description;
    public List<String> swaggerIds = new ArrayList<>();
    public List<ResourceTarget> resources = new ArrayList<>();
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  public static class ResourceTarget {
    public String resourceId;
    public String swaggerDocumentId;
    public String swaggerId;
    public String swaggerName;
    public Integer revision;
    public String status;
    public String baseUrl;
    public String url;
    public String path;
    public String method;
    public String operationId;
    public String summary;
    public List<String> tags = new ArrayList<>();
    public List<String> servers = new ArrayList<>();
    public Instant lastScannedAt;
  }
}
