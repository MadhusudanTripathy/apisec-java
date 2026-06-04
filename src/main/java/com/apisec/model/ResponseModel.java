package com.apisec.model;

import java.util.*;

public class ResponseModel {
  public int statusCode;
  public Map<String, List<String>> headers = new LinkedHashMap<>();
  public byte[] body = new byte[0];
  public long durationMs;
  public int bodySize;
  public String contentType = "";
  public String error = "";
}
