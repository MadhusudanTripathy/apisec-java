package com.apisec.model;

import java.net.URI;
import java.util.*;

public class RequestModel {
  public String method = "GET";
  public String url = "";
  public String scheme = "";
  public String host = "";
  public String path = "";
  public Map<String, List<String>> query = new LinkedHashMap<>();
  public Map<String, List<String>> headers = new LinkedHashMap<>();
  public Map<String, String> cookies = new LinkedHashMap<>();
  public byte[] body = new byte[0];
  public String formEncoding = "";
  public List<FormField> formFields = new ArrayList<>();

  public RequestModel copy() {
    RequestModel c = new RequestModel();
    c.method = method; c.url = url; c.scheme = scheme; c.host = host; c.path = path;
    query.forEach((k, v) -> c.query.put(k, new ArrayList<>(v)));
    headers.forEach((k, v) -> c.headers.put(k, new ArrayList<>(v)));
    c.cookies.putAll(cookies);
    c.body = Arrays.copyOf(body, body.length);
    c.formEncoding = formEncoding;
    formFields.forEach(field -> c.formFields.add(field.copy()));
    return c;
  }

  public void normalizeFromUrl() {
    URI u = URI.create(url);
    scheme = u.getScheme();
    host = u.getHost();
    path = u.getRawPath() == null || u.getRawPath().isEmpty() ? "/" : u.getRawPath();
  }

  public static class FormField {
    public String name = "";
    public String value;
    public String contentType;
    public String filename;

    public FormField copy() {
      FormField c = new FormField();
      c.name = name;
      c.value = value;
      c.contentType = contentType;
      c.filename = filename;
      return c;
    }
  }
}
