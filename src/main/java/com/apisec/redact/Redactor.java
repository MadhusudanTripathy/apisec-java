package com.apisec.redact;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.*;
import java.util.regex.*;

public class Redactor {
  public static final String REDACTED = "[REDACTED]";
  private static final Set<String> KEYS = Set.of("authorization","cookie","set-cookie","x-api-key","x-apikey","api_key","apikey","access_token","refresh_token","token","password","passwd","secret","client_secret","private_key");
  private static final Pattern PAIR = Pattern.compile("(?i)(authorization|cookie|set-cookie|x-api-key|x-apikey|api_key|apikey|access_token|refresh_token|token|password|passwd|secret|client_secret|private_key)(=|: )([^&\\s,}]+)");

  public static String text(String in) {
    if (in == null) return "";
    return PAIR.matcher(in).replaceAll("$1$2" + REDACTED);
  }

  public static JsonNode json(JsonNode n) {
    if (n == null) return null;
    if (n.isObject()) {
      ObjectNode o = (ObjectNode)n;
      Iterator<String> names = o.fieldNames();
      List<String> keys = new ArrayList<>();
      names.forEachRemaining(keys::add);
      for (String k: keys) {
        if (KEYS.contains(k.toLowerCase(Locale.ROOT))) o.put(k, REDACTED);
        else json(o.get(k));
      }
    } else if (n.isArray()) n.forEach(Redactor::json);
    return n;
  }
}
