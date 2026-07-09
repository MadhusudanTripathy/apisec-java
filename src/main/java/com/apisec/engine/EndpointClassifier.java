package com.apisec.engine;

import com.apisec.model.RequestModel;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

public class EndpointClassifier {
  private static final Pattern UUID = Pattern.compile("(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");

  public record EndpointContext(Set<String> types, boolean hasObjectIdentifier, boolean hasPaginationSignal,
                                boolean hasOtpSignal, boolean hasUrlInput, boolean hasCookieSignal,
                                boolean hasTenantSignal, boolean hasPaymentSignal, boolean hasSensitiveAction) {
    public boolean is(String type) { return types.contains(type); }
  }

  public static EndpointContext classify(RequestModel req) {
    String path = lower(req.path);
    String url = lower(req.url);
    String body = lower(new String(req.body == null ? new byte[0] : req.body, StandardCharsets.UTF_8));
    String queryKeys = lower(String.join(" ", req.query.keySet()));
    String headerKeys = lower(String.join(" ", req.headers.keySet()));
    String all = String.join(" ", path, url, body, queryKeys, headerKeys);

    boolean objectId = hasObjectIdentifier(req);
    boolean pagination = containsAny(all, "page", "limit", "offset", "cursor", "size", "per_page", "perpage")
        || path.matches(".*/(list|search|query|items|records)(/.*)?$");
    boolean otp = containsAny(all, "otp", "mfa", "2fa", "verify", "verification", "one-time", "password-reset", "reset-password");
    boolean auth = containsAny(all, "login", "logout", "token", "auth", "signin", "signup", "session");
    boolean payment = containsAny(all, "payment", "payments", "transfer", "amount", "currency", "debtor", "creditor", "account");
    boolean admin = containsAny(all, "admin", "role", "privilege", "permission");
    boolean webhook = containsAny(all, "webhook", "callback", "callbackurl", "callback_url", "returnurl", "return_url");
    boolean urlInput = hasUrlInput(req, body);
    boolean cookie = !req.cookies.isEmpty() || req.headers.keySet().stream().anyMatch(k -> k.equalsIgnoreCase("Cookie"));
    boolean tenant = req.headers.keySet().stream().anyMatch(k -> lower(k).contains("tenant") || lower(k).contains("org"))
        || req.query.keySet().stream().anyMatch(k -> lower(k).contains("tenant") || lower(k).contains("org"));
    boolean sensitiveAction = payment || containsAny(all, "delete", "approve", "withdraw", "refund", "payout", "beneficiary", "credential", "password");

    Set<String> types = new TreeSet<>();
    if (auth) types.add("AUTH");
    if (payment) types.add("PAYMENT_TRANSFER");
    if (pagination) types.add("LIST_OR_SEARCH");
    if (objectId) types.add("OBJECT_DETAIL");
    if (admin) types.add("ADMIN_OR_PERMISSION");
    if (webhook) types.add("WEBHOOK");
    if (otp) types.add("OTP_OR_VERIFICATION");
    if (sensitiveAction) types.add("SENSITIVE_ACTION");
    if (types.isEmpty()) types.add("UNKNOWN");

    return new EndpointContext(types, objectId, pagination, otp, urlInput, cookie, tenant, payment, sensitiveAction);
  }

  private static boolean hasObjectIdentifier(RequestModel req) {
    for (String part : req.path.split("/")) {
      if (part.matches("^\\d+$") || UUID.matcher(part).matches()) return true;
    }
    Set<String> idKeys = Set.of("id", "userid", "accountid", "orgid", "tenantid", "orderid", "permissionid", "paymentid", "transactionid");
    for (String k : req.query.keySet()) {
      String key = lower(k).replace("_", "");
      if (idKeys.contains(key)) return true;
      for (String v : req.query.getOrDefault(k, List.of())) if (UUID.matcher(v).find()) return true;
    }
    String headers = lower(String.join(" ", req.headers.keySet()));
    return headers.contains("tenant") || headers.contains("org");
  }

  private static boolean hasUrlInput(RequestModel req, String body) {
    if (body.contains("http://") || body.contains("https://") || body.contains("callbackurl") || body.contains("upstreamurl")) return true;
    for (var e : req.query.entrySet()) {
      String k = lower(e.getKey());
      if (k.contains("url") || k.contains("uri") || k.contains("callback") || k.contains("webhook")) return true;
      for (String v : e.getValue()) if (lower(v).startsWith("http://") || lower(v).startsWith("https://")) return true;
    }
    return false;
  }

  private static boolean containsAny(String text, String... needles) {
    for (String n : needles) if (text.contains(n)) return true;
    return false;
  }

  private static String lower(String s) {
    return s == null ? "" : s.toLowerCase(Locale.ROOT);
  }
}
