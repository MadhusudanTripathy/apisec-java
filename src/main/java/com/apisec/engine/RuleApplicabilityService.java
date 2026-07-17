package com.apisec.engine;

import com.apisec.engine.EndpointClassifier.EndpointContext;
import com.apisec.engine.ResponseSemanticAnalyzer.Semantics;
import com.apisec.model.RequestModel;

import java.util.*;

public class RuleApplicabilityService {
  public record Decision(boolean applicable, String reason) {
    public static Decision run() { return new Decision(true, ""); }
    public static Decision skip(String reason) { return new Decision(false, reason); }
  }

  public static Decision applicable(String ruleId, RequestModel req, EndpointContext ctx, Semantics baseline) {
    if (ruleId == null) return Decision.run();

    if (ruleId.equals("API2-AUTH-005") && !baseline.cookieSignal() && req.cookies.isEmpty()) {
      return Decision.skip("Cookie rule skipped because the baseline response did not set cookies.");
    }

    if (Set.of("API4-RESOURCE-001", "API4-RESOURCE-002", "API4-RESOURCE-003").contains(ruleId) && !ctx.hasPaginationSignal()) {
      return Decision.skip("Pagination rule skipped because no pagination/list signal was detected.");
    }

    if (ruleId.equals("API6-BUSINESS-002") && !ctx.hasOtpSignal()) {
      return Decision.skip("OTP/rate-limit rule skipped because this endpoint does not look like OTP, MFA, verification, login, or password reset.");
    }

    if (ruleId.equals("API6-BUSINESS-003") && !ctx.hasPaymentSignal()) {
      return Decision.skip("Payment idempotency rule skipped because no payment or transfer signal was detected.");
    }

    if (ruleId.equals("API6-BUSINESS-005") && !ctx.hasSensitiveAction()) {
      return Decision.skip("Confirmation rule skipped because no sensitive business action was detected.");
    }

    if (Set.of("API7-SSRF-001", "API7-SSRF-002", "API7-SSRF-003", "API7-SSRF-004", "API7-SSRF-005",
        "API10-CONSUME-001", "API10-CONSUME-004", "API10-CONSUME-005").contains(ruleId)
        && !ctx.hasUrlInput() && !ctx.is("WEBHOOK")) {
      return Decision.skip("URL/SSRF rule skipped because no URL-like input or webhook/callback signal was detected.");
    }

    if (ruleId.equals("API1-BOLA-006")) return Decision.run();
    if (ruleId.startsWith("API1-BOLA") && !ctx.hasObjectIdentifier()) {
      return Decision.skip("BOLA rule skipped because no object identifier was detected.");
    }

    return Decision.run();
  }
}
