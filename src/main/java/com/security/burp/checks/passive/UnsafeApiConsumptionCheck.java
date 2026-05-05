package com.security.burp.checks.passive;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.security.burp.ai.AiTriage;
import com.security.burp.checks.AbstractPassiveCheck;
import com.security.burp.scanner.EndpointRegistry;
import com.security.burp.util.IssueBuilder;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * OWASP API10:2023 — Unsafe Consumption of APIs.
 *
 * <p>Two heuristics:
 * <ul>
 *   <li>response body references a well-known third-party API host (Google,
 *       Stripe, Twilio, ...) without obvious signs of validation;</li>
 *   <li>request path looks like a webhook receiver — webhook handlers are a
 *       common locus of unsafe consumption (no signature verification, no
 *       schema enforcement).</li>
 * </ul>
 */
public final class UnsafeApiConsumptionCheck extends AbstractPassiveCheck {

    /** Hosts whose appearance in a response strongly implies third-party consumption. */
    private static final Set<String> THIRD_PARTY_HOSTS = Set.of(
            "googleapis.com", "github.com", "stripe.com", "twilio.com",
            "sendgrid.com", "amazonaws.com", "azure.com", "cloudflare.com",
            "slack.com", "api.twitter.com", "graph.facebook.com");

    /** Heuristic markers that the response body shows validation occurring. */
    private static final Set<String> VALIDATION_MARKERS = Set.of(
            "\"validated\"", "\"sanitized\"", "\"verified\"");

    /** Path keywords identifying webhook / external-event receivers. */
    private static final Set<String> WEBHOOK_PATH_KEYWORDS = Set.of(
            "/webhook", "/callback", "/notify", "/event", "/integration");

    private static final String ISSUE_BACKGROUND =
            "API10:2023 - Unsafe Consumption of APIs<br><br>" +
            "Developers tend to trust data from third-party APIs more than user input, and " +
            "apply weaker validation to it. Attackers compromise integrated services rather " +
            "than the target API directly, then ride the trust relationship.";

    public UnsafeApiConsumptionCheck(MontoyaApi api, EndpointRegistry endpoints, AiTriage triage) {
        super(api, endpoints, triage);
    }

    @Override
    public String checkName() {
        return "API10:2023 Unsafe API Consumption";
    }

    @Override
    protected List<AuditIssue> audit(HttpRequestResponse rr) {
        if (!rr.hasResponse()) return List.of();

        List<AuditIssue> issues = new ArrayList<>();
        String body = rr.response().bodyToString();
        String thirdParty = referencedThirdParty(body);
        if (thirdParty != null && !looksValidated(body)) {
            issues.add(buildThirdPartyIssue(rr, thirdParty));
        }
        if (isWebhookPath(rr.request().pathWithoutQuery())) {
            issues.add(buildWebhookIssue(rr));
        }
        return issues;
    }

    // ---- Detection ---------------------------------------------------------

    private static String referencedThirdParty(String body) {
        if (body == null) return null;
        for (String host : THIRD_PARTY_HOSTS) {
            if (body.contains(host)) return host;
        }
        return null;
    }

    private static boolean looksValidated(String body) {
        if (body == null) return false;
        for (String marker : VALIDATION_MARKERS) {
            if (body.contains(marker)) return true;
        }
        return false;
    }

    private static boolean isWebhookPath(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase(Locale.ROOT);
        for (String keyword : WEBHOOK_PATH_KEYWORDS) {
            if (lower.contains(keyword)) return true;
        }
        return false;
    }

    // ---- Issues ------------------------------------------------------------

    private AuditIssue buildThirdPartyIssue(HttpRequestResponse rr, String host) {
        String detail =
                "The response references a third-party API host (<code>" + host + "</code>) " +
                "and shows no obvious signs of validation. Untrusted upstream data flowing " +
                "through this endpoint may carry injection payloads or violate downstream " +
                "schema assumptions.";
        String remediation =
                "Treat third-party data as untrusted: validate against an explicit schema, " +
                "sanitize, and rate-limit consumption.";
        return IssueBuilder.issue(rr)
                .name("API10:2023 - Unsafe Consumption of APIs (Third-Party Reference)")
                .detail(detail)
                .remediation(remediation)
                .background(ISSUE_BACKGROUND)
                .severity("Medium")
                .confidence("Tentative")
                .build();
    }

    private AuditIssue buildWebhookIssue(HttpRequestResponse rr) {
        String path = rr.request().pathWithoutQuery();
        String detail =
                "Endpoint <code>" + path + "</code> appears to be a webhook receiver. " +
                "Webhook handlers commonly skip signature verification, schema validation, " +
                "and source allow-listing.";
        String remediation =
                "Verify HMAC signatures on webhook payloads, allow-list source IP ranges where " +
                "the provider publishes them, and validate body shape before any side effect.";
        return IssueBuilder.issue(rr)
                .name("API10:2023 - Unsafe Consumption of APIs (Webhook Endpoint)")
                .detail(detail)
                .remediation(remediation)
                .background(ISSUE_BACKGROUND)
                .severity("Medium")
                .confidence("Tentative")
                .build();
    }
}
