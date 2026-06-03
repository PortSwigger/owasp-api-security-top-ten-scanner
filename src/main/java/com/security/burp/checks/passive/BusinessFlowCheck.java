package com.security.burp.checks.passive;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
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
 * OWASP API6:2023 — Unrestricted Access to Sensitive Business Flows.
 *
 * <p>Flags requests to "sensitive" paths (checkout, payment, transfer,
 * withdrawal, etc.) that lack anti-automation indicators (CAPTCHA challenge,
 * rate-limit headers, delay headers). High-value endpoints exposed to
 * unrestricted automation are the focus of this OWASP category.
 *
 * <p>Heuristic, not exact — detection is keyword-based on the URL path and
 * presence-based on response headers/body. The AI triage layer (when
 * enabled) is the second-line filter for false positives.
 */
public final class BusinessFlowCheck extends AbstractPassiveCheck {

    /** Path keywords that suggest a sensitive business flow. */
    private static final Set<String> SENSITIVE_PATH_KEYWORDS = Set.of(
            "checkout", "payment", "purchase", "buy",
            "transfer", "withdraw", "deposit",
            "register", "signup", "account/create",
            "vote", "ballot");

    /** Response headers that suggest some form of anti-automation control. */
    private static final Set<String> ANTI_AUTOMATION_HEADERS = Set.of(
            "x-ratelimit-limit", "x-ratelimit-remaining", "x-rate-limit-limit",
            "retry-after", "x-captcha-required", "x-bot-detection");

    /** Response body markers that suggest a CAPTCHA or other challenge. */
    private static final Set<String> ANTI_AUTOMATION_BODY_MARKERS = Set.of(
            "captcha", "recaptcha", "hcaptcha", "challenge");

    private static final String ISSUE_NAME =
            "API6:2023 - Unrestricted Access to Sensitive Business Flow";

    private static final String ISSUE_BACKGROUND =
            "API6:2023 - Unrestricted Access to Sensitive Business Flows<br><br>" +
            "An attacker may exploit the lack of automation defences on a high-value " +
            "endpoint to perform actions at scale: bulk account creation, ticket scalping, " +
            "fraudulent purchases, vote stuffing, etc.";

    private static final String ISSUE_REMEDIATION =
            "Apply rate limits, CAPTCHA challenges, or proof-of-work to sensitive " +
            "endpoints. Consider step-up authentication for high-value operations.";

    public BusinessFlowCheck(MontoyaApi api, EndpointRegistry endpoints, AiTriage triage) {
        super(api, endpoints, triage);
    }

    @Override
    public String checkName() {
        return ISSUE_NAME;
    }

    @Override
    protected List<AuditIssue> audit(HttpRequestResponse rr) {
        if (!isSensitivePath(rr.request())) return List.of();
        if (!rr.hasResponse()) return List.of();
        if (hasAntiAutomation(rr.response())) return List.of();

        List<AuditIssue> issues = new ArrayList<>(1);
        issues.add(buildIssue(rr));
        return issues;
    }

    // ---- Detection helpers --------------------------------------------------

    private static boolean isSensitivePath(HttpRequest request) {
        String path = request.pathWithoutQuery();
        if (path == null) return false;
        String lower = path.toLowerCase(Locale.ROOT);
        for (String keyword : SENSITIVE_PATH_KEYWORDS) {
            if (lower.contains(keyword)) return true;
        }
        return false;
    }

    private static boolean hasAntiAutomation(HttpResponse response) {
        for (HttpHeader header : response.headers()) {
            if (ANTI_AUTOMATION_HEADERS.contains(header.name().toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        String body = response.bodyToString();
        if (body == null) return false;
        String lower = body.toLowerCase(Locale.ROOT);
        for (String marker : ANTI_AUTOMATION_BODY_MARKERS) {
            if (lower.contains(marker)) return true;
        }
        return false;
    }

    // ---- Issue construction -------------------------------------------------

    private AuditIssue buildIssue(HttpRequestResponse rr) {
        String detail =
                "The endpoint <code>" + IssueBuilder.escapeHtml(rr.request().pathWithoutQuery()) + "</code> appears " +
                "to expose a sensitive business flow but the response shows no obvious " +
                "anti-automation control (no rate-limit headers, no CAPTCHA challenge, " +
                "no Retry-After).<br><br>" +
                "An attacker who can drive this endpoint at scale may be able to perform " +
                "the underlying business action many times in succession.";

        return IssueBuilder.issue(rr)
                .name(ISSUE_NAME)
                .detail(detail)
                .remediation(ISSUE_REMEDIATION)
                .background(ISSUE_BACKGROUND)
                .severity("Medium")
                .confidence("Tentative")
                .build();
    }
}
