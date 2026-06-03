package com.security.burp.checks.passive;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.security.burp.ai.AiTriage;
import com.security.burp.checks.AbstractPassiveCheck;
import com.security.burp.scanner.EndpointRegistry;
import com.security.burp.util.IssueBuilder;

import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * OWASP API10:2023 — Unsafe Consumption of APIs.
 *
 * <p>Webhook-receiver detection only. The earlier "third-party API
 * reference in response body" detector was dropped per security-research
 * feedback (Zak): hardcoded substrings like {@code googleapis.com}
 * produced a lot of noise on real targets without much signal — modern
 * web apps legitimately mention third-party domains all the time, and
 * the presence of a string is a poor proxy for unsafe consumption.
 *
 * <p>Webhook detection is kept because the path-keyword signal is
 * tight: receivers named {@code /webhook}, {@code /callback}, etc. are
 * specifically vulnerable to skipped signature verification and
 * downstream injection from external sources.
 */
public final class UnsafeApiConsumptionCheck extends AbstractPassiveCheck {

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
        if (!isWebhookPath(rr.request().pathWithoutQuery())) return List.of();
        return List.of(buildWebhookIssue(rr));
    }

    private static boolean isWebhookPath(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase(Locale.ROOT);
        for (String keyword : WEBHOOK_PATH_KEYWORDS) {
            if (lower.contains(keyword)) return true;
        }
        return false;
    }

    private AuditIssue buildWebhookIssue(HttpRequestResponse rr) {
        String path = IssueBuilder.escapeHtml(rr.request().pathWithoutQuery());
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
