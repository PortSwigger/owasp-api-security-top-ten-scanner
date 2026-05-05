package com.security.burp.checks.passive;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
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
 * OWASP API4:2023 — Unrestricted Resource Consumption.
 *
 * <p>Two cheap passive signals:
 * <ol>
 *   <li>response body exceeds {@value #LARGE_RESPONSE_BYTES} bytes;</li>
 *   <li>response is missing rate-limit headers on a path whose name suggests
 *       resource-intensive work (search, export, report, ...).</li>
 * </ol>
 */
public final class ResourceConsumptionCheck extends AbstractPassiveCheck {

    private static final int LARGE_RESPONSE_BYTES = 5 * 1024 * 1024;

    /** Path keywords that suggest resource-intensive work. */
    private static final Set<String> HEAVY_PATH_KEYWORDS = Set.of(
            "/search", "/export", "/report", "/download",
            "/bulk", "/batch", "/query");

    /** Header-name prefixes that indicate the server reports rate-limit state. */
    private static final List<String> RATE_LIMIT_HEADER_PREFIXES = List.of(
            "x-ratelimit-", "x-rate-limit-", "ratelimit-");

    private static final String ISSUE_BACKGROUND =
            "API4:2023 - Unrestricted Resource Consumption<br><br>" +
            "Satisfying API requests consumes bandwidth, CPU, memory, and storage. " +
            "Successful exploitation can lead to denial of service or an increase in " +
            "operational costs through abuse of paid-per-request integrations.";

    public ResourceConsumptionCheck(MontoyaApi api, EndpointRegistry endpoints, AiTriage triage) {
        super(api, endpoints, triage);
    }

    @Override
    public String checkName() {
        return "API4:2023 Unrestricted Resource Consumption";
    }

    @Override
    protected List<AuditIssue> audit(HttpRequestResponse rr) {
        if (!rr.hasResponse()) return List.of();
        HttpResponse response = rr.response();

        List<AuditIssue> issues = new ArrayList<>();
        int responseBytes = response.toByteArray().length();
        if (responseBytes > LARGE_RESPONSE_BYTES) {
            issues.add(buildLargeResponseIssue(rr, responseBytes));
        }
        if (!hasRateLimitHeader(response) && isHeavyPath(rr)) {
            issues.add(buildMissingRateLimitIssue(rr));
        }
        return issues;
    }

    // ---- Detection ---------------------------------------------------------

    private static boolean hasRateLimitHeader(HttpResponse response) {
        for (HttpHeader header : response.headers()) {
            String name = header.name() == null ? "" : header.name().toLowerCase(Locale.ROOT);
            for (String prefix : RATE_LIMIT_HEADER_PREFIXES) {
                if (name.startsWith(prefix)) return true;
            }
        }
        return false;
    }

    private static boolean isHeavyPath(HttpRequestResponse rr) {
        String path = rr.request().pathWithoutQuery();
        if (path == null) return false;
        String lower = path.toLowerCase(Locale.ROOT);
        for (String keyword : HEAVY_PATH_KEYWORDS) {
            if (lower.contains(keyword)) return true;
        }
        return false;
    }

    // ---- Issues ------------------------------------------------------------

    private AuditIssue buildLargeResponseIssue(HttpRequestResponse rr, int bytes) {
        String detail =
                "The API returned a very large response (" + (bytes / 1024) + " KB).<br><br>" +
                "Large responses can cause client-side memory exhaustion, network bandwidth " +
                "consumption, and amplification-style denial of service.";
        String remediation =
                "Paginate large datasets, enforce a server-side response size cap, and stream " +
                "instead of buffering for genuinely large payloads.";
        return IssueBuilder.issue(rr)
                .name("API4:2023 - Unrestricted Resource Consumption (Large Response)")
                .detail(detail)
                .remediation(remediation)
                .background(ISSUE_BACKGROUND)
                .severity("Medium")
                .confidence("Certain")
                .build();
    }

    private AuditIssue buildMissingRateLimitIssue(HttpRequestResponse rr) {
        String path = rr.request().pathWithoutQuery();
        String detail =
                "Endpoint <code>" + path + "</code> performs resource-intensive work but the " +
                "response carries no rate-limit headers (X-RateLimit-*, RateLimit-*).<br><br>" +
                "Without rate limiting, an attacker can drive the endpoint at scale to cause " +
                "denial of service, exhaust per-account quotas, or run up operational costs.";
        String remediation =
                "Apply rate limiting and surface the state via standard response headers: " +
                "<code>X-RateLimit-Limit</code>, <code>X-RateLimit-Remaining</code>, " +
                "<code>X-RateLimit-Reset</code>.";
        return IssueBuilder.issue(rr)
                .name("API4:2023 - Unrestricted Resource Consumption (Missing Rate Limiting)")
                .detail(detail)
                .remediation(remediation)
                .background(ISSUE_BACKGROUND)
                .severity("Low")
                .confidence("Tentative")
                .build();
    }
}
