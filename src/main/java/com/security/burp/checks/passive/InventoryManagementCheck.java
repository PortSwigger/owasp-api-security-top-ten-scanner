package com.security.burp.checks.passive;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
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
import java.util.regex.Pattern;

/**
 * OWASP API9:2023 — Improper Inventory Management.
 *
 * <p>Three lightweight passive signals:
 * <ul>
 *   <li>path looks like a deprecated/legacy API version;</li>
 *   <li>path looks like a debug/internal endpoint exposed in production;</li>
 *   <li>response advertises an API version in a header.</li>
 * </ul>
 */
public final class InventoryManagementCheck extends AbstractPassiveCheck {

    /**
     * Path patterns suggesting a deprecated version or legacy code path.
     * Only {@code /v0/} is treated as deprecated — {@code /v1/} is the
     * <em>current</em> version on most APIs, so flagging it produced a false
     * positive on nearly every modern API (removed per BApp review).
     */
    private static final List<Pattern> DEPRECATED_PATH_PATTERNS = List.of(
            Pattern.compile(".*/v0/.*"));

    private static final Set<String> DEPRECATED_PATH_KEYWORDS = Set.of(
            "/deprecated/", "/legacy/", "/old/", "-old", "-deprecated");

    /**
     * Path keywords that suggest a debug / internal / management endpoint.
     * Documentation paths ({@code /swagger}, {@code /api-docs},
     * {@code /openapi}) were removed: they are intentional published artefacts,
     * and Burp's native scanner already reports exposed API definitions.
     */
    private static final Set<String> DEBUG_PATH_KEYWORDS = Set.of(
            "/debug", "/test", "/dev", "/staging", "/_debug",
            "/internal", "/admin", "/actuator", "/metrics",
            "/health", "/status");

    private static final Set<String> VERSION_HEADER_NAMES = Set.of(
            "x-api-version", "api-version");

    private static final String ISSUE_BACKGROUND =
            "API9:2023 - Improper Inventory Management<br><br>" +
            "APIs expose more endpoints than traditional web applications. Without an " +
            "accurate inventory of hosts, versions, and exposed routes, deprecated and " +
            "internal endpoints can survive into production.";

    public InventoryManagementCheck(MontoyaApi api, EndpointRegistry endpoints, AiTriage triage) {
        super(api, endpoints, triage);
    }

    @Override
    public String checkName() {
        return "API9:2023 Improper Inventory Management";
    }

    @Override
    protected List<AuditIssue> audit(HttpRequestResponse rr) {
        if (!rr.hasResponse()) return List.of();

        List<AuditIssue> issues = new ArrayList<>();
        String path = rr.request().pathWithoutQuery();

        if (isDeprecatedPath(path)) issues.add(buildDeprecatedVersionIssue(rr, path));
        if (isDebugPath(path))      issues.add(buildDebugEndpointIssue(rr, path));

        String version = versionFromHeaders(rr);
        if (version != null)        issues.add(buildVersionDisclosureIssue(rr, version));

        return issues;
    }

    // ---- Detection ---------------------------------------------------------

    private static boolean isDeprecatedPath(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase(Locale.ROOT);
        for (Pattern p : DEPRECATED_PATH_PATTERNS) if (p.matcher(lower).matches()) return true;
        for (String keyword : DEPRECATED_PATH_KEYWORDS) if (lower.contains(keyword)) return true;
        return false;
    }

    private static boolean isDebugPath(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase(Locale.ROOT);
        for (String keyword : DEBUG_PATH_KEYWORDS) if (lower.contains(keyword)) return true;
        return false;
    }

    private static String versionFromHeaders(HttpRequestResponse rr) {
        for (HttpHeader header : rr.response().headers()) {
            String name = header.name() == null ? "" : header.name().toLowerCase(Locale.ROOT);
            if (VERSION_HEADER_NAMES.contains(name)) return header.value();
        }
        return null;
    }

    // ---- Issues ------------------------------------------------------------

    private AuditIssue buildDeprecatedVersionIssue(HttpRequestResponse rr, String path) {
        String safePath = IssueBuilder.escapeHtml(path);
        String detail =
                "Endpoint <code>" + safePath + "</code> appears to use a deprecated or legacy API " +
                "version. Old versions often miss security fixes that have been applied to the " +
                "current version.";
        String remediation =
                "Migrate clients to the current API version with a published sunset date for " +
                "the legacy version. Maintain a documented inventory of deployed versions.";
        return IssueBuilder.issue(rr)
                .name("API9:2023 - Improper Inventory Management (Deprecated API Version)")
                .detail(detail)
                .remediation(remediation)
                .background(ISSUE_BACKGROUND)
                .severity("Medium")
                .confidence("Tentative")
                .build();
    }

    private AuditIssue buildDebugEndpointIssue(HttpRequestResponse rr, String path) {
        String safePath = IssueBuilder.escapeHtml(path);
        String detail =
                "Endpoint <code>" + safePath + "</code> matches a debug / internal / management " +
                "path pattern (e.g. /debug, /actuator, /metrics, /internal). If reachable and " +
                "unprotected in production it can leak runtime configuration or grant " +
                "administrative actions.<br><br>" +
                "Detected from the path alone — some of these endpoints (health probes, status " +
                "pages) are intentional and may be access-controlled. Confirm whether this one " +
                "is meant to be exposed and whether it is protected.";
        String remediation =
                "If unintended, remove it from production. If intended (health probe, status), " +
                "restrict access (mTLS, VPN, IP allow-list) and confirm it leaks nothing " +
                "sensitive.";
        return IssueBuilder.issue(rr)
                .name("API9:2023 - Improper Inventory Management (Debug/Management Endpoint)")
                .detail(detail)
                .remediation(remediation)
                .background(ISSUE_BACKGROUND)
                .severity("Low")
                // Path-pattern heuristic only — Tentative, not Certain.
                .confidence("Tentative")
                .build();
    }

    private AuditIssue buildVersionDisclosureIssue(HttpRequestResponse rr, String version) {
        String detail =
                "The response advertises an API version in a header: <code>" +
                IssueBuilder.escapeHtml(version) +
                "</code>. Not directly exploitable, but it shortens an attacker's recon path.";
        String remediation =
                "Drop the version header from outbound responses or restrict it to trusted " +
                "internal callers.";
        return IssueBuilder.issue(rr)
                .name("API9:2023 - Improper Inventory Management (API Version Disclosure)")
                .detail(detail)
                .remediation(remediation)
                .background(ISSUE_BACKGROUND)
                .severity("Information")
                .confidence("Certain")
                .build();
    }
}
