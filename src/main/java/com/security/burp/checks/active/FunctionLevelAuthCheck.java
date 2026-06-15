package com.security.burp.checks.active;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.security.burp.checks.AbstractActiveCheck;
import com.security.burp.util.HttpUtils;
import com.security.burp.util.IssueBuilder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * OWASP API5:2023 — Broken Function Level Authorization.
 *
 * <p>Targets requests that look privileged (path keywords like
 * {@code /admin}, {@code /delete}, {@code /config}; or methods like
 * {@code PUT}/{@code PATCH}/{@code DELETE}). Two replays per request:
 * <ol>
 *   <li><b>without auth</b>: strip Authorization / Cookie / API-key headers
 *       and look for a 2xx;</li>
 *   <li><b>with low-privilege role hint</b>: set
 *       {@code X-User-Role: user} and look for a 2xx.</li>
 * </ol>
 *
 * <p>Registered {@code PER_HOST}; deduped per (host + method + path).
 */
public final class FunctionLevelAuthCheck extends AbstractActiveCheck {

    private static final Set<String> PRIVILEGED_PATH_KEYWORDS = Set.of(
            "admin", "administrator", "superuser", "root",
            "delete", "remove", "destroy", "drop",
            "approve", "reject", "verify",
            "config", "configuration", "settings",
            "logs", "audit", "monitor",
            "users", "accounts", "permissions", "roles");

    private static final Set<String> PRIVILEGED_METHODS = Set.of("DELETE", "PUT", "PATCH");

    private static final Set<String> AUTH_HEADER_NAMES = Set.of(
            "authorization", "cookie", "x-api-key", "x-auth-token");

    private static final Set<String> ROLE_HEADER_NAMES = Set.of(
            "x-user-role", "x-role", "role");

    private static final String LOW_PRIV_ROLE_VALUE = "user";

    private static final String ISSUE_BACKGROUND =
            "API5:2023 - Broken Function Level Authorization<br><br>" +
            "Complex access-control policies and unclear separation between administrative " +
            "and regular functions tend to leave privileged endpoints accessible to lower " +
            "privilege actors. The result is administrative actions reachable by users that " +
            "should not be able to invoke them.";

    private final Set<String> dedupe = Collections.newSetFromMap(new ConcurrentHashMap<>());

    public FunctionLevelAuthCheck(MontoyaApi api) {
        super(api);
    }

    @Override
    public String checkName() {
        return "API5:2023 Broken Function Level Authorization";
    }

    @Override
    protected List<AuditIssue> audit(HttpRequestResponse rr, AuditInsertionPoint ip, Http http) {
        if (!shouldRunOnce(rr)) return List.of();
        if (!looksPrivileged(rr.request())) return List.of();

        List<AuditIssue> issues = new ArrayList<>();
        addIfFound(issues, tryWithoutAuth(rr, http), "no authentication required");
        addIfFound(issues, tryWithLowPrivilegeRole(rr, http), "accessible with low-privilege role (X-User-Role: user)");
        return issues;
    }

    private boolean shouldRunOnce(HttpRequestResponse rr) {
        String key = rr.request().httpService().host() + "|" +
                rr.request().method() + "|" +
                rr.request().pathWithoutQuery();
        return dedupe.add(key);
    }

    // ---- Privileged-endpoint detection -------------------------------------

    private static boolean looksPrivileged(HttpRequest request) {
        if (PRIVILEGED_METHODS.contains(request.method())) return true;
        String path = request.pathWithoutQuery();
        if (path == null) return false;
        String lower = path.toLowerCase(Locale.ROOT);
        for (String keyword : PRIVILEGED_PATH_KEYWORDS) {
            if (lower.contains(keyword)) return true;
        }
        return false;
    }

    // ---- Replays -----------------------------------------------------------

    private HttpRequestResponse tryWithoutAuth(HttpRequestResponse rr, Http http) {
        if (!hasAnyAuthHeader(rr.request())) return null;
        HttpRequest stripped = removeHeaders(rr.request(), AUTH_HEADER_NAMES);
        return sendOrNull(stripped, http);
    }

    private HttpRequestResponse tryWithLowPrivilegeRole(HttpRequestResponse rr, Http http) {
        HttpRequest mutated = removeHeaders(rr.request(), ROLE_HEADER_NAMES)
                .withAddedHeader("X-User-Role", LOW_PRIV_ROLE_VALUE);
        return sendOrNull(mutated, http);
    }

    private static boolean hasAnyAuthHeader(HttpRequest request) {
        for (HttpHeader header : request.headers()) {
            if (header.name() != null
                    && AUTH_HEADER_NAMES.contains(header.name().toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    private static HttpRequest removeHeaders(HttpRequest request, Set<String> namesLower) {
        HttpRequest result = request;
        for (HttpHeader header : request.headers()) {
            if (header.name() != null
                    && namesLower.contains(header.name().toLowerCase(Locale.ROOT))) {
                result = result.withRemovedHeader(header);
            }
        }
        return result;
    }

    private HttpRequestResponse sendOrNull(HttpRequest request, Http http) {
        try {
            HttpRequestResponse response = http.sendRequest(request);
            if (response == null || !response.hasResponse()) return null;
            if (!isSuccess(response.response().statusCode())) return null;
            // A 2xx whose body is an error/"unauthorized"/"forbidden" message
            // means authorization actually held (the server just used a sloppy
            // status code). Don't count it as the privileged action succeeding.
            if (HttpUtils.looksRejected(response.response())) return null;
            return response;
        } catch (Exception e) {
            api.logging().logToError("[Function Level Auth] Send failed: " + e.getMessage());
            return null;
        }
    }

    private static boolean isSuccess(int status) {
        return status >= 200 && status < 300;
    }

    private void addIfFound(List<AuditIssue> sink,
                            HttpRequestResponse evidence,
                            String condition) {
        if (evidence != null) sink.add(buildIssue(evidence, condition));
    }

    // ---- Issues ------------------------------------------------------------

    private AuditIssue buildIssue(HttpRequestResponse evidence, String condition) {
        String detail =
                "A privileged endpoint returned a 2xx response under the test condition: " +
                "<b>" + condition + "</b>.<br><br>" +
                "Endpoint: <code>" + IssueBuilder.escapeHtml(evidence.request().method()) + " " +
                IssueBuilder.escapeHtml(evidence.request().pathWithoutQuery()) + "</code><br><br>" +
                "Privileged endpoints (admin paths, destructive verbs) must enforce role " +
                "checks server-side on every invocation.";
        String remediation =
                "Reject the request if the caller lacks the required role. Apply checks at the " +
                "framework or middleware layer rather than per route to avoid omissions.";
        return IssueBuilder.issue(evidence)
                .name("API5:2023 - Broken Function Level Authorization")
                .detail(detail)
                .remediation(remediation)
                .background(ISSUE_BACKGROUND)
                .severity("High")
                .confidence("Firm")
                .evidence(evidence)
                .build();
    }
}
