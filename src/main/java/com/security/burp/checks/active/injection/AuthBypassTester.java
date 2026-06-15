package com.security.burp.checks.active.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import com.security.burp.util.IssueBuilder;

import java.util.List;
import java.util.Locale;

/**
 * Targeted SQL-injection test for authentication endpoints.
 *
 * <p>If a POST request to a path containing {@code /login} or {@code /auth}
 * carries a JSON body with username and password fields, replace the
 * password with classic SQL bypass payloads and look for either a 200
 * response that contains a token (auth bypass) or a SQL-error string in
 * the response (information leak).
 *
 * <p>Findings here are critical and tested first — when one fires the
 * caller should skip generic per-insertion-point testing for this request.
 */
public final class AuthBypassTester {

    private static final List<String> AUTH_PATH_KEYWORDS = List.of(
            "/login", "/auth", "/signin", "/token", "/authenticate");

    private static final List<String> USERNAME_FIELD_NAMES = List.of(
            "username", "user", "email", "login", "account");

    private static final List<String> PASSWORD_FIELD_NAMES = List.of(
            "password", "pass", "pwd", "secret", "credentials");

    /**
     * Markers in a 200 response that suggest authentication SUCCEEDED. Kept
     * specific to positive-success shapes — broad words like "logged" or
     * "authenticated" were removed because they appear in failure messages
     * ("not logged in", "not authenticated"), producing false Critical
     * findings on rejected logins.
     */
    private static final List<String> SUCCESS_MARKERS = List.of(
            "\"token\"", "\"access_token\"", "\"accesstoken\"", "\"jwt\"",
            "\"success\":true", "\"success\": true",
            "\"authenticated\":true", "\"authenticated\": true",
            "set-cookie");

    /** Phrases that indicate the login FAILED — used to veto a success match. */
    private static final List<String> FAILURE_MARKERS = List.of(
            "invalid", "incorrect", "failed", "denied", "not authenticated",
            "not logged", "unauthor", "bad credentials", "error");

    private static final String ISSUE_BACKGROUND =
            "API2:2023 - Broken Authentication<br><br>" +
            "Authentication mechanisms are often implemented incorrectly. SQL injection in " +
            "the credential check leads to complete authentication bypass.";

    private final MontoyaApi api;

    public AuthBypassTester(MontoyaApi api) {
        this.api = api;
    }

    public boolean isAuthEndpoint(HttpRequest request) {
        if (!"POST".equals(request.method())) return false;
        String path = request.pathWithoutQuery();
        if (path == null) return false;
        String lower = path.toLowerCase(Locale.ROOT);
        for (String keyword : AUTH_PATH_KEYWORDS) {
            if (lower.contains(keyword)) return true;
        }
        return false;
    }

    /**
     * Run the bypass probe. Returns the first finding (auth bypass or SQL
     * error leak) or {@code null} if none of the payloads triggered either.
     */
    public AuditIssue test(HttpRequestResponse rr, Http http) {
        JsonObject body = parseBody(rr.request().bodyToString());
        if (body == null) return null;

        String userField = firstPresentField(body, USERNAME_FIELD_NAMES);
        String passField = firstPresentField(body, PASSWORD_FIELD_NAMES);
        if (userField == null || passField == null) return null;

        api.logging().logToOutput("[Injection] Auth-endpoint SQL probes on " +
                rr.request().pathWithoutQuery());

        // Baseline: the original (un-injected) login response. A success marker
        // already present here proves nothing about our payload.
        String baselineLower = rr.hasResponse() && rr.response().bodyToString() != null
                ? rr.response().bodyToString().toLowerCase(Locale.ROOT)
                : "";

        for (String payload : InjectionPayloads.SQL) {
            JsonObject mutated = body.deepCopy();
            mutated.addProperty(userField, "admin");
            mutated.addProperty(passField, payload);
            HttpRequestResponse evidence = sendBody(rr, http, mutated.toString());
            if (evidence == null) continue;

            String responseBodyLower = evidence.response().bodyToString().toLowerCase(Locale.ROOT);
            int status = evidence.response().statusCode();

            // Bypass only if: 200, a positive success marker is present, that
            // marker is NEW vs the baseline login response, and the body does
            // not also carry a failure indicator.
            if (status == 200
                    && containsAnyNotInBaseline(responseBodyLower, baselineLower, SUCCESS_MARKERS)
                    && !containsAny(responseBodyLower, FAILURE_MARKERS)) {
                return buildBypassIssue(rr, evidence, passField, payload);
            }
            // SQL-error leak: only if the error string is NEW vs the baseline
            // (an error page that always contains a SQL keyword isn't proof).
            if (containsAnyNotInBaseline(responseBodyLower, baselineLower, InjectionPayloads.SQL_ERROR_MARKERS)) {
                return buildSqlErrorIssue(rr, evidence, passField, payload);
            }
        }
        return null;
    }

    private static boolean containsAnyNotInBaseline(String body, String baseline, List<String> needles) {
        for (String n : needles) {
            if (body.contains(n) && !baseline.contains(n)) return true;
        }
        return false;
    }

    // ---- Helpers -----------------------------------------------------------

    private static JsonObject parseBody(String body) {
        if (body == null || body.isEmpty()) return null;
        try {
            JsonElement element = JsonParser.parseString(body);
            return element.isJsonObject() ? element.getAsJsonObject() : null;
        } catch (JsonSyntaxException e) {
            return null;
        }
    }

    private static String firstPresentField(JsonObject obj, List<String> candidates) {
        for (String candidate : candidates) {
            if (obj.has(candidate)) return candidate;
        }
        return null;
    }

    private static boolean containsAny(String haystack, List<String> needles) {
        for (String needle : needles) if (haystack.contains(needle)) return true;
        return false;
    }

    private HttpRequestResponse sendBody(HttpRequestResponse rr, Http http, String body) {
        try {
            HttpRequest mutated = rr.request().withBody(body);
            HttpRequestResponse response = http.sendRequest(mutated);
            return (response != null && response.hasResponse()) ? response : null;
        } catch (Exception e) {
            api.logging().logToError("[Injection] auth-endpoint send failed: " + e.getMessage());
            return null;
        }
    }

    // ---- Issues ------------------------------------------------------------

    private AuditIssue buildBypassIssue(HttpRequestResponse base,
                                        HttpRequestResponse evidence,
                                        String field,
                                        String payload) {
        String detail =
                "Sending the SQL payload <code>" + IssueBuilder.escapeHtml(payload) + "</code> in the " +
                "<code>" + IssueBuilder.escapeHtml(field) + "</code> field returned a 200 response containing tokens / " +
                "success markers. This is consistent with a SQL-injection authentication bypass.";
        return IssueBuilder.issue(base)
                .name("API2:2023 - Broken Authentication (SQL Injection Auth Bypass)")
                .detail(detail)
                .remediation("Use parameterised queries; never concatenate user input into SQL.")
                .background(ISSUE_BACKGROUND)
                .severity("Critical")
                .confidence("Firm")
                .evidence(base, evidence)
                .build();
    }

    private AuditIssue buildSqlErrorIssue(HttpRequestResponse base,
                                          HttpRequestResponse evidence,
                                          String field,
                                          String payload) {
        String detail =
                "The SQL payload <code>" + IssueBuilder.escapeHtml(payload) + "</code> in <code>" +
                IssueBuilder.escapeHtml(field) +
                "</code> caused the server to return a SQL-engine error message. The error " +
                "leak is itself a finding and strongly indicates an injectable code path.";
        return IssueBuilder.issue(base)
                .name("API2:2023 - Broken Authentication (SQL Error Leak in Auth Endpoint)")
                .detail(detail)
                .remediation("Use parameterised queries; suppress detailed engine errors in " +
                        "responses.")
                .background(ISSUE_BACKGROUND)
                .severity("High")
                .confidence("Firm")
                .evidence(base, evidence)
                .build();
    }

}
