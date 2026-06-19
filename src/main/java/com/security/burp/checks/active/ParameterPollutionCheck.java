package com.security.burp.checks.active;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointType;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.security.burp.checks.AbstractActiveCheck;
import com.security.burp.util.IssueBuilder;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;

/**
 * OWASP API10:2023 — HTTP Parameter Pollution (HPP).
 *
 * <p>For each URL or body-form parameter Burp identifies as an insertion
 * point, send a polluted request that contains the same parameter
 * <em>twice</em> — once with the original value, once with a marker
 * value — and compare the response against the original. If the
 * polluted response differs substantially (status code change, large
 * body-length delta), the server is reading the two values
 * inconsistently, which is the precondition for parameter-pollution
 * exploits (auth bypass, parameter overriding, cache poisoning).
 *
 * <p>Active check, registered {@code PER_INSERTION_POINT}. Targets only
 * {@code PARAM_URL} and {@code PARAM_BODY} — JSON, cookies, XML, and
 * multipart parameters do not have the same duplicate-name semantics.
 *
 * <p>Reported at {@code TENTATIVE} confidence: response differences are
 * a heuristic, not proof. Manual validation is needed to confirm the
 * inconsistency is actually exploitable (see VALIDATION_GUIDE.md).
 *
 * <p>Replaces the noisy third-party-reference detection that used to
 * cover API10 (per security-research feedback: Zak).
 */
public final class ParameterPollutionCheck extends AbstractActiveCheck {

    private static final Set<AuditInsertionPointType> SUPPORTED_TYPES = Set.of(
            AuditInsertionPointType.PARAM_URL,
            AuditInsertionPointType.PARAM_BODY);

    /** Pollution value. Chosen to be visually distinctive in evidence. */
    private static final String POLLUTION_MARKER = "polluted-by-bapi-scanner";

    /** Minimum body-length ratio for the responses to be considered meaningfully different. */
    private static final double BODY_LENGTH_DELTA_THRESHOLD = 0.30;

    private static final String ISSUE_BACKGROUND =
            "API10:2023 - Unsafe Consumption of APIs<br><br>" +
            "HTTP Parameter Pollution exploits inconsistent server-side handling of " +
            "duplicate-named parameters. Different frameworks read the first, the last, or " +
            "concatenate values — and when the server and an intermediary (proxy, WAF) " +
            "disagree, the inconsistency can be exploited for filter bypass, parameter " +
            "overriding, or access-control evasion.";

    public ParameterPollutionCheck(MontoyaApi api) {
        super(api);
    }

    @Override
    public String checkName() {
        return "API10:2023 HTTP Parameter Pollution";
    }

    @Override
    protected List<AuditIssue> audit(HttpRequestResponse rr, AuditInsertionPoint ip, Http http) {
        if (!SUPPORTED_TYPES.contains(ip.type())) return List.of();

        HttpRequest polluted = buildPollutedRequest(rr.request(), ip);
        if (polluted == null) return List.of();

        HttpRequestResponse pollutedResponse = sendOrNull(polluted, http);
        if (pollutedResponse == null || !pollutedResponse.hasResponse()) return List.of();
        if (!rr.hasResponse()) return List.of();

        int baseStatus = rr.response().statusCode();
        int pollutedStatus = pollutedResponse.response().statusCode();

        // The polluted request must SUCCEED for this to be interesting. A 4xx/5xx
        // means the server rejected the duplicate (or the injected value was
        // invalid for the parameter's type) — that is safe handling, not an
        // exploitable parsing inconsistency. In particular a 2xx->4xx transition
        // (e.g. orderId=123&orderId=<non-numeric> -> 400) is the server correctly
        // refusing bad input and must NOT fire.
        if (!isSuccess(pollutedStatus)) return List.of();

        // Polluted request succeeded. If the BASELINE did not succeed, the
        // duplicate parameter turned a rejected request into an accepted one —
        // a strong parameter-pollution / validation-bypass signal.
        if (!isSuccess(baseStatus)) {
            return List.of(buildIssue(rr, pollutedResponse, ip));
        }

        // Both succeeded: only meaningful if the body changed materially. That
        // signal is confounded by non-deterministic responses (timestamps,
        // UUIDs, nonces), so measure the endpoint's natural jitter with one
        // unmodified re-request and only fire if the pollution delta clearly
        // exceeds it.
        if (!bodyLengthDeltaExceedsJitter(rr, pollutedResponse, http)) {
            return List.of();
        }
        return List.of(buildIssue(rr, pollutedResponse, ip));
    }

    private static boolean isSuccess(int status) {
        return status >= 200 && status < 300;
    }

    /**
     * True if the polluted-vs-baseline body-length delta is both above the
     * threshold AND materially larger than the endpoint's own
     * request-to-request jitter (measured by re-sending the original request
     * once). Non-deterministic endpoints — fresh UUID/timestamp per response —
     * exhibit large natural jitter, so their pollution delta is discarded.
     */
    private boolean bodyLengthDeltaExceedsJitter(HttpRequestResponse base,
                                                 HttpRequestResponse polluted,
                                                 Http http) {
        int baseLen = lengthOrZero(base.response());
        int pollutedLen = lengthOrZero(polluted.response());
        double pollutionDelta = relativeDelta(baseLen, pollutedLen);
        if (pollutionDelta < BODY_LENGTH_DELTA_THRESHOLD) return false;

        HttpRequestResponse repeat = sendOrNull(base.request(), http);
        if (repeat == null || !repeat.hasResponse()) {
            // Can't measure jitter — be conservative and don't fire on length alone.
            return false;
        }
        double naturalJitter = relativeDelta(baseLen, lengthOrZero(repeat.response()));
        // Require the pollution delta to exceed natural jitter by a clear margin.
        return pollutionDelta >= naturalJitter + BODY_LENGTH_DELTA_THRESHOLD;
    }

    private static double relativeDelta(int a, int b) {
        int max = Math.max(a, b);
        if (max == 0) return 0.0;
        return (double) Math.abs(a - b) / max;
    }

    // ---- Request construction ----------------------------------------------

    /**
     * Append a duplicate of the parameter named {@code ip.name()} with the
     * {@link #POLLUTION_MARKER} value. Returns null if the parameter type
     * isn't a flavour we can manipulate via simple string substitution.
     */
    private HttpRequest buildPollutedRequest(HttpRequest base, AuditInsertionPoint ip) {
        String name = ip.name();
        if (name == null || name.isEmpty()) return null;
        String encodedAddition = urlEncode(name) + "=" + urlEncode(POLLUTION_MARKER);

        if (ip.type() == AuditInsertionPointType.PARAM_URL) {
            return base.withService(base.httpService())
                    .withPath(appendToQueryString(base.path(), encodedAddition));
        }
        if (ip.type() == AuditInsertionPointType.PARAM_BODY) {
            String body = base.bodyToString();
            String pollutedBody = body == null || body.isEmpty()
                    ? encodedAddition
                    : body + "&" + encodedAddition;
            return base.withBody(pollutedBody);
        }
        return null;
    }

    /** Append a {@code &k=v} segment to a path that may or may not already have a query string. */
    private static String appendToQueryString(String path, String encodedKeyValue) {
        if (path == null) return "?" + encodedKeyValue;
        int queryStart = path.indexOf('?');
        if (queryStart < 0) return path + "?" + encodedKeyValue;
        // Already has '?'. If it ends right after the '?', no separator needed.
        return queryStart == path.length() - 1
                ? path + encodedKeyValue
                : path + "&" + encodedKeyValue;
    }

    private static String urlEncode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    // ---- Response comparison -----------------------------------------------

    private static int lengthOrZero(HttpResponse response) {
        String body = response.bodyToString();
        return body == null ? 0 : body.length();
    }

    // ---- HTTP send ---------------------------------------------------------

    private HttpRequestResponse sendOrNull(HttpRequest request, Http http) {
        try {
            return http.sendRequest(request);
        } catch (Exception e) {
            api.logging().logToError("[Parameter Pollution] send failed: " + e.getMessage());
            return null;
        }
    }

    // ---- Issue construction ------------------------------------------------

    private AuditIssue buildIssue(HttpRequestResponse base,
                                  HttpRequestResponse polluted,
                                  AuditInsertionPoint ip) {
        int origStatus = base.response().statusCode();
        int pollStatus = polluted.response().statusCode();
        int origLen = lengthOrZero(base.response());
        int pollLen = lengthOrZero(polluted.response());

        String safeName = IssueBuilder.escapeHtml(ip.name());
        String detail =
                "Sending a duplicate of the <code>" + safeName + "</code> parameter " +
                "(<code>" + IssueBuilder.escapeHtml(POLLUTION_MARKER) + "</code>) produced a response that " +
                "differs from the baseline:<br><br>" +
                "<table border=\"0\" cellpadding=\"4\">" +
                "<tr><td><b>&nbsp;</b></td><td><b>Status</b></td><td><b>Body length</b></td></tr>" +
                "<tr><td>Baseline</td><td>" + origStatus + "</td><td>" + origLen + "</td></tr>" +
                "<tr><td>Polluted</td><td>" + pollStatus + "</td><td>" + pollLen + "</td></tr>" +
                "</table><br>" +
                "The server reads the two values for <code>" + safeName + "</code> differently. " +
                "If the parameter participates in authorization, filtering, or business logic, " +
                "an attacker who can pollute the parameter at the right layer may be able to " +
                "override the trusted value.";
        String remediation =
                "Decide on a single canonical handling for duplicate-named parameters (reject, " +
                "use first, use last) and enforce it consistently across the application stack " +
                "and any intermediaries. Reject duplicates at the framework level where " +
                "feasible.";
        return IssueBuilder.issue(base)
                .name("API10:2023 - HTTP Parameter Pollution")
                .detail(detail)
                .remediation(remediation)
                .background(ISSUE_BACKGROUND)
                .severity("Medium")
                .confidence("Tentative")
                .evidence(base, polluted)
                .build();
    }

}
