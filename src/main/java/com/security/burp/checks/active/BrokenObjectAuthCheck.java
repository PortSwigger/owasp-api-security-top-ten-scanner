package com.security.burp.checks.active;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.security.burp.checks.AbstractActiveCheck;
import com.security.burp.util.IssueBuilder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * OWASP API1:2023 — Broken Object Level Authorization (BOLA / IDOR).
 *
 * <p>Three sub-tests, all gated on the URL containing what looks like an
 * object identifier (numeric, UUID, or MongoDB ObjectID, optionally in a
 * query parameter):
 * <ol>
 *   <li><b>ID manipulation:</b> swap the numeric ID for a few other values
 *       and look for a 2xx;</li>
 *   <li><b>unauthenticated access:</b> strip authentication headers and
 *       look for a 2xx;</li>
 *   <li><b>sequential enumeration:</b> if multiple adjacent numeric IDs
 *       return 2xx, the namespace is enumerable.</li>
 * </ol>
 *
 * <p>Registered {@code PER_HOST}; deduped per (host + path).
 */
public final class BrokenObjectAuthCheck extends AbstractActiveCheck {

    private static final List<Pattern> ID_PATTERNS = List.of(
            Pattern.compile("/\\d+(?:/|$)"),
            Pattern.compile("/[a-f0-9]{24}(?:/|$)"),
            Pattern.compile("/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}(?:/|$)"),
            Pattern.compile("[?&]id=\\d+"),
            Pattern.compile("[?&]user_?id=\\d+"),
            Pattern.compile("[?&]account_?id=\\d+"));

    private static final Pattern NUMERIC_PATH_ID = Pattern.compile("/(\\d+)(?:/|$)");

    private static final int[] ID_TEST_VALUES = {1, 2, 100, 999};
    private static final int[] ENUMERATION_OFFSETS = {-2, -1, 1, 2};

    private static final Set<String> AUTH_HEADERS = Set.of(
            "authorization", "cookie", "x-api-key", "x-auth-token");

    private static final String ISSUE_BACKGROUND =
            "API1:2023 - Broken Object Level Authorization<br><br>" +
            "Endpoints that take an object identifier from the client must verify the caller " +
            "is authorized to access that object. Failures in this control are the most " +
            "common and impactful API vulnerability.";

    private final Set<String> dedupe = Collections.newSetFromMap(new ConcurrentHashMap<>());

    public BrokenObjectAuthCheck(MontoyaApi api) {
        super(api);
    }

    @Override
    public String checkName() {
        return "API1:2023 Broken Object Level Authorization";
    }

    @Override
    protected List<AuditIssue> audit(HttpRequestResponse rr, AuditInsertionPoint ip, Http http) {
        if (!shouldRunOnce(rr)) return List.of();
        if (!hasObjectIdentifier(rr.request().url())) return List.of();

        List<AuditIssue> issues = new ArrayList<>();
        addIfFound(issues, tryIdManipulation(rr, http), "id-manipulation", "Critical");
        addIfFound(issues, tryUnauthenticated(rr, http), "unauthenticated", "Critical");
        if (idEnumerable(rr, http)) issues.add(buildEnumerationIssue(rr));
        return issues;
    }

    private boolean shouldRunOnce(HttpRequestResponse rr) {
        String key = rr.request().httpService().host() + "|" + rr.request().pathWithoutQuery();
        return dedupe.add(key);
    }

    // ---- Detection helpers --------------------------------------------------

    private static boolean hasObjectIdentifier(String url) {
        if (url == null) return false;
        for (Pattern pattern : ID_PATTERNS) {
            if (pattern.matcher(url).find()) return true;
        }
        return false;
    }

    // ---- Sub-tests ---------------------------------------------------------

    private HttpRequestResponse tryIdManipulation(HttpRequestResponse rr, Http http) {
        Matcher matcher = NUMERIC_PATH_ID.matcher(rr.request().url());
        if (!matcher.find()) return null;
        int originalId = parseSilently(matcher.group(1));
        if (originalId < 0) return null;

        for (int candidate : ID_TEST_VALUES) {
            if (candidate == originalId || candidate <= 0) continue;
            HttpRequestResponse evidence = sendWithReplacedId(rr, http, originalId, candidate);
            if (evidence != null) return evidence;
        }
        return null;
    }

    private HttpRequestResponse tryUnauthenticated(HttpRequestResponse rr, Http http) {
        if (!hasAnyAuthHeader(rr.request())) return null;
        HttpRequest stripped = removeHeaders(rr.request(), AUTH_HEADERS);
        return sendIfSuccess(stripped, http);
    }

    private boolean idEnumerable(HttpRequestResponse rr, Http http) {
        Matcher matcher = NUMERIC_PATH_ID.matcher(rr.request().url());
        if (!matcher.find()) return false;
        int originalId = parseSilently(matcher.group(1));
        if (originalId < 0) return false;

        int hits = 0;
        for (int offset : ENUMERATION_OFFSETS) {
            int candidate = originalId + offset;
            if (candidate <= 0) continue;
            if (sendWithReplacedId(rr, http, originalId, candidate) != null) hits++;
            if (hits >= 2) return true;
        }
        return false;
    }

    // ---- Sending -----------------------------------------------------------

    private HttpRequestResponse sendWithReplacedId(HttpRequestResponse rr,
                                                   Http http,
                                                   int originalId,
                                                   int newId) {
        try {
            String oldUrl = rr.request().url();
            String newUrl = oldUrl.replaceFirst("/" + originalId + "(?=/|$)", "/" + newId);
            if (newUrl.equals(oldUrl)) return null;

            // httpRequestFromUrl already inserts a Host header derived from the
            // URL. Adding rr.request().headers() on top of that produces a
            // duplicate Host header — which some servers reject with 4xx,
            // making this whole check appear to find nothing. Re-attach every
            // original header except Host.
            HttpRequest mutated = HttpRequest.httpRequestFromUrl(newUrl)
                    .withMethod(rr.request().method())
                    .withBody(rr.request().bodyToString());
            for (HttpHeader header : rr.request().headers()) {
                if (header.name() != null && !"host".equalsIgnoreCase(header.name())) {
                    mutated = mutated.withAddedHeader(header);
                }
            }
            return sendIfSuccess(mutated, http);
        } catch (Exception e) {
            api.logging().logToError("[BOLA] sendWithReplacedId failed: " + e.getMessage());
            return null;
        }
    }

    private HttpRequestResponse sendIfSuccess(HttpRequest request, Http http) {
        try {
            HttpRequestResponse response = http.sendRequest(request);
            return (response != null && response.hasResponse() && isSuccess(response.response().statusCode()))
                    ? response : null;
        } catch (Exception e) {
            api.logging().logToError("[BOLA] send failed: " + e.getMessage());
            return null;
        }
    }

    private static boolean isSuccess(int status) { return status >= 200 && status < 300; }

    // ---- Header utilities --------------------------------------------------

    private static boolean hasAnyAuthHeader(HttpRequest request) {
        for (HttpHeader header : request.headers()) {
            if (header.name() != null
                    && AUTH_HEADERS.contains(header.name().toLowerCase(Locale.ROOT))) {
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

    private static int parseSilently(String s) {
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    // ---- Issues ------------------------------------------------------------

    private void addIfFound(List<AuditIssue> sink,
                            HttpRequestResponse evidence,
                            String mode,
                            String severity) {
        if (evidence != null) sink.add(buildAccessIssue(evidence, mode, severity));
    }

    private AuditIssue buildAccessIssue(HttpRequestResponse evidence, String mode, String severity) {
        String detail =
                "The endpoint returned a 2xx response under test condition <b>" + mode + "</b>:" +
                "<br><br>Endpoint: <code>" +
                IssueBuilder.escapeHtml(evidence.request().method()) + " " +
                IssueBuilder.escapeHtml(evidence.request().pathWithoutQuery()) +
                "</code>.<br><br>" +
                "Object-level authorization checks must verify the caller's right to the " +
                "specific object before returning data, on every request.";
        return IssueBuilder.issue(evidence)
                .name("API1:2023 - Broken Object Level Authorization")
                .detail(detail)
                .remediation("Verify ownership/membership of the requested object against the " +
                        "authenticated principal in the route handler.")
                .background(ISSUE_BACKGROUND)
                .severity(severity)
                .confidence("Firm")
                .evidence(evidence)
                .build();
    }

    private AuditIssue buildEnumerationIssue(HttpRequestResponse rr) {
        return IssueBuilder.issue(rr)
                .name("API1:2023 - Broken Object Level Authorization (Sequential ID Enumeration)")
                .detail("Multiple adjacent numeric IDs return 2xx responses. The object " +
                        "namespace is enumerable; combined with weak authorization, this " +
                        "enables bulk extraction.")
                .remediation("Use opaque identifiers (UUIDs) or scope identifiers per-tenant; " +
                        "rate-limit ID-bearing endpoints.")
                .background(ISSUE_BACKGROUND)
                .severity("Medium")
                .confidence("Firm")
                .build();
    }
}
