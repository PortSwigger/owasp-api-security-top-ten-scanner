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
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * OWASP API1:2023 — Broken Object Level Authorization (BOLA / IDOR).
 *
 * <p>Two sub-tests, both gated on the URL containing what looks like an
 * object identifier (numeric, UUID, or MongoDB ObjectID, optionally in a
 * query parameter), and both requiring a <em>content</em> comparison
 * against the baseline (a 2xx alone is not enough):
 * <ol>
 *   <li><b>ID manipulation:</b> swap the numeric ID for a few other values
 *       and fire only when a different object is returned;</li>
 *   <li><b>sequential enumeration:</b> if multiple adjacent numeric IDs
 *       each return a distinct object, the namespace is enumerable.</li>
 * </ol>
 *
 * <p>The earlier unauthenticated-access sub-test (strip auth headers, look
 * for a 2xx) stays removed as of v2.3.0 — the content-comparison rework
 * above is a genuine detection-quality improvement (a 2xx alone isn't
 * access), not just anti-duplication. The kept sub-tests still overlap the
 * native "Broken access control" check, so they cross-reference it below.
 * (If full parity with the native access-control coverage is wanted, the
 * unauthenticated sub-test can be restored — it lives on the {@code full}
 * branch history.)
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

        // ID manipulation and enumeration only. The unauthenticated-access
        // test was removed — that case is Burp's native "Broken access
        // control" issue (see README OWASP mapping); re-detecting it
        // duplicated the native scanner.
        //
        // Both sub-tests require a CONTENT comparison against the baseline,
        // not just a 2xx: a finding fires only when swapping the ID returns a
        // *different object* than the original request did. That distinguishes
        // "reached another resource" (the BOLA signal) from "same response /
        // ID ignored", and is what justifies Firm confidence on a single
        // observation (the human still confirms the two objects shouldn't be
        // cross-accessible).
        addIfFound(issues, tryIdManipulation(rr, http), "id manipulation");
        if (idEnumerable(rr, http)) issues.add(buildEnumerationIssue(rr));
        return issues;
    }

    private String baselineBody(HttpRequestResponse rr) {
        return rr.hasResponse() && rr.response().bodyToString() != null
                ? rr.response().bodyToString() : null;
    }

    /** A modified-ID response is evidence only if it returns different content. */
    private boolean returnedDifferentObject(HttpRequestResponse evidence, String baseline) {
        if (evidence == null) return false;
        String body = evidence.response().bodyToString();
        if (body == null || body.isEmpty()) return false;
        return baseline == null || !body.equals(baseline);
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

        String baseline = baselineBody(rr);
        for (int candidate : ID_TEST_VALUES) {
            if (candidate == originalId || candidate <= 0) continue;
            HttpRequestResponse evidence = sendWithReplacedId(rr, http, originalId, candidate);
            if (returnedDifferentObject(evidence, baseline)) return evidence;
        }
        return null;
    }

    private boolean idEnumerable(HttpRequestResponse rr, Http http) {
        Matcher matcher = NUMERIC_PATH_ID.matcher(rr.request().url());
        if (!matcher.find()) return false;
        int originalId = parseSilently(matcher.group(1));
        if (originalId < 0) return false;

        String baseline = baselineBody(rr);
        int hits = 0;
        for (int offset : ENUMERATION_OFFSETS) {
            int candidate = originalId + offset;
            if (candidate <= 0) continue;
            if (returnedDifferentObject(sendWithReplacedId(rr, http, originalId, candidate), baseline)) {
                hits++;
            }
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
            if (response == null || !response.hasResponse()) return null;
            if (!isSuccess(response.response().statusCode())) return null;
            // A 200 carrying an error/"not found"/"forbidden" body is the
            // server refusing access with a sloppy status code — not a
            // successful object read. Don't treat it as BOLA.
            if (HttpUtils.looksRejected(response.response())) return null;
            return response;
        } catch (Exception e) {
            api.logging().logToError("[BOLA] send failed: " + e.getMessage());
            return null;
        }
    }

    private static boolean isSuccess(int status) { return status >= 200 && status < 300; }

    // ---- Parsing -----------------------------------------------------------

    private static int parseSilently(String s) {
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    // ---- Issues ------------------------------------------------------------

    private void addIfFound(List<AuditIssue> sink, HttpRequestResponse evidence, String mode) {
        if (evidence != null) sink.add(buildAccessIssue(evidence, mode));
    }

    private AuditIssue buildAccessIssue(HttpRequestResponse evidence, String mode) {
        String detail =
                "Changing the object identifier (" + IssueBuilder.escapeHtml(mode) + ") returned a " +
                "<b>different object</b> than the original request — the response body differs " +
                "from the baseline.<br><br>Endpoint: <code>" +
                IssueBuilder.escapeHtml(evidence.request().method()) + " " +
                IssueBuilder.escapeHtml(evidence.request().pathWithoutQuery()) +
                "</code>.<br><br>" +
                "If the two objects belong to different users/tenants, this is Broken Object " +
                "Level Authorization. Confirm the returned object should not be accessible to " +
                "the original caller." +
                RELATED_CHECKS;
        return IssueBuilder.issue(evidence)
                .name("API1:2023 - Broken Object Level Authorization")
                .detail(detail)
                .remediation("Verify ownership/membership of the requested object against the " +
                        "authenticated principal in the route handler.")
                .background(ISSUE_BACKGROUND)
                .severity("High")
                .confidence("Firm")
                .evidence(evidence)
                .build();
    }

    private AuditIssue buildEnumerationIssue(HttpRequestResponse rr) {
        return IssueBuilder.issue(rr)
                .name("API1:2023 - Broken Object Level Authorization (Sequential ID Enumeration)")
                .detail("Multiple adjacent numeric IDs each return a <b>distinct object</b> " +
                        "(different response bodies). The object namespace is enumerable; " +
                        "combined with weak authorization this enables bulk extraction." +
                        RELATED_CHECKS)
                .remediation("Use opaque identifiers (UUIDs) or scope identifiers per-tenant; " +
                        "rate-limit ID-bearing endpoints.")
                .background(ISSUE_BACKGROUND)
                .severity("Medium")
                .confidence("Firm")
                .build();
    }

    /** Cross-reference to native Burp coverage (DAST-compatible; static). */
    private static final String RELATED_CHECKS =
            "<br><br><b>Related Burp Scanner checks:</b> for further detail refer to the native " +
            "<a href=\"https://portswigger.net/kb/issues/00100850_broken-access-control\">Broken access control</a> check.";
}
