package com.security.burp.checks.active;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.security.burp.checks.AbstractActiveCheck;
import com.security.burp.util.IssueBuilder;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * OWASP API8:2023 — Cross-Site Tracing (XST) via TRACE.
 *
 * <p>Originally a broad HTTP-method-fuzzing check that also reported
 * "unexpected method accepted" and "OPTIONS Allow disclosure" findings.
 * Both proved noisy on real targets (Zak, security research): non-405
 * responses on unsupported verbs are extremely common and rarely
 * exploitable, and OPTIONS allow disclosure is by design on many APIs.
 *
 * <p>Trimmed to just the one detection that genuinely indicates a
 * misconfiguration on a modern API: TRACE returning 200, which enables
 * Cross-Site Tracing.
 *
 * <p>Registered {@code PER_HOST}; deduped per (host + path).
 */
public final class MethodFuzzingCheck extends AbstractActiveCheck {

    private static final String API8_BACKGROUND =
            "API8:2023 - Security Misconfiguration<br><br>" +
            "TRACE echoes the request and can be exploited (Cross-Site Tracing) to " +
            "exfiltrate sensitive headers — including HTTPOnly cookies — that are " +
            "otherwise inaccessible to JavaScript.";

    /** Distinctive marker used to confirm TRACE actually echoes the request. */
    private static final String XST_MARKER_HEADER = "X-Bapi-Xst-Probe";
    private static final String XST_MARKER_VALUE = "bapi-xst-7f3c2a";

    private final Set<String> dedupe = Collections.newSetFromMap(new ConcurrentHashMap<>());

    public MethodFuzzingCheck(MontoyaApi api) {
        super(api);
    }

    @Override
    public String checkName() {
        return "API8:2023 TRACE / Cross-Site Tracing";
    }

    @Override
    protected List<AuditIssue> audit(HttpRequestResponse rr, AuditInsertionPoint ip, Http http) {
        if (!shouldRunOnce(rr)) return List.of();

        HttpRequestResponse evidence = sendTrace(rr.request(), http);
        if (evidence == null || !evidence.hasResponse()) return List.of();
        if (evidence.response().statusCode() != 200) return List.of();

        // XST requires the TRACE response to ECHO the request back to the
        // client — that's the whole exploit. A 200 that doesn't reflect our
        // marker header (e.g. a WAF/proxy returning a canned 200) is not
        // exploitable, so don't report it.
        String body = evidence.response().bodyToString();
        if (body == null || !body.contains(XST_MARKER_VALUE)) return List.of();

        return List.of(buildTraceIssue(rr, evidence));
    }

    private boolean shouldRunOnce(HttpRequestResponse rr) {
        String key = rr.request().httpService().host() + "|" + rr.request().pathWithoutQuery();
        return dedupe.add(key);
    }

    private HttpRequestResponse sendTrace(HttpRequest base, Http http) {
        try {
            // Add a distinctive marker header; if TRACE echoes the request,
            // the marker will appear in the response body (XST confirmation).
            HttpRequest trace = base.withMethod("TRACE").withBody("")
                    .withAddedHeader(XST_MARKER_HEADER, XST_MARKER_VALUE);
            return http.sendRequest(trace);
        } catch (Exception e) {
            api.logging().logToError("[TRACE] send failed: " + e.getMessage());
            return null;
        }
    }

    private AuditIssue buildTraceIssue(HttpRequestResponse base, HttpRequestResponse evidence) {
        String detail =
                "The endpoint responded to HTTP TRACE with 200. TRACE echoes the request and " +
                "can be exploited via Cross-Site Tracing to bypass HTTPOnly cookie " +
                "protections and exfiltrate sensitive headers.";
        return IssueBuilder.issue(base)
                .name("API8:2023 - Security Misconfiguration (TRACE Enabled — XST Risk)")
                .detail(detail)
                .remediation("Disable TRACE at the web server / framework level.")
                .background(API8_BACKGROUND)
                .severity("Medium")
                .confidence("Certain")
                .evidence(base, evidence)
                .build();
    }
}
