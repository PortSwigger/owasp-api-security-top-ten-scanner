package com.security.burp.checks.active;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.security.burp.checks.AbstractActiveCheck;
import com.security.burp.util.HttpUtils;
import com.security.burp.util.IssueBuilder;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * OWASP API7:2023 — Server-Side Request Forgery.
 *
 * <p>Targets parameters whose name suggests they carry a URL or host
 * (e.g. {@code url}, {@code callback}, {@code redirect}, {@code webhook},
 * {@code target}). Mutates each candidate insertion point with payloads
 * that, if reflected back in the response, indicate the server fetched
 * the attacker-controlled URL.
 *
 * <p>Registered as {@code PER_INSERTION_POINT}, so this check runs once
 * per insertion point Burp identifies in the base request.
 */
public final class SsrfCheck extends AbstractActiveCheck {

    /** Heuristic: parameter names likely to carry URLs / hosts. */
    private static final Set<String> URL_LIKE_PARAM_NAMES = Set.of(
            "url", "uri", "link", "href", "src", "source",
            "target", "destination", "redirect", "redirect_uri",
            "callback", "webhook", "endpoint", "host", "address");

    /**
     * Payloads designed to evidence SSRF when reflected. Each payload's
     * marker string is also unique enough to grep for in the response
     * (rejecting spurious echoes of the original input).
     */
    private static final List<Payload> PAYLOADS = List.of(
            new Payload("http://127.0.0.1/", "127.0.0.1"),
            new Payload("http://localhost/",  "localhost"),
            new Payload("http://169.254.169.254/latest/meta-data/", "meta-data"),  // AWS IMDS
            new Payload("http://metadata.google.internal/",          "metadata.google"), // GCP
            new Payload("file:///etc/passwd",                        "root:x:0:0"));

    private static final String ISSUE_NAME = "API7:2023 - Server-Side Request Forgery";

    private static final String ISSUE_BACKGROUND =
            "API7:2023 - Server-Side Request Forgery<br><br>" +
            "An SSRF flaw allows an attacker to coerce the server into making HTTP " +
            "requests to attacker-chosen destinations, including cloud metadata services " +
            "and internal-only endpoints.";

    private static final String ISSUE_REMEDIATION =
            "Validate URL-bearing parameters against an allow-list of permitted hosts. " +
            "Disable {@code file://} and other non-HTTP schemes. Block requests to private " +
            "address space and to cloud-instance metadata IPs (169.254.169.254, etc.).";

    public SsrfCheck(MontoyaApi api) {
        super(api);
    }

    @Override
    public String checkName() {
        return ISSUE_NAME;
    }

    @Override
    protected List<AuditIssue> audit(HttpRequestResponse rr, AuditInsertionPoint ip, Http http) {
        if (!isUrlLikeParameter(ip)) return List.of();

        List<AuditIssue> issues = new ArrayList<>();
        for (Payload payload : PAYLOADS) {
            // If the marker is already in the baseline response (e.g. docs that
            // mention root:x:0:0, or a page that names the IMDS host), its
            // presence after the payload proves nothing — skip this payload.
            if (HttpUtils.baselineContains(rr, payload.marker)) continue;

            HttpRequestResponse evidence = sendPayload(rr, ip, http, payload);
            if (evidence != null && responseSuggestsSsrf(evidence, payload)) {
                issues.add(buildIssue(rr, evidence, ip, payload));
                break; // One finding per insertion point is enough.
            }
        }
        return issues;
    }

    // ---- Detection helpers --------------------------------------------------

    private static boolean isUrlLikeParameter(AuditInsertionPoint ip) {
        String name = ip.name();
        if (name == null) return false;
        return URL_LIKE_PARAM_NAMES.contains(name.toLowerCase(Locale.ROOT));
    }

    private HttpRequestResponse sendPayload(HttpRequestResponse rr,
                                            AuditInsertionPoint ip,
                                            Http http,
                                            Payload payload) {
        try {
            HttpRequest mutated = ip.buildHttpRequestWithPayload(
                    burp.api.montoya.core.ByteArray.byteArray(payload.value));
            return http.sendRequest(mutated);
        } catch (Exception e) {
            api.logging().logToError("[SSRF] Sending payload failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Fire only when the marker appears in a response the server actually
     * produced for our payload — not a 4xx validation error that simply
     * echoes the rejected URL back (e.g. OAuth "redirect_uri is not
     * whitelisted"). A genuine SSRF surfaces fetched content in a 2xx (or a
     * 3xx the server followed), not in a client-error rejection.
     */
    private static boolean responseSuggestsSsrf(HttpRequestResponse evidence, Payload payload) {
        if (evidence == null || !evidence.hasResponse()) return false;
        HttpResponse response = evidence.response();
        int status = response.statusCode();
        if (status >= 400) return false;          // validation error / rejection, not a fetch
        if (HttpUtils.looksRejected(response)) return false;
        String body = response.bodyToString();
        return body != null && body.contains(payload.marker);
    }

    // ---- Issue construction -------------------------------------------------

    private AuditIssue buildIssue(HttpRequestResponse base,
                                  HttpRequestResponse evidence,
                                  AuditInsertionPoint ip,
                                  Payload payload) {
        String detail =
                "Parameter <code>" + IssueBuilder.escapeHtml(ip.name()) + "</code> appears vulnerable to SSRF. " +
                "Submitting <code>" + IssueBuilder.escapeHtml(payload.value) + "</code> caused the " +
                "response to contain the marker <code>" + IssueBuilder.escapeHtml(payload.marker) + "</code>, " +
                "indicating the server fetched the attacker-controlled URL.<br><br>" +
                "<b>Why this matters:</b> SSRF can be escalated to read cloud-instance metadata, " +
                "scan internal networks, or exfiltrate files (<code>file://</code> scheme).";

        return IssueBuilder.issue(base)
                .name(ISSUE_NAME)
                .detail(detail)
                .remediation(ISSUE_REMEDIATION)
                .background(ISSUE_BACKGROUND)
                .severity("High")
                .confidence("Firm")
                .evidence(base, evidence)
                .build();
    }

    // ---- Payload record ----------------------------------------------------

    private record Payload(String value, String marker) {}
}
