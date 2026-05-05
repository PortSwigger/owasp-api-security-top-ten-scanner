package com.security.burp.checks.active;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.security.burp.checks.AbstractActiveCheck;
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
            HttpRequestResponse evidence = sendPayload(rr, ip, http, payload);
            if (evidence != null && responseSuggestsSsrf(evidence.response(), payload)) {
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

    private static boolean responseSuggestsSsrf(HttpResponse response, Payload payload) {
        if (response == null) return false;
        String body = response.bodyToString();
        return body != null && body.contains(payload.marker);
    }

    // ---- Issue construction -------------------------------------------------

    private AuditIssue buildIssue(HttpRequestResponse base,
                                  HttpRequestResponse evidence,
                                  AuditInsertionPoint ip,
                                  Payload payload) {
        String detail =
                "Parameter <code>" + ip.name() + "</code> appears vulnerable to SSRF. " +
                "Submitting <code>" + escapeHtml(payload.value) + "</code> caused the " +
                "response to contain the marker <code>" + escapeHtml(payload.marker) + "</code>, " +
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

    private static String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }

    // ---- Payload record ----------------------------------------------------

    private record Payload(String value, String marker) {}
}
