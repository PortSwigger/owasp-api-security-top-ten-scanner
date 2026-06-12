package com.security.burp.checks.passive;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.security.burp.ai.AiTriage;
import com.security.burp.checks.AbstractPassiveCheck;
import com.security.burp.scanner.EndpointRegistry;
import com.security.burp.util.IssueBuilder;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * OWASP API8:2023 — Security Misconfiguration.
 *
 * <p>Five passive sub-checks, run independently:
 * <ul>
 *   <li>missing recommended security headers;</li>
 *   <li>presence of information-disclosure headers (Server, X-Powered-By, ...);</li>
 *   <li>CORS misconfiguration (wildcard origin, wildcard with credentials,
 *       reflected origin);</li>
 *   <li>API served over unencrypted HTTP;</li>
 *   <li>verbose error messages on 4xx/5xx responses.</li>
 * </ul>
 */
public final class SecurityMisconfigCheck extends AbstractPassiveCheck {

    private static final Map<String, String> RECOMMENDED_HEADERS = new LinkedHashMap<>();
    static {
        RECOMMENDED_HEADERS.put("X-Content-Type-Options",     "nosniff");
        RECOMMENDED_HEADERS.put("X-Frame-Options",            "DENY or SAMEORIGIN");
        RECOMMENDED_HEADERS.put("Content-Security-Policy",    "restrictive policy");
        RECOMMENDED_HEADERS.put("Strict-Transport-Security",  "max-age value");
    }

    /**
     * Headers that disclose technology / version information, paired with a
     * pattern the value must match before the finding fires.
     *
     * <p>Naive presence-based detection (Zak, security research) generates
     * a lot of noise on real targets — every CDN sets <code>Server:
     * cloudflare</code>, every static-content host returns a generic
     * <code>Server</code> value. Only fire on values that genuinely
     * disclose a versioned product, or on headers whose only purpose is
     * tech-stack disclosure (X-Powered-By and friends).
     *
     * <p>Pattern reference:
     * <a href="https://github.com/augustd/burp-suite-software-version-checks/blob/master/src/main/resources/burp/match-rules.tab">burp-suite-software-version-checks</a>.
     */
    private static final Pattern VERSIONED = Pattern.compile(".+/[\\d.]+.*");
    private static final Pattern ANY_VALUE = Pattern.compile(".+");

    private static final Map<String, DisclosurePattern> DISCLOSURE_PATTERNS = new LinkedHashMap<>();
    static {
        DISCLOSURE_PATTERNS.put("server",              new DisclosurePattern(VERSIONED, "Server version"));
        DISCLOSURE_PATTERNS.put("x-powered-by",        new DisclosurePattern(ANY_VALUE, "X-Powered-By technology"));
        DISCLOSURE_PATTERNS.put("x-aspnet-version",    new DisclosurePattern(ANY_VALUE, "ASP.NET version"));
        DISCLOSURE_PATTERNS.put("x-aspnetmvc-version", new DisclosurePattern(ANY_VALUE, "ASP.NET MVC version"));
        DISCLOSURE_PATTERNS.put("x-runtime",           new DisclosurePattern(ANY_VALUE, "Runtime version"));
        DISCLOSURE_PATTERNS.put("x-version",           new DisclosurePattern(ANY_VALUE, "Application version"));
        DISCLOSURE_PATTERNS.put("x-generator",         new DisclosurePattern(ANY_VALUE, "Framework generator"));
    }

    private record DisclosurePattern(Pattern valueMatch, String label) {}

    /** Phrases in a 4xx/5xx response body that suggest a verbose error. */
    private static final Set<String> ERROR_LEAK_MARKERS = Set.of(
            "stack trace", "stacktrace", "traceback",
            "at line", "exception in thread", "caused by:");

    private static final String ISSUE_BACKGROUND =
            "API8:2023 - Security Misconfiguration<br><br>" +
            "APIs and supporting systems typically contain complex configurations, meant " +
            "to make them customizable. Configuration mistakes — missing security headers, " +
            "permissive CORS, plaintext transport, verbose errors — open the door to a " +
            "wide range of attacks.";

    public SecurityMisconfigCheck(MontoyaApi api, EndpointRegistry endpoints, AiTriage triage) {
        super(api, endpoints, triage);
    }

    @Override
    public String checkName() {
        return "API8:2023 Security Misconfiguration";
    }

    @Override
    protected List<AuditIssue> audit(HttpRequestResponse rr) {
        if (!rr.hasResponse()) return List.of();

        List<AuditIssue> issues = new ArrayList<>();
        addMissingHeadersIssue(rr, issues);
        addDisclosureHeadersIssue(rr, issues);
        addCorsIssues(rr, issues);
        addInsecureProtocolIssue(rr, issues);
        addVerboseErrorIssue(rr, issues);
        return issues;
    }

    // ---- Sub-checks --------------------------------------------------------

    private void addMissingHeadersIssue(HttpRequestResponse rr, List<AuditIssue> sink) {
        Set<String> presentLower = headerNamesLowercase(rr.response());
        List<String> missing = new ArrayList<>();
        for (String header : RECOMMENDED_HEADERS.keySet()) {
            if (!presentLower.contains(header.toLowerCase(Locale.ROOT))) missing.add(header);
        }
        if (!missing.isEmpty()) sink.add(buildMissingHeadersIssue(rr, missing));
    }

    private void addDisclosureHeadersIssue(HttpRequestResponse rr, List<AuditIssue> sink) {
        List<String> found = new ArrayList<>();
        for (HttpHeader header : rr.response().headers()) {
            String headerName = header.name();
            if (headerName == null) continue;
            DisclosurePattern pattern = DISCLOSURE_PATTERNS.get(headerName.toLowerCase(Locale.ROOT));
            if (pattern == null) continue;
            String value = header.value();
            if (value == null) continue;
            if (pattern.valueMatch().matcher(value).matches()) {
                found.add(IssueBuilder.escapeHtml(headerName + ": " + value));
            }
        }
        if (!found.isEmpty()) sink.add(buildDisclosureHeadersIssue(rr, found));
    }

    private void addCorsIssues(HttpRequestResponse rr, List<AuditIssue> sink) {
        String origin = headerValue(rr.response(), "access-control-allow-origin");
        if (origin == null) return;

        if ("*".equals(origin)) {
            String creds = headerValue(rr.response(), "access-control-allow-credentials");
            if ("true".equalsIgnoreCase(creds)) {
                sink.add(buildCorsCredentialsIssue(rr));
            } else {
                sink.add(buildCorsWildcardIssue(rr));
            }
        }

        String requestOrigin = headerValue(rr.request(), "origin");
        if (requestOrigin != null && requestOrigin.equals(origin)) {
            sink.add(buildCorsReflectedIssue(rr, requestOrigin));
        }
    }

    /**
     * Flags an API served over cleartext HTTP — but ONLY when the server
     * actually processes the request over HTTP (a 2xx response). A server
     * that answers an http:// request with a 3xx redirect to the https://
     * equivalent is enforcing HTTPS correctly, not misconfigured; firing on
     * that is a false positive (confirmed against brokencrystals.com, where
     * an nginx 308 redirect to HTTPS was wrongly flagged High/Certain and
     * Burp's own AI returned an "Inconclusive" outcome).
     */
    private void addInsecureProtocolIssue(HttpRequestResponse rr, List<AuditIssue> sink) {
        String url = rr.request().url();
        if (url == null || !url.startsWith("http://")) return;
        if (!rr.hasResponse()) return;

        int status = rr.response().statusCode();

        // 3xx to an https:// Location = correct HTTPS enforcement. Not a finding.
        if (status >= 300 && status < 400) {
            String location = headerValue(rr.response(), "location");
            if (location != null && location.toLowerCase(Locale.ROOT).startsWith("https://")) {
                return;
            }
        }

        // Only flag when the server actually serves content over cleartext.
        if (status >= 200 && status < 300) {
            sink.add(buildInsecureProtocolIssue(rr));
        }
    }

    private void addVerboseErrorIssue(HttpRequestResponse rr, List<AuditIssue> sink) {
        int status = rr.response().statusCode();
        if (status < 400) return;
        String body = rr.response().bodyToString();
        if (body == null) return;
        String lower = body.toLowerCase(Locale.ROOT);
        for (String marker : ERROR_LEAK_MARKERS) {
            if (lower.contains(marker)) {
                sink.add(buildVerboseErrorIssue(rr));
                return;
            }
        }
    }

    // ---- Header helpers ----------------------------------------------------

    private static Set<String> headerNamesLowercase(HttpResponse response) {
        Set<String> names = new java.util.HashSet<>();
        for (HttpHeader h : response.headers()) {
            if (h.name() != null) names.add(h.name().toLowerCase(Locale.ROOT));
        }
        return names;
    }

    private static String headerValue(HttpResponse response, String nameLower) {
        for (HttpHeader h : response.headers()) {
            if (h.name() != null && nameLower.equals(h.name().toLowerCase(Locale.ROOT))) {
                return h.value();
            }
        }
        return null;
    }

    private static String headerValue(HttpRequest request, String nameLower) {
        for (HttpHeader h : request.headers()) {
            if (h.name() != null && nameLower.equals(h.name().toLowerCase(Locale.ROOT))) {
                return h.value();
            }
        }
        return null;
    }

    // ---- Issue builders ----------------------------------------------------

    private AuditIssue buildMissingHeadersIssue(HttpRequestResponse rr, List<String> missing) {
        StringBuilder list = new StringBuilder();
        for (String header : missing) {
            list.append("- ").append(header).append(": ")
                    .append(RECOMMENDED_HEADERS.get(header)).append("<br>");
        }
        String detail =
                "The response is missing recommended security headers:<br><br>" + list +
                "<br>These headers protect against XSS, clickjacking, MIME-type confusion, " +
                "and protocol downgrade attacks.";
        return IssueBuilder.issue(rr)
                .name("API8:2023 - Security Misconfiguration (Missing Security Headers)")
                .detail(detail)
                .background(ISSUE_BACKGROUND)
                .severity("Information")
                .confidence("Certain")
                .build();
    }

    private AuditIssue buildDisclosureHeadersIssue(HttpRequestResponse rr, List<String> found) {
        StringBuilder list = new StringBuilder();
        for (String header : found) list.append("- ").append(header).append("<br>");
        String detail =
                "The response includes headers that disclose server / framework details:<br><br>" +
                list + "<br>These hints help attackers narrow their search for known vulnerabilities.";
        return IssueBuilder.issue(rr)
                .name("API8:2023 - Security Misconfiguration (Information Disclosure via Headers)")
                .detail(detail)
                .background(ISSUE_BACKGROUND)
                .severity("Information")
                .confidence("Certain")
                .build();
    }

    private AuditIssue buildCorsWildcardIssue(HttpRequestResponse rr) {
        return IssueBuilder.issue(rr)
                .name("API8:2023 - Security Misconfiguration (CORS Wildcard Origin)")
                .detail("The response sends <code>Access-Control-Allow-Origin: *</code>. " +
                        "Any website can read the response. Acceptable only if the API exposes " +
                        "purely public data.")
                .remediation("Use an explicit allow-list of origins instead of <code>*</code>.")
                .background(ISSUE_BACKGROUND)
                .severity("Low")
                .confidence("Certain")
                .build();
    }

    private AuditIssue buildCorsCredentialsIssue(HttpRequestResponse rr) {
        return IssueBuilder.issue(rr)
                .name("API8:2023 - Security Misconfiguration (CORS Wildcard with Credentials)")
                .detail("The response combines <code>Access-Control-Allow-Origin: *</code> with " +
                        "<code>Access-Control-Allow-Credentials: true</code>. Browsers reject " +
                        "this combination, but its presence indicates a severe misconfiguration: " +
                        "the server is asking browsers to send credentials cross-origin to any site.")
                .remediation("Echo a specific allow-listed origin and only when credentials are " +
                        "required.")
                .background(ISSUE_BACKGROUND)
                .severity("High")
                .confidence("Certain")
                .build();
    }

    private AuditIssue buildCorsReflectedIssue(HttpRequestResponse rr, String origin) {
        return IssueBuilder.issue(rr)
                .name("API8:2023 - Security Misconfiguration (CORS Reflected Origin)")
                .detail("The server reflects the request <code>Origin</code> header back into " +
                        "<code>Access-Control-Allow-Origin</code> without validation. " +
                        "Origin sent: <code>" + IssueBuilder.escapeHtml(origin) + "</code>.<br><br>" +
                        "Combined with credentials, this allows full cross-origin attack against " +
                        "authenticated sessions.")
                .remediation("Validate the request origin against an allow-list before reflecting.")
                .background(ISSUE_BACKGROUND)
                .severity("High")
                .confidence("Firm")
                .build();
    }

    private AuditIssue buildInsecureProtocolIssue(HttpRequestResponse rr) {
        return IssueBuilder.issue(rr)
                .name("API8:2023 - Security Misconfiguration (API over HTTP)")
                .detail("The API returned a 2xx response over unencrypted HTTP — it processes " +
                        "requests in cleartext rather than redirecting to HTTPS. Authentication " +
                        "tokens, credentials, and request bodies sent to this endpoint travel " +
                        "in cleartext and can be intercepted on the network path.")
                .remediation("Serve the API exclusively over HTTPS; redirect HTTP to HTTPS at " +
                        "the edge (a 308 redirect to the https:// URL) and add an HSTS header.")
                .background(ISSUE_BACKGROUND)
                .severity("High")
                // Firm, not Certain: cleartext transport is confirmed, but whether
                // sensitive data actually traverses this endpoint is context-dependent.
                .confidence("Firm")
                .build();
    }

    private AuditIssue buildVerboseErrorIssue(HttpRequestResponse rr) {
        return IssueBuilder.issue(rr)
                .name("API8:2023 - Security Misconfiguration (Verbose Error Messages)")
                .detail("The error response includes a stack trace or other implementation " +
                        "detail. This shortens an attacker's recon by revealing framework, " +
                        "version, and code structure.")
                .remediation("Return generic error responses to clients; log detail server-side.")
                .background(ISSUE_BACKGROUND)
                .severity("Low")
                .confidence("Firm")
                .build();
    }
}
