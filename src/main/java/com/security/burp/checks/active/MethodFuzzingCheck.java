package com.security.burp.checks.active;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.security.burp.checks.AbstractActiveCheck;
import com.security.burp.util.IssueBuilder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * OWASP API5:2023 — Broken Function Level Authorization (HTTP method fuzzing).
 *
 * <p>For each request, replays it with every other HTTP method and reports
 * any that aren't refused with a {@code 405 Method Not Allowed}. Unexpected
 * acceptance of {@code PUT} / {@code DELETE} / {@code PATCH} / {@code TRACE}
 * is treated as more severe.
 *
 * <p>Also checks for two related misconfigurations: {@code OPTIONS}
 * disclosing the allow-list, and {@code TRACE} being enabled (Cross-Site
 * Tracing risk).
 *
 * <p>Registered {@code PER_HOST}; deduped per (host + path) so that Burp
 * calling us repeatedly on the same path during a scan doesn't refuzz it.
 */
public final class MethodFuzzingCheck extends AbstractActiveCheck {

    private static final List<String> ALL_METHODS = List.of(
            "GET", "POST", "PUT", "DELETE", "PATCH",
            "HEAD", "OPTIONS", "TRACE", "CONNECT");

    private static final Set<String> METHODS_THAT_CARRY_BODY = Set.of(
            "POST", "PUT", "PATCH", "DELETE");

    private static final Set<String> DANGEROUS_METHODS = Set.of(
            "PUT", "DELETE", "PATCH", "TRACE");

    private static final String API5_BACKGROUND =
            "API5:2023 - Broken Function Level Authorization<br><br>" +
            "Complex access-control policies frequently fail to deny privileged HTTP methods " +
            "on functional endpoints. The result is an attacker reaching admin functions " +
            "(or other users' resources) by changing the verb on an existing request.";

    private static final String API8_BACKGROUND =
            "API8:2023 - Security Misconfiguration<br><br>" +
            "Verbose method support exposes internal API surface and, in the case of TRACE, " +
            "carries direct cross-site tracing risk.";

    private final Set<String> dedupe = Collections.newSetFromMap(new ConcurrentHashMap<>());

    public MethodFuzzingCheck(MontoyaApi api) {
        super(api);
    }

    @Override
    public String checkName() {
        return "API5:2023 HTTP Method Fuzzing";
    }

    @Override
    protected List<AuditIssue> audit(HttpRequestResponse rr, AuditInsertionPoint ip, Http http) {
        if (!shouldRunOnce(rr)) return List.of();

        List<AuditIssue> issues = new ArrayList<>();
        String originalMethod = rr.request().method();

        for (String method : ALL_METHODS) {
            if (method.equals(originalMethod)) continue;
            HttpRequestResponse evidence = sendWithMethod(rr.request(), method, http);
            if (evidence == null || !evidence.hasResponse()) continue;
            inspectResponse(rr, evidence, method, originalMethod, issues);
        }
        return issues;
    }

    /** Runs at most once per (host, path) for the lifetime of the check. */
    private boolean shouldRunOnce(HttpRequestResponse rr) {
        String key = rr.request().httpService().host() + "|" + rr.request().pathWithoutQuery();
        return dedupe.add(key);
    }

    // ---- Sending -----------------------------------------------------------

    private HttpRequestResponse sendWithMethod(HttpRequest base, String method, Http http) {
        try {
            HttpRequest mutated = base.withMethod(method);
            if (!METHODS_THAT_CARRY_BODY.contains(method)) {
                mutated = mutated.withBody("");
            }
            return http.sendRequest(mutated);
        } catch (Exception e) {
            api.logging().logToError("[Method Fuzzing] " + method + " send failed: " + e.getMessage());
            return null;
        }
    }

    // ---- Response inspection -----------------------------------------------

    private void inspectResponse(HttpRequestResponse base,
                                 HttpRequestResponse evidence,
                                 String method,
                                 String originalMethod,
                                 List<AuditIssue> sink) {
        HttpResponse response = evidence.response();
        int status = response.statusCode();

        if ("OPTIONS".equals(method)) {
            String allow = headerValue(response, "allow");
            if (allow != null) sink.add(buildOptionsIssue(base, evidence, allow));
        }
        if ("TRACE".equals(method) && status == 200) {
            sink.add(buildTraceIssue(base, evidence));
        }

        if (status == 405) return; // Correctly refused — no finding.

        // Successful or partially-successful response is the interesting case.
        boolean accepted = status >= 200 && status < 300;
        if (DANGEROUS_METHODS.contains(method) && status < 400) {
            sink.add(buildMethodIssue(base, evidence, method, originalMethod, status, "High"));
        } else if (accepted) {
            sink.add(buildMethodIssue(base, evidence, method, originalMethod, status, "Medium"));
        } else {
            // Anything else (400, 401, 5xx) — informational signal that the
            // server engages with the verb at all.
            sink.add(buildMethodIssue(base, evidence, method, originalMethod, status, "Information"));
        }
    }

    private static String headerValue(HttpResponse response, String nameLower) {
        for (HttpHeader header : response.headers()) {
            if (header.name() != null && nameLower.equalsIgnoreCase(header.name())) {
                return header.value();
            }
        }
        return null;
    }

    // ---- Issues ------------------------------------------------------------

    private AuditIssue buildMethodIssue(HttpRequestResponse base,
                                        HttpRequestResponse evidence,
                                        String method,
                                        String originalMethod,
                                        int status,
                                        String severity) {
        String detail =
                "The endpoint responded to HTTP <code>" + method + "</code> with status " +
                status + ".<br><br>" +
                "Original observed method: <code>" + originalMethod + "</code>.<br>" +
                "Endpoint reachable via: <code>" + method + "</code>.<br><br>" +
                "Acceptance of unexpected HTTP methods may indicate missing access control on " +
                "the function — for example, exposing a write operation through a verb that " +
                "wasn't intended to support it.";
        return IssueBuilder.issue(base)
                .name("API5:2023 - Broken Function Level Authorization (Unexpected Method: " + method + ")")
                .detail(detail)
                .remediation("Reject unsupported methods with 405 Method Not Allowed and an " +
                        "explicit Allow header.")
                .background(API5_BACKGROUND)
                .severity(severity)
                .confidence("Firm")
                .evidence(base, evidence)
                .build();
    }

    private AuditIssue buildOptionsIssue(HttpRequestResponse base,
                                         HttpRequestResponse evidence,
                                         String allow) {
        String detail =
                "The endpoint responds to OPTIONS and discloses the supported methods via the " +
                "Allow header: <code>" + allow + "</code>.<br><br>" +
                "Not directly exploitable, but this shortens an attacker's enumeration step.";
        return IssueBuilder.issue(base)
                .name("API8:2023 - Security Misconfiguration (OPTIONS Method Disclosure)")
                .detail(detail)
                .background(API8_BACKGROUND)
                .severity("Information")
                .confidence("Certain")
                .evidence(base, evidence)
                .build();
    }

    private AuditIssue buildTraceIssue(HttpRequestResponse base, HttpRequestResponse evidence) {
        String detail =
                "The endpoint responds to TRACE with 200. TRACE echoes the request and can be " +
                "exploited for Cross-Site Tracing to bypass HTTPOnly cookie protections.";
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
