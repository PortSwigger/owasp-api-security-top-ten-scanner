package com.security.burp.checks.active;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.security.burp.checks.AbstractActiveCheck;
import com.security.burp.checks.active.injection.AuthBypassTester;
import com.security.burp.checks.active.injection.InjectionPayloads;
import com.security.burp.util.HttpUtils;
import com.security.burp.util.IssueBuilder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * OWASP API2:2023 / API8:2023 — Injection (SQL, NoSQL, command, XSS).
 *
 * <p>Two paths:
 * <ol>
 *   <li><b>Auth-endpoint SQL bypass.</b> If this is a {@code POST} to a
 *       login-shaped path with a JSON body containing username/password,
 *       run the targeted bypass probe via {@link AuthBypassTester}. This
 *       runs once per (host + path) and short-circuits if it finds
 *       anything — generic per-insertion-point fuzzing on the same
 *       request would just be noise.</li>
 *   <li><b>Per-insertion-point payload fuzzing.</b> For each insertion
 *       point Burp identifies, replace the value with each payload from
 *       each family (SQL / NoSQL / command / XSS) and inspect the response
 *       for family-specific evidence (engine error string, command output,
 *       payload reflection).</li>
 * </ol>
 *
 * <p>Registered {@code PER_INSERTION_POINT}.
 */
public final class InjectionCheck extends AbstractActiveCheck {

    private static final String SQL_BACKGROUND =
            "API2:2023 - Broken Authentication / API8:2023 - Security Misconfiguration<br><br>" +
            "Injection allows an attacker to alter the meaning of a server-side query or " +
            "command by smuggling syntax through a user-controlled parameter.";

    private final AuthBypassTester authBypassTester;
    private final Set<String> authEndpointsTried = Collections.newSetFromMap(new ConcurrentHashMap<>());

    public InjectionCheck(MontoyaApi api) {
        super(api);
        this.authBypassTester = new AuthBypassTester(api);
    }

    @Override
    public String checkName() {
        return "API2:2023 / API8:2023 Injection";
    }

    @Override
    protected List<AuditIssue> audit(HttpRequestResponse rr, AuditInsertionPoint ip, Http http) {
        AuditIssue authBypass = tryAuthBypassOnce(rr, http);
        if (authBypass != null) return List.of(authBypass);

        List<AuditIssue> issues = new ArrayList<>();
        addFirstFinding(issues, runSql(rr, ip, http));
        // NoSQL is the one family that fires per matching payload rather than
        // first match — the bypass-behavior path (200 OK to a $ne payload) is
        // a heuristic worth surfacing for every payload that triggers it,
        // matching the legacy v1 behavior.
        if (HttpUtils.isJson(rr.request())) issues.addAll(runNoSql(rr, ip, http));
        addFirstFinding(issues, runCommand(rr, ip, http));
        addFirstFinding(issues, runXss(rr, ip, http));
        return issues;
    }

    private AuditIssue tryAuthBypassOnce(HttpRequestResponse rr, Http http) {
        if (!authBypassTester.isAuthEndpoint(rr.request())) return null;
        String key = rr.request().httpService().host() + "|" + rr.request().pathWithoutQuery();
        if (!authEndpointsTried.add(key)) return null;
        return authBypassTester.test(rr, http);
    }

    private static void addFirstFinding(List<AuditIssue> sink, AuditIssue finding) {
        if (finding != null) sink.add(finding);
    }

    // ---- Per-family runners ------------------------------------------------

    private AuditIssue runSql(HttpRequestResponse rr, AuditInsertionPoint ip, Http http) {
        return runFamily(rr, ip, http,
                InjectionPayloads.SQL,
                (response, payload) -> bodyContainsAny(response, InjectionPayloads.SQL_ERROR_MARKERS)
                        ? "Critical" : null,
                (base, evidence, payload, severity) -> buildIssue(base, evidence, ip, payload,
                        "API2:2023 - Broken Authentication (SQL Injection)",
                        "Server response carried a SQL engine error after the payload was " +
                        "delivered through this insertion point.",
                        severity, "Firm", SQL_BACKGROUND));
    }

    /**
     * NoSQL has two detection paths preserved from the legacy implementation:
     * <ul>
     *   <li>response carries a NoSQL driver error string — high confidence,
     *       fires once and short-circuits the rest of the family;</li>
     *   <li>response is a 200 to a payload containing a Mongo operator
     *       (e.g. {@code $ne}) — heuristic "potential bypass" signal,
     *       reported as Tentative confidence; fires for <em>every</em>
     *       payload that matches, since each payload represents a distinct
     *       piece of evidence the reviewer can inspect.</li>
     * </ul>
     */
    private List<AuditIssue> runNoSql(HttpRequestResponse rr, AuditInsertionPoint ip, Http http) {
        List<AuditIssue> findings = new ArrayList<>();
        for (String payload : InjectionPayloads.NOSQL) {
            HttpRequestResponse evidence = sendPayload(rr, ip, http, payload);
            if (evidence == null) continue;

            if (bodyContainsAny(evidence.response(), InjectionPayloads.NOSQL_ERROR_MARKERS)) {
                findings.add(buildNoSqlIssue(rr, evidence, ip, payload, "Firm",
                        "Server response carried a NoSQL driver error after the operator " +
                        "payload was delivered."));
                return findings; // confirmed error — no need to keep probing.
            }
            if (evidence.response().statusCode() == 200 && payload.contains("$ne")) {
                findings.add(buildNoSqlIssue(rr, evidence, ip, payload, "Tentative",
                        "Endpoint returned 200 OK to a Mongo operator payload " +
                        "(<code>" + IssueBuilder.escapeHtml(payload) + "</code>). The application appears " +
                        "to accept the operator object without an error — consistent with " +
                        "a missing input-shape check that may permit authentication or " +
                        "filter bypass."));
                // No short-circuit: keep probing remaining payloads.
            }
        }
        return findings;
    }

    private AuditIssue buildNoSqlIssue(HttpRequestResponse base,
                                       HttpRequestResponse evidence,
                                       AuditInsertionPoint ip,
                                       String payload,
                                       String confidence,
                                       String summary) {
        return buildIssue(base, evidence, ip, payload,
                "API2:2023 - Broken Authentication (NoSQL Injection)",
                summary, "High", confidence, SQL_BACKGROUND);
    }

    private AuditIssue runCommand(HttpRequestResponse rr, AuditInsertionPoint ip, Http http) {
        return runFamily(rr, ip, http,
                InjectionPayloads.COMMAND,
                (response, payload) -> {
                    boolean output = bodyContainsAny(response, InjectionPayloads.COMMAND_OUTPUT_MARKERS);
                    boolean error  = bodyContainsAny(response, InjectionPayloads.COMMAND_ERROR_MARKERS);
                    return (output || error) ? "Critical" : null;
                },
                (base, evidence, payload, severity) -> buildIssue(base, evidence, ip, payload,
                        "API8:2023 - Security Misconfiguration (Command Injection)",
                        "Response indicates the OS attempted to execute the injected payload " +
                        "(either by leaking output or producing a shell error).",
                        severity, "Firm", SQL_BACKGROUND));
    }

    private AuditIssue runXss(HttpRequestResponse rr, AuditInsertionPoint ip, Http http) {
        return runFamily(rr, ip, http,
                InjectionPayloads.XSS,
                (response, payload) -> {
                    String body = response.bodyToString();
                    return (body != null && body.contains(payload)) ? "Medium" : null;
                },
                (base, evidence, payload, severity) -> buildIssue(base, evidence, ip, payload,
                        "API8:2023 - Security Misconfiguration (Reflected XSS in API Response)",
                        "Response reflects the payload unencoded. If the response is ever " +
                        "rendered as HTML this is exploitable.",
                        severity, "Firm", SQL_BACKGROUND));
    }

    // ---- Generic family runners --------------------------------------------

    /** Shape used by SQL/Command/XSS where the trigger only carries severity. */
    private AuditIssue runFamily(HttpRequestResponse rr,
                                 AuditInsertionPoint ip,
                                 Http http,
                                 List<String> payloads,
                                 SeverityTrigger trigger,
                                 SeverityFindingBuilder builder) {
        for (String payload : payloads) {
            HttpRequestResponse evidence = sendPayload(rr, ip, http, payload);
            if (evidence == null) continue;
            String severity = trigger.severityFor(evidence.response(), payload);
            if (severity != null) return builder.build(rr, evidence, payload, severity);
        }
        return null;
    }

    private HttpRequestResponse sendPayload(HttpRequestResponse rr,
                                            AuditInsertionPoint ip,
                                            Http http,
                                            String payload) {
        try {
            HttpRequest mutated = ip.buildHttpRequestWithPayload(ByteArray.byteArray(payload));
            HttpRequestResponse response = http.sendRequest(mutated);
            return (response != null && response.hasResponse()) ? response : null;
        } catch (Exception e) {
            api.logging().logToError("[Injection] Payload send failed: " + e.getMessage());
            return null;
        }
    }

    private static boolean bodyContainsAny(HttpResponse response, List<String> needlesLower) {
        String body = response.bodyToString();
        if (body == null) return false;
        String lower = body.toLowerCase(Locale.ROOT);
        for (String needle : needlesLower) if (lower.contains(needle)) return true;
        return false;
    }

    // ---- Issue construction ------------------------------------------------

    private AuditIssue buildIssue(HttpRequestResponse base,
                                  HttpRequestResponse evidence,
                                  AuditInsertionPoint ip,
                                  String payload,
                                  String name,
                                  String summary,
                                  String severity,
                                  String confidence,
                                  String background) {
        String detail =
                summary + "<br><br>" +
                "Insertion point: <code>" + IssueBuilder.escapeHtml(ip.name()) + "</code><br>" +
                "Payload: <code>" + IssueBuilder.escapeHtml(payload) + "</code>";
        return IssueBuilder.issue(base)
                .name(name)
                .detail(detail)
                .remediation("Use parameterised queries / safe APIs and a strict input " +
                        "validation policy. Never interpolate untrusted values into queries, " +
                        "shell commands, or response markup.")
                .background(background)
                .severity(severity)
                .confidence(confidence)
                .evidence(base, evidence)
                .build();
    }

    @FunctionalInterface
    private interface SeverityTrigger {
        /** Returns the severity to fire at, or null if the response doesn't trigger. */
        String severityFor(HttpResponse response, String payload);
    }

    @FunctionalInterface
    private interface SeverityFindingBuilder {
        AuditIssue build(HttpRequestResponse base, HttpRequestResponse evidence,
                         String payload, String severity);
    }
}
