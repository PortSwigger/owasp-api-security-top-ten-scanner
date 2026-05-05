package com.security.burp.checks.active;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
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
import java.util.function.BiPredicate;

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
        if (HttpUtils.isJson(rr.request())) addFirstFinding(issues, runNoSql(rr, ip, http));
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
                (body, payload) -> containsAny(body.toLowerCase(Locale.ROOT),
                        InjectionPayloads.SQL_ERROR_MARKERS),
                (base, evidence, payload) -> buildIssue(base, evidence, ip, payload,
                        "API2:2023 - Broken Authentication (SQL Injection)",
                        "Server response carried a SQL engine error after the payload was " +
                        "delivered through this insertion point.",
                        "Critical", SQL_BACKGROUND));
    }

    private AuditIssue runNoSql(HttpRequestResponse rr, AuditInsertionPoint ip, Http http) {
        return runFamily(rr, ip, http,
                InjectionPayloads.NOSQL,
                (body, payload) -> containsAny(body.toLowerCase(Locale.ROOT),
                        InjectionPayloads.NOSQL_ERROR_MARKERS),
                (base, evidence, payload) -> buildIssue(base, evidence, ip, payload,
                        "API2:2023 - Broken Authentication (NoSQL Injection)",
                        "Server response carried a NoSQL driver error after the operator " +
                        "payload was delivered.",
                        "High", SQL_BACKGROUND));
    }

    private AuditIssue runCommand(HttpRequestResponse rr, AuditInsertionPoint ip, Http http) {
        return runFamily(rr, ip, http,
                InjectionPayloads.COMMAND,
                (body, payload) -> {
                    String lower = body.toLowerCase(Locale.ROOT);
                    return containsAny(lower, InjectionPayloads.COMMAND_OUTPUT_MARKERS)
                            || containsAny(lower, InjectionPayloads.COMMAND_ERROR_MARKERS);
                },
                (base, evidence, payload) -> buildIssue(base, evidence, ip, payload,
                        "API8:2023 - Security Misconfiguration (Command Injection)",
                        "Response indicates the OS attempted to execute the injected payload " +
                        "(either by leaking output or producing a shell error).",
                        "Critical", SQL_BACKGROUND));
    }

    private AuditIssue runXss(HttpRequestResponse rr, AuditInsertionPoint ip, Http http) {
        return runFamily(rr, ip, http,
                InjectionPayloads.XSS,
                (body, payload) -> body.contains(payload),
                (base, evidence, payload) -> buildIssue(base, evidence, ip, payload,
                        "API8:2023 - Security Misconfiguration (Reflected XSS in API Response)",
                        "Response reflects the payload unencoded. If the response is ever " +
                        "rendered as HTML this is exploitable.",
                        "Medium", SQL_BACKGROUND));
    }

    // ---- Generic family runner ---------------------------------------------

    /**
     * Send each {@code payload} through the insertion point and call
     * {@code findingBuilder} the first time {@code triggers} returns true.
     */
    private AuditIssue runFamily(HttpRequestResponse rr,
                                 AuditInsertionPoint ip,
                                 Http http,
                                 List<String> payloads,
                                 BiPredicate<String, String> triggers,
                                 FindingBuilder findingBuilder) {
        for (String payload : payloads) {
            HttpRequestResponse evidence = sendPayload(rr, ip, http, payload);
            if (evidence == null) continue;
            String body = evidence.response().bodyToString();
            if (body == null) continue;
            if (triggers.test(body, payload)) {
                return findingBuilder.build(rr, evidence, payload);
            }
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

    private static boolean containsAny(String haystack, List<String> needles) {
        for (String needle : needles) if (haystack.contains(needle)) return true;
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
                                  String background) {
        String detail =
                summary + "<br><br>" +
                "Insertion point: <code>" + ip.name() + "</code><br>" +
                "Payload: <code>" + escape(payload) + "</code>";
        return IssueBuilder.issue(base)
                .name(name)
                .detail(detail)
                .remediation("Use parameterised queries / safe APIs and a strict input " +
                        "validation policy. Never interpolate untrusted values into queries, " +
                        "shell commands, or response markup.")
                .background(background)
                .severity(severity)
                .confidence("Firm")
                .evidence(base, evidence)
                .build();
    }

    private static String escape(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    @FunctionalInterface
    private interface FindingBuilder {
        AuditIssue build(HttpRequestResponse base, HttpRequestResponse evidence, String payload);
    }
}
