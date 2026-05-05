package com.security.burp.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;
import com.security.burp.ai.AiTriage;
import com.security.burp.scanner.EndpointRegistry;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Collections;
import java.util.List;

/**
 * Base class for passive scan checks.
 *
 * <p>Centralises three things every check would otherwise duplicate:
 * <ol>
 *   <li>endpoint recording into {@link EndpointRegistry};</li>
 *   <li>exception handling — uncaught throwables are logged with stack
 *       trace and the check returns no issues rather than crashing the scan;</li>
 *   <li>optional AI triage — if {@link AiTriage} is supplied and AI is
 *       available, findings are filtered through it before being reported.</li>
 * </ol>
 *
 * Subclasses implement {@link #audit(HttpRequestResponse)} and return any
 * issues they find. They do not need to wrap themselves in try/catch.
 */
public abstract class AbstractPassiveCheck implements PassiveScanCheck {

    protected final MontoyaApi api;
    protected final EndpointRegistry endpoints;
    protected final AiTriage triage;

    protected AbstractPassiveCheck(MontoyaApi api, EndpointRegistry endpoints, AiTriage triage) {
        this.api = api;
        this.endpoints = endpoints;
        this.triage = triage;
    }

    @Override
    public final AuditResult doCheck(HttpRequestResponse rr) {
        recordEndpoint(rr);
        List<AuditIssue> issues = runAudit(rr);
        List<AuditIssue> filtered = applyTriage(issues, rr);
        return AuditResult.auditResult(filtered);
    }

    /** Implemented by each check. Errors thrown here are caught and logged. */
    protected abstract List<AuditIssue> audit(HttpRequestResponse rr);

    private void recordEndpoint(HttpRequestResponse rr) {
        try {
            endpoints.record(
                    rr.request().httpService().host(),
                    rr.request().pathWithoutQuery(),
                    rr.request().method());
        } catch (Exception e) {
            // Recording is best-effort; a malformed request should not break a check.
            api.logging().logToError("[" + checkName() + "] Endpoint recording failed: " + e.getMessage());
        }
    }

    private List<AuditIssue> runAudit(HttpRequestResponse rr) {
        try {
            List<AuditIssue> issues = audit(rr);
            return issues != null ? issues : Collections.emptyList();
        } catch (Throwable t) {
            logFailure(t);
            return Collections.emptyList();
        }
    }

    private List<AuditIssue> applyTriage(List<AuditIssue> issues, HttpRequestResponse rr) {
        if (triage == null || issues.isEmpty()) return issues;
        try {
            return triage.filter(issues, rr);
        } catch (Throwable t) {
            logFailure(t);
            return issues; // Triage failure must not drop legitimate findings.
        }
    }

    private void logFailure(Throwable t) {
        StringWriter trace = new StringWriter();
        t.printStackTrace(new PrintWriter(trace));
        api.logging().logToError("[" + checkName() + "] Uncaught error:\n" + trace);
    }
}
