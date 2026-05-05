package com.security.burp.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.scancheck.ActiveScanCheck;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Collections;
import java.util.List;

/**
 * Base class for active scan checks.
 *
 * <p>Centralises exception handling and provides a single hook
 * ({@link #audit}) for subclasses. Checks registered as
 * {@code PER_INSERTION_POINT} that mutate whole-body payloads (e.g. JSON
 * mass-assignment) should consult {@link #shouldRunOnce} to dedupe.
 */
public abstract class AbstractActiveCheck implements ActiveScanCheck {

    protected final MontoyaApi api;

    protected AbstractActiveCheck(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public final AuditResult doCheck(HttpRequestResponse rr, AuditInsertionPoint ip, Http http) {
        try {
            List<AuditIssue> issues = audit(rr, ip, http);
            return AuditResult.auditResult(issues != null ? issues : Collections.emptyList());
        } catch (Throwable t) {
            logFailure(t);
            return AuditResult.auditResult(Collections.emptyList());
        }
    }

    /** Implemented by each check. Errors are caught and logged. */
    protected abstract List<AuditIssue> audit(HttpRequestResponse rr,
                                              AuditInsertionPoint ip,
                                              Http http);

    private void logFailure(Throwable t) {
        StringWriter trace = new StringWriter();
        t.printStackTrace(new PrintWriter(trace));
        api.logging().logToError("[" + checkName() + "] Uncaught error:\n" + trace);
    }
}
