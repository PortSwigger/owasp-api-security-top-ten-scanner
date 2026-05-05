package com.security.burp.util;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.List;

/**
 * Fluent builder for {@link AuditIssue}, taking the place of the legacy
 * {@code CustomScanIssue}. Centralises severity/confidence parsing and
 * the legacy-{@code Critical} → Montoya-{@code HIGH} mapping (Montoya has
 * no Critical level).
 *
 * <p>Use it like:
 * <pre>
 *   IssueBuilder.issue(rr)
 *           .name("API3:2023 - Mass Assignment")
 *           .detail(detailHtml)
 *           .background(API3_BACKGROUND)
 *           .severity("High")
 *           .confidence("Firm")
 *           .build();
 * </pre>
 */
public final class IssueBuilder {

    private final HttpRequestResponse base;
    private HttpRequestResponse[] evidence;
    private String name;
    private String detail;
    private String remediation = "";
    private String background = "";
    private AuditIssueSeverity severity = AuditIssueSeverity.INFORMATION;
    private AuditIssueConfidence confidence = AuditIssueConfidence.TENTATIVE;

    private IssueBuilder(HttpRequestResponse base) {
        this.base = base;
    }

    public static IssueBuilder issue(HttpRequestResponse base) {
        return new IssueBuilder(base);
    }

    public IssueBuilder name(String name)               { this.name = name; return this; }
    public IssueBuilder detail(String detail)           { this.detail = detail; return this; }
    public IssueBuilder remediation(String remediation) { this.remediation = remediation; return this; }
    public IssueBuilder background(String background)   { this.background = background; return this; }

    public IssueBuilder severity(String severity) {
        this.severity = severityFromString(severity);
        return this;
    }

    public IssueBuilder confidence(String confidence) {
        this.confidence = confidenceFromString(confidence);
        return this;
    }

    public IssueBuilder evidence(HttpRequestResponse... evidence) {
        this.evidence = evidence;
        return this;
    }

    public AuditIssue build() {
        if (name == null) throw new IllegalStateException("issue name is required");
        if (detail == null) throw new IllegalStateException("issue detail is required");
        HttpRequestResponse[] requests = (evidence != null && evidence.length > 0)
                ? evidence
                : new HttpRequestResponse[] { base };
        return AuditIssue.auditIssue(
                name,
                detail,
                remediation,
                base.request().url(),
                severity,
                confidence,
                background,
                "",
                severity,
                List.of(requests));
    }

    private static AuditIssueSeverity severityFromString(String s) {
        if (s == null) return AuditIssueSeverity.INFORMATION;
        return switch (s.toLowerCase()) {
            // Montoya has no CRITICAL; collapse onto HIGH (the highest available).
            case "critical", "high" -> AuditIssueSeverity.HIGH;
            case "medium"           -> AuditIssueSeverity.MEDIUM;
            case "low"              -> AuditIssueSeverity.LOW;
            default                 -> AuditIssueSeverity.INFORMATION;
        };
    }

    private static AuditIssueConfidence confidenceFromString(String s) {
        if (s == null) return AuditIssueConfidence.TENTATIVE;
        return switch (s.toLowerCase()) {
            case "certain" -> AuditIssueConfidence.CERTAIN;
            case "firm"    -> AuditIssueConfidence.FIRM;
            default        -> AuditIssueConfidence.TENTATIVE;
        };
    }
}
