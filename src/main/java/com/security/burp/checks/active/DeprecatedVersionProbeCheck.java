package com.security.burp.checks.active;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.security.burp.checks.AbstractActiveCheck;
import com.security.burp.util.IssueBuilder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * OWASP API9:2023 — Improper Inventory Management (active version probe).
 *
 * <p>Companion to the passive {@code InventoryManagementCheck}, which only
 * inspects the path for keywords. This check actively probes <em>older</em>
 * versions of the API: if the request path matches {@code /v3/...}, fire
 * a request to {@code /v2/...}, {@code /v1/...} and {@code /v0/...} and
 * report each version that responds with a 2xx.
 *
 * <p>Per security-research feedback (Zak): keyword detection alone is
 * insufficient — the high-value finding is that an outdated version is
 * actually <em>still reachable</em> on the same host.
 *
 * <p>Registered {@code PER_HOST}; deduped per (host + path).
 */
public final class DeprecatedVersionProbeCheck extends AbstractActiveCheck {

    private static final Pattern VERSION_PATTERN = Pattern.compile("/v(\\d+)(/|$)");

    private static final String ISSUE_BACKGROUND =
            "API9:2023 - Improper Inventory Management<br><br>" +
            "Old API versions left exposed continue to receive traffic but typically miss " +
            "the security fixes applied to the current version, becoming an easier path " +
            "to the same data.";

    private final Set<String> dedupe = Collections.newSetFromMap(new ConcurrentHashMap<>());

    public DeprecatedVersionProbeCheck(MontoyaApi api) {
        super(api);
    }

    @Override
    public String checkName() {
        return "API9:2023 Deprecated Version Probe";
    }

    @Override
    protected List<AuditIssue> audit(HttpRequestResponse rr, AuditInsertionPoint ip, Http http) {
        if (!shouldRunOnce(rr)) return List.of();

        String path = rr.request().pathWithoutQuery();
        if (path == null) return List.of();
        Matcher matcher = VERSION_PATTERN.matcher(path);
        if (!matcher.find()) return List.of();

        int currentVersion = parseSilently(matcher.group(1));
        if (currentVersion <= 0) return List.of();

        List<AuditIssue> issues = new ArrayList<>();
        for (int olderVersion = currentVersion - 1; olderVersion >= 0; olderVersion--) {
            HttpRequestResponse evidence = probeVersion(rr, http, currentVersion, olderVersion);
            if (evidence != null) issues.add(buildIssue(rr, evidence, currentVersion, olderVersion));
        }
        return issues;
    }

    private boolean shouldRunOnce(HttpRequestResponse rr) {
        String key = rr.request().httpService().host() + "|" + rr.request().pathWithoutQuery();
        return dedupe.add(key);
    }

    /** Returns the response if the older-version path returns a 2xx; null otherwise. */
    private HttpRequestResponse probeVersion(HttpRequestResponse rr,
                                             Http http,
                                             int currentVersion,
                                             int olderVersion) {
        try {
            HttpRequest probe = rebuildAtVersion(rr.request(), currentVersion, olderVersion);
            HttpRequestResponse response = http.sendRequest(probe);
            if (response == null || !response.hasResponse()) return null;
            int status = response.response().statusCode();
            return (status >= 200 && status < 300) ? response : null;
        } catch (Exception e) {
            api.logging().logToError("[Deprecated Version] Probe v" + olderVersion + " failed: " + e.getMessage());
            return null;
        }
    }

    /** Rewrites the first {@code /v<currentVersion>} segment to {@code /v<olderVersion>}. */
    private static HttpRequest rebuildAtVersion(HttpRequest base,
                                                int currentVersion,
                                                int olderVersion) {
        String oldUrl = base.url();
        String newUrl = oldUrl.replaceFirst(
                "/v" + currentVersion + "(?=/|$)",
                "/v" + olderVersion);
        if (newUrl.equals(oldUrl)) return base;

        HttpRequest result = HttpRequest.httpRequestFromUrl(newUrl)
                .withMethod(base.method())
                .withBody(base.bodyToString());
        // Re-attach headers other than Host (httpRequestFromUrl already sets Host).
        for (var header : base.headers()) {
            if (header.name() != null && !"host".equalsIgnoreCase(header.name())) {
                result = result.withAddedHeader(header);
            }
        }
        return result;
    }

    private static int parseSilently(String s) {
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private AuditIssue buildIssue(HttpRequestResponse base,
                                  HttpRequestResponse evidence,
                                  int currentVersion,
                                  int olderVersion) {
        String detail =
                "Endpoint <code>" + base.request().pathWithoutQuery() + "</code> belongs to " +
                "API <code>v" + currentVersion + "</code>. The same endpoint at API " +
                "<code>v" + olderVersion + "</code> also returned a 2xx response — meaning " +
                "an older version of the API surface is still reachable on this host.<br><br>" +
                "Probed path: <code>" + evidence.request().pathWithoutQuery() + "</code>";
        String remediation =
                "Either remove the older version from production, redirect it to the current " +
                "version, or restrict access (mTLS, allow-list).";
        return IssueBuilder.issue(base)
                .name("API9:2023 - Improper Inventory Management (Deprecated Version Reachable: v" + olderVersion + ")")
                .detail(detail)
                .remediation(remediation)
                .background(ISSUE_BACKGROUND)
                .severity("Medium")
                .confidence("Firm")
                .evidence(base, evidence)
                .build();
    }
}
