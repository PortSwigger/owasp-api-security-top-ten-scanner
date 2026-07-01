package com.security.burp.checks.passive;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import com.security.burp.ai.AiTriage;
import com.security.burp.checks.AbstractPassiveCheck;
import com.security.burp.scanner.EndpointRegistry;
import com.security.burp.util.HttpUtils;
import com.security.burp.util.IssueBuilder;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * OWASP API3:2023 — Excessive Data Exposure (one face of Broken Object
 * Property Level Authorization).
 *
 * <p>Two response-shape signals that Burp's native scanner does not report:
 * <ul>
 *   <li>top-level array with very large item count (suggests no pagination);</li>
 *   <li>top-level array whose elements expose a large number of distinct
 *       fields (suggests no DTO / field filtering).</li>
 * </ul>
 *
 * <p>The earlier sensitive-field-by-name signal stays removed as of v2.3.0:
 * matching field names was a weak heuristic (empty {@code password_hash}
 * fields, benign {@code content_hash}, etc.), and the native scanner reports
 * actual value leaks ("Password returned in response", "Credit card numbers
 * disclosed", "Private key disclosed") at higher confidence. Those native
 * checks are cross-referenced from the issues below; the response-shape
 * signals here are the part native does not cover.
 */
public final class ExcessiveDataExposureCheck extends AbstractPassiveCheck {

    private static final int LARGE_ARRAY_ITEMS = 100;
    private static final int EXCESSIVE_FIELD_COUNT = 20;
    /** Limit recursive descent into JSON to avoid pathological inputs. */
    private static final int MAX_ARRAY_SAMPLE = 10;

    private static final String ISSUE_BACKGROUND =
            "API3:2023 - Broken Object Property Level Authorization<br><br>" +
            "This category combines the legacy Excessive Data Exposure and Mass Assignment " +
            "categories. The root cause is missing authorization at the property level: " +
            "fields are returned to (or accepted from) clients that should not see or " +
            "modify them.";

    /**
     * Cross-reference to native Burp coverage (DAST-compatible; static). This
     * check reports the response <em>shape</em> (unbounded arrays, over-broad
     * projections); specific value leaks are the native scanner's job.
     */
    private static final String RELATED_CHECKS =
            "<br><br><b>Related Burp Scanner checks:</b> for specific sensitive values in " +
            "responses refer to the native <b>Password returned in later response</b>, " +
            "<b>Credit card numbers disclosed</b>, <b>Private key disclosed</b> and " +
            "<b>Cleartext submission of password</b> checks in the " +
            "<a href=\"https://portswigger.net/burp/documentation/scanner/vulnerabilities-list\">" +
            "Burp Scanner vulnerabilities list</a>. This check covers the response shape " +
            "those don't.";

    public ExcessiveDataExposureCheck(MontoyaApi api, EndpointRegistry endpoints, AiTriage triage) {
        super(api, endpoints, triage);
    }

    @Override
    public String checkName() {
        return "API3:2023 Excessive Data Exposure";
    }

    @Override
    protected List<AuditIssue> audit(HttpRequestResponse rr) {
        if (!rr.hasResponse()) return List.of();
        if (!HttpUtils.isJson(rr.response())) return List.of();

        String body = rr.response().bodyToString();
        if (body == null || body.isEmpty()) return List.of();

        JsonElement root = parseSilently(body);
        if (root == null) return List.of();

        // The sensitive-field-by-name test was removed — Burp's native scanner
        // already reports specific leaks ("Password returned in response",
        // "Credit card numbers disclosed", "Private key disclosed", etc.) at
        // higher confidence. We keep the API-shape signals native doesn't:
        // unbounded arrays and over-broad object projections.
        List<AuditIssue> issues = new ArrayList<>();

        if (root.isJsonArray()) {
            JsonArray array = root.getAsJsonArray();
            // A large array is only "unbounded" if the response shows no sign
            // of pagination. A well-designed paginated API legitimately returns
            // 100+ items per page alongside pagination headers / params.
            if (array.size() > LARGE_ARRAY_ITEMS && !looksPaginated(rr)) {
                issues.add(buildLargeArrayIssue(rr, array.size()));
            }

            Set<String> fields = collectFieldNames(array);
            if (fields.size() > EXCESSIVE_FIELD_COUNT) issues.add(buildExcessiveFieldsIssue(rr, fields));
        }
        return issues;
    }

    /** True if request or response carries a recognisable pagination signal. */
    private static boolean looksPaginated(HttpRequestResponse rr) {
        for (HttpHeader header : rr.response().headers()) {
            String name = header.name();
            if (name == null) continue;
            String lower = name.toLowerCase(Locale.ROOT);
            if (lower.equals("link") || lower.startsWith("x-total") || lower.startsWith("x-page")
                    || lower.startsWith("x-per-page") || lower.startsWith("x-next")
                    || lower.startsWith("x-pagination")) {
                return true;
            }
        }
        String query = rr.request().query();
        if (query == null) return false;
        String q = query.toLowerCase(Locale.ROOT);
        return q.contains("page") || q.contains("offset") || q.contains("limit")
                || q.contains("per_page") || q.contains("cursor");
    }

    // ---- JSON walking ------------------------------------------------------

    private static JsonElement parseSilently(String body) {
        try {
            return JsonParser.parseString(body);
        } catch (JsonSyntaxException e) {
            return null;
        }
    }

    private static Set<String> collectFieldNames(JsonArray array) {
        Set<String> names = new HashSet<>();
        int limit = Math.min(array.size(), MAX_ARRAY_SAMPLE);
        for (int i = 0; i < limit; i++) {
            JsonElement element = array.get(i);
            if (element.isJsonObject()) names.addAll(element.getAsJsonObject().keySet());
        }
        return names;
    }

    // ---- Issues ------------------------------------------------------------

    private AuditIssue buildLargeArrayIssue(HttpRequestResponse rr, int itemCount) {
        String detail =
                "The endpoint returned " + itemCount + " items in a single array without an " +
                "obvious pagination control. Unbounded list responses can leak entire datasets " +
                "and create denial-of-service risk on the client.";
        String remediation =
                "Apply server-side pagination with a small default page size and an explicit " +
                "cap on the maximum requestable size.";
        return IssueBuilder.issue(rr)
                .name("API3:2023 - Broken Object Property Level Authorization (Large Unbounded Response)")
                .detail(detail + RELATED_CHECKS)
                .remediation(remediation)
                .background(ISSUE_BACKGROUND)
                .severity("Low")
                .confidence("Firm")
                .build();
    }

    private AuditIssue buildExcessiveFieldsIssue(HttpRequestResponse rr, Set<String> fields) {
        String detail =
                "Items in the array response carry " + fields.size() + " distinct field names. " +
                "This usually means the back-end model is being serialized wholesale rather " +
                "than projected through a DTO — a common path to property-level data leaks.";
        String remediation =
                "Use DTOs or explicit field selection (e.g. <code>?fields=id,name,email</code>) " +
                "to return only the data the client needs.";
        return IssueBuilder.issue(rr)
                .name("API3:2023 - Broken Object Property Level Authorization (Excessive Fields)")
                .detail(detail + RELATED_CHECKS)
                .remediation(remediation)
                .background(ISSUE_BACKGROUND)
                .severity("Information")
                .confidence("Firm")
                .build();
    }
}
