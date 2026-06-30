package com.security.burp.checks.active;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import com.security.burp.ai.AiFieldDiscovery;
import com.security.burp.checks.AbstractActiveCheck;
import com.security.burp.util.HttpUtils;
import com.security.burp.util.IssueBuilder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * OWASP API3:2023 — Broken Object Property Level Authorization (mass-
 * assignment side).
 *
 * <p>For each modifying request with a JSON body, injects each candidate
 * privileged field individually and looks for it being echoed back in the
 * response. The candidate set is the union of:
 * <ul>
 *   <li>a hardcoded list of well-known privileged names ({@code isAdmin},
 *       {@code role}, {@code balance}, ...);</li>
 *   <li>contextual names suggested by Burp AI when available — these are
 *       domain-specific fields the model thinks the server might accept
 *       given the observed request shape (e.g. {@code priceOverride} on a
 *       cart endpoint, {@code organizationRole} on a multi-tenant API).</li>
 * </ul>
 *
 * <p>Registered {@code PER_INSERTION_POINT}; deduped per
 * {@code (host + method + path + body-hash)} so whole-body mutation runs
 * once per base request, not once per insertion point.
 */
public final class MassAssignmentCheck extends AbstractActiveCheck {

    private static final List<String> HARDCODED_FIELDS = List.of(
            "isAdmin", "is_admin", "admin", "role", "roles",
            "permissions", "is_verified", "isVerified", "verified",
            "is_active", "isActive", "active", "status",
            "password", "email_verified", "emailVerified",
            "balance", "credit", "credits", "premium", "isPremium");

    private static final List<String> COMBO_FIELDS = List.of(
            "isAdmin", "role", "verified", "premium");

    private static final String ISSUE_BACKGROUND =
            "API3:2023 - Broken Object Property Level Authorization<br><br>" +
            "Failures here come from missing authorization at the property level: the API " +
            "blindly accepts any property the client sends and writes it through to the " +
            "model, allowing an attacker to set fields they shouldn't be able to.";

    private final AiFieldDiscovery fieldDiscovery;
    private final Set<String> dedupe = Collections.newSetFromMap(new ConcurrentHashMap<>());

    public MassAssignmentCheck(MontoyaApi api, AiFieldDiscovery fieldDiscovery) {
        super(api);
        this.fieldDiscovery = fieldDiscovery;
    }

    @Override
    public String checkName() {
        return "API3:2023 Mass Assignment";
    }

    @Override
    protected List<AuditIssue> audit(HttpRequestResponse rr, AuditInsertionPoint ip, Http http) {
        HttpRequest request = rr.request();
        if (!HttpUtils.isModifyingMethod(request.method())) return List.of();
        if (!HttpUtils.isJson(request)) return List.of();
        if (!shouldRunOnce(request)) return List.of();

        String body = request.bodyToString();
        if (body == null || body.isEmpty()) return List.of();

        JsonObject originalBody = parseJsonObjectOrNull(body);
        if (originalBody == null) return List.of();

        api.logging().logToOutput("[Mass Assignment] Testing: " + request.pathWithoutQuery());

        List<AuditIssue> issues = new ArrayList<>();
        Set<String> candidates = candidateFields(request, body);
        for (String field : candidates) {
            AuditIssue issue = testField(rr, http, originalBody, field);
            if (issue != null) issues.add(issue);
        }
        AuditIssue combo = testCombination(rr, http, originalBody);
        if (combo != null) issues.add(combo);
        return issues;
    }

    // ---- Candidate field assembly ------------------------------------------

    private Set<String> candidateFields(HttpRequest request, String body) {
        Set<String> all = new LinkedHashSet<>(HARDCODED_FIELDS);
        if (fieldDiscovery != null && fieldDiscovery.isAvailable()) {
            all.addAll(fieldDiscovery.suggestFields(
                    request.httpService().host(),
                    request.pathWithoutQuery(),
                    request.method(),
                    body));
        }
        return all;
    }

    private boolean shouldRunOnce(HttpRequest request) {
        String key = request.httpService().host() + "|" +
                request.method() + "|" +
                request.pathWithoutQuery() + "|" +
                Integer.toHexString(request.bodyToString().hashCode());
        return dedupe.add(key);
    }

    // ---- Single-field test -------------------------------------------------

    private AuditIssue testField(HttpRequestResponse rr,
                                 Http http,
                                 JsonObject originalBody,
                                 String field) {
        if (originalBody.has(field)) return null;
        for (Object value : testValuesFor(field)) {
            JsonObject mutated = originalBody.deepCopy();
            assignProperty(mutated, field, value);
            HttpRequestResponse evidence = sendBody(rr, http, mutated.toString());
            if (evidence == null) continue;
            if (fieldGenuinelyAccepted(rr, evidence, field)) {
                boolean privEsc = looksPrivilegeEscalating(field);
                return buildSingleFieldIssue(rr, evidence, field, value.toString(), privEsc);
            }
        }
        return null;
    }

    private static void assignProperty(JsonObject obj, String field, Object value) {
        if (value instanceof Boolean b) obj.addProperty(field, b);
        else if (value instanceof Number n) obj.addProperty(field, n);
        else obj.addProperty(field, value.toString());
    }

    private static Object[] testValuesFor(String field) {
        String lower = field.toLowerCase(Locale.ROOT);
        if (lower.contains("admin"))                 return new Object[]{true};
        if (lower.contains("role"))                  return new Object[]{"admin", "administrator", "superuser"};
        if (lower.contains("verified") || lower.contains("active"))
                                                     return new Object[]{true};
        if (lower.contains("balance") || lower.contains("credit"))
                                                     return new Object[]{999_999, 1_000_000};
        if (lower.contains("premium"))               return new Object[]{true};
        if (lower.contains("status"))                return new Object[]{"active", "approved", "verified"};
        return new Object[]{true, "admin", 1};
    }

    private static boolean looksPrivilegeEscalating(String field) {
        String lower = field.toLowerCase(Locale.ROOT);
        return lower.contains("admin") || lower.contains("role") || lower.contains("permission");
    }

    // ---- Multi-field combo test --------------------------------------------

    private AuditIssue testCombination(HttpRequestResponse rr, Http http, JsonObject originalBody) {
        JsonObject mutated = originalBody.deepCopy();
        mutated.addProperty("isAdmin", true);
        mutated.addProperty("role", "admin");
        mutated.addProperty("verified", true);
        mutated.addProperty("premium", true);
        HttpRequestResponse evidence = sendBody(rr, http, mutated.toString());
        if (evidence == null) return null;

        List<String> accepted = new ArrayList<>();
        for (String field : COMBO_FIELDS) {
            if (fieldGenuinelyAccepted(rr, evidence, field)) accepted.add(field);
        }
        return accepted.isEmpty() ? null : buildComboIssue(rr, evidence, accepted);
    }

    // ---- HTTP and parsing helpers ------------------------------------------

    private HttpRequestResponse sendBody(HttpRequestResponse rr, Http http, String body) {
        try {
            HttpRequest mutated = rr.request().withBody(body);
            HttpRequestResponse response = http.sendRequest(mutated);
            if (response == null || !response.hasResponse()) return null;
            int status = response.response().statusCode();
            return (status >= 200 && status < 300) ? response : null;
        } catch (Exception e) {
            api.logging().logToError("[Mass Assignment] Send failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Treat a field as genuinely accepted only when:
     * <ul>
     *   <li>it appears in the payload response, AND</li>
     *   <li>it did NOT already appear in the baseline response — so a field
     *       name that lives in a schema/metadata block (present either way)
     *       doesn't count, AND</li>
     *   <li>the response doesn't read as a validation rejection
     *       (e.g. {@code "Field 'isAdmin' is not allowed"}).</li>
     * </ul>
     * Residual limitation: an endpoint that echoes the raw request body back
     * for audit/logging will still match, since the field is genuinely new vs
     * baseline. Distinguishing echo from persistence isn't possible from a
     * single response; the Firm (not Certain) confidence reflects that.
     */
    private static boolean fieldGenuinelyAccepted(HttpRequestResponse base,
                                                  HttpRequestResponse evidence,
                                                  String field) {
        String body = evidence.response().bodyToString();
        if (body == null) return false;
        String token = "\"" + field + "\"";
        if (!body.contains(token)) return false;
        if (HttpUtils.looksRejected(evidence.response())) return false;
        // New vs baseline: if the field name was already in the baseline
        // response (schema/docs), its presence now proves nothing.
        return !HttpUtils.baselineContains(base, token);
    }

    private static JsonObject parseJsonObjectOrNull(String body) {
        try {
            JsonElement element = JsonParser.parseString(body);
            return element.isJsonObject() ? element.getAsJsonObject() : null;
        } catch (JsonSyntaxException e) {
            return null;
        }
    }

    // ---- Issues ------------------------------------------------------------

    private AuditIssue buildSingleFieldIssue(HttpRequestResponse base,
                                             HttpRequestResponse evidence,
                                             String field,
                                             String value,
                                             boolean privEsc) {
        String name = privEsc
                ? "API3:2023 - Mass Assignment Privilege Escalation"
                : "API3:2023 - Broken Object Property Level Authorization (Mass Assignment)";

        String safeField = IssueBuilder.escapeHtml(field);
        String safeValue = IssueBuilder.escapeHtml(value);
        String detail = privEsc
                ? "Sending <code>" + safeField + " = " + safeValue + "</code> in the request body " +
                  "caused the previously-absent field to be accepted and echoed in the response. " +
                  "The field name suggests a privileged property, so this is a candidate " +
                  "mass-assignment privilege escalation.<br><br>Note: the field was echoed, which " +
                  "is not by itself proof it was persisted — confirm the change took effect on a " +
                  "subsequent read."
                : "The endpoint accepted the previously-absent field <code>" + safeField + "</code> " +
                  "(value: <code>" + safeValue + "</code>) and echoed it back in the response.";

        return IssueBuilder.issue(base)
                .name(name)
                .detail(detail)
                .remediation("Use explicit allow-lists / DTOs at the controller layer; never " +
                        "spread the request body into the model.")
                .background(ISSUE_BACKGROUND)
                .severity(privEsc ? "Critical" : "High")
                .confidence("Firm")
                .evidence(base, evidence)
                .build();
    }

    private AuditIssue buildComboIssue(HttpRequestResponse base,
                                       HttpRequestResponse evidence,
                                       List<String> accepted) {
        StringBuilder escapedList = new StringBuilder();
        for (int i = 0; i < accepted.size(); i++) {
            if (i > 0) escapedList.append(", ");
            escapedList.append(IssueBuilder.escapeHtml(accepted.get(i)));
        }
        String detail =
                "The endpoint accepted multiple privileged fields in a single request: <b>" +
                escapedList + "</b>. " +
                "This is the worst case for mass assignment — a single request can flip " +
                "every privileged property at once.<br><br>" +
                "Note: the fields were echoed in the response, which is not by itself proof " +
                "they were persisted — confirm the change took effect on a subsequent read.";
        return IssueBuilder.issue(base)
                .name("API3:2023 - Broken Object Property Level Authorization (Multiple Field Mass Assignment)")
                .detail(detail)
                .remediation("Apply a strict allow-list of writable fields, especially for " +
                        "anything affecting roles, verification, or billing.")
                .background(ISSUE_BACKGROUND)
                .severity("High")
                // Firm, not Certain: an echoed value isn't proof of persistence.
                .confidence("Firm")
                .evidence(base, evidence)
                .build();
    }
}
