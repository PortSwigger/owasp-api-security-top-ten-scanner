package com.security.burp.checks.passive;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
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
import java.util.Map;
import java.util.Set;

/**
 * OWASP API3:2023 — Excessive Data Exposure (one face of Broken Object
 * Property Level Authorization).
 *
 * <p>Three signals from the JSON response body:
 * <ul>
 *   <li>presence of fields whose <em>name</em> looks sensitive (password,
 *       token, ssn, ...);</li>
 *   <li>top-level array with very large item count (suggests no pagination);</li>
 *   <li>top-level array whose elements expose a large number of distinct
 *       fields (suggests no DTO / field filtering).</li>
 * </ul>
 */
public final class ExcessiveDataExposureCheck extends AbstractPassiveCheck {

    private static final int LARGE_ARRAY_ITEMS = 100;
    private static final int EXCESSIVE_FIELD_COUNT = 20;
    /** Limit recursive descent into JSON to avoid pathological inputs. */
    private static final int MAX_ARRAY_SAMPLE = 10;

    private static final Set<String> SENSITIVE_FIELD_KEYWORDS = Set.of(
            "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
            "private_key", "privatekey", "ssn", "social_security", "credit_card",
            "cvv", "pin", "salt", "hash", "internal_id", "internal");

    /**
     * Field-name substrings that contain a sensitive keyword but are benign —
     * integrity hashes, cache validators, and password <em>policy</em>
     * metadata. Matched as substrings; a field whose name contains any of
     * these is not flagged even if it also matches a sensitive keyword. Stops
     * the check firing on {@code content_hash}, {@code etag},
     * {@code password_expiry_days}, etc.
     */
    private static final Set<String> BENIGN_FIELD_EXCEPTIONS = Set.of(
            "content_hash", "contenthash", "integrity_hash", "integrityhash",
            "checksum", "etag", "hashtag", "hash_tag",
            "password_change", "passwordchange", "password_expir", "passwordexpir",
            "password_policy", "passwordpolicy", "password_rotation", "passwordrotation",
            "password_last", "passwordlast", "password_required", "passwordrequired",
            "token_expir", "tokenexpir", "token_type", "tokentype");

    private static final String ISSUE_BACKGROUND =
            "API3:2023 - Broken Object Property Level Authorization<br><br>" +
            "This category combines the legacy Excessive Data Exposure and Mass Assignment " +
            "categories. The root cause is missing authorization at the property level: " +
            "fields are returned to (or accepted from) clients that should not see or " +
            "modify them.";

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

        List<AuditIssue> issues = new ArrayList<>();
        List<String> sensitive = findSensitiveFields(root, "");
        if (!sensitive.isEmpty()) issues.add(buildSensitiveDataIssue(rr, sensitive));

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

    private static List<String> findSensitiveFields(JsonElement element, String path) {
        List<String> found = new ArrayList<>();
        if (element.isJsonObject()) {
            walkObject(element.getAsJsonObject(), path, found);
        } else if (element.isJsonArray()) {
            walkArray(element.getAsJsonArray(), path, found);
        }
        return found;
    }

    private static void walkObject(JsonObject obj, String path, List<String> sink) {
        for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
            String fieldName = entry.getKey().toLowerCase(Locale.ROOT);
            String fullPath = path.isEmpty() ? entry.getKey() : path + "." + entry.getKey();
            JsonElement value = entry.getValue();

            if (matchesSensitiveKeyword(fieldName) && hasMeaningfulValue(value)) {
                sink.add(fullPath);
            }
            if (value.isJsonObject() || value.isJsonArray()) {
                sink.addAll(findSensitiveFields(value, fullPath));
            }
        }
    }

    private static void walkArray(JsonArray array, String path, List<String> sink) {
        int limit = Math.min(array.size(), MAX_ARRAY_SAMPLE);
        for (int i = 0; i < limit; i++) {
            sink.addAll(findSensitiveFields(array.get(i), path + "[" + i + "]"));
        }
    }

    private static boolean matchesSensitiveKeyword(String fieldNameLower) {
        for (String benign : BENIGN_FIELD_EXCEPTIONS) {
            if (fieldNameLower.contains(benign)) return false;
        }
        for (String keyword : SENSITIVE_FIELD_KEYWORDS) {
            if (fieldNameLower.contains(keyword)) return true;
        }
        return false;
    }

    private static boolean hasMeaningfulValue(JsonElement value) {
        if (value.isJsonNull()) return false;
        if (value.isJsonPrimitive() && value.getAsString().isEmpty()) return false;
        return true;
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

    private AuditIssue buildSensitiveDataIssue(HttpRequestResponse rr, List<String> paths) {
        StringBuilder list = new StringBuilder();
        for (String path : paths) {
            list.append("- <code>").append(IssueBuilder.escapeHtml(path)).append("</code><br>");
        }
        String detail =
                "Fields whose names suggest sensitive content appear in the response:<br><br>" +
                list + "<br>Filter response payloads with explicit allow-lists (DTOs) so that " +
                "back-end model fields cannot leak by accident.";
        return IssueBuilder.issue(rr)
                .name("API3:2023 - Broken Object Property Level Authorization (Sensitive Data Exposure)")
                .detail(detail)
                .background(ISSUE_BACKGROUND)
                .severity("Medium")
                .confidence("Firm")
                .build();
    }

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
                .detail(detail)
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
                .detail(detail)
                .remediation(remediation)
                .background(ISSUE_BACKGROUND)
                .severity("Information")
                .confidence("Firm")
                .build();
    }
}
