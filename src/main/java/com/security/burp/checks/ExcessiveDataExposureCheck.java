package com.security.burp.checks;

import burp.*;
import com.google.gson.*;
import com.security.burp.model.CustomScanIssue;
import java.io.PrintWriter;
import java.util.*;

/**
 * Excessive Data Exposure Check
 * OWASP API3:2023 - Broken Object Property Level Authorization
 * Detects when APIs return more data than necessary (information exposure aspect)
 */
public class ExcessiveDataExposureCheck {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final PrintWriter stdout;
    private final Gson gson;

    // Sensitive fields that shouldn't be exposed
    private static final String[] SENSITIVE_FIELDS = {
        "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
        "private_key", "privatekey", "ssn", "social_security", "credit_card",
        "cvv", "pin", "salt", "hash", "internal_id", "internal"
    };

    public ExcessiveDataExposureCheck(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
                                     PrintWriter stdout) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.stdout = stdout;
        this.gson = new GsonBuilder().setPrettyPrinting().create();
    }

    public List<IScanIssue> checkPassive(IHttpRequestResponse baseRequestResponse) {
        List<IScanIssue> issues = new ArrayList<>();

        try {
            if (baseRequestResponse.getResponse() == null) {
                return issues;
            }

            IResponseInfo responseInfo = helpers.analyzeResponse(baseRequestResponse.getResponse());
            String contentType = getContentType(responseInfo.getHeaders());

            if (contentType == null || !contentType.contains("application/json")) {
                return issues;
            }

            int bodyOffset = responseInfo.getBodyOffset();
            if (bodyOffset >= baseRequestResponse.getResponse().length) {
                return issues;
            }

            String responseBody = new String(Arrays.copyOfRange(
                baseRequestResponse.getResponse(),
                bodyOffset,
                baseRequestResponse.getResponse().length
            ));

            try {
                JsonElement jsonElement = JsonParser.parseString(responseBody);

                // Check for sensitive fields
                List<String> foundSensitiveFields = findSensitiveFields(jsonElement, "");

                if (!foundSensitiveFields.isEmpty()) {
                    stdout.println("[Data Exposure] ⚠️  Sensitive fields found: " + foundSensitiveFields);
                    issues.add(createSensitiveDataIssue(baseRequestResponse, foundSensitiveFields,
                              responseBody));
                }

                // Check for excessive array responses
                if (jsonElement.isJsonArray()) {
                    JsonArray array = jsonElement.getAsJsonArray();
                    if (array.size() > 100) {
                        stdout.println("[Data Exposure] Large array response: " + array.size() + " items");
                        issues.add(createLargeResponseIssue(baseRequestResponse, array.size()));
                    }

                    // Check for inconsistent filtering
                    if (array.size() > 0 && array.get(0).isJsonObject()) {
                        Set<String> allFields = getAllFields(array);
                        if (allFields.size() > 20) {
                            stdout.println("[Data Exposure] Response contains " + allFields.size() + " fields");
                            issues.add(createExcessiveFieldsIssue(baseRequestResponse, allFields));
                        }
                    }
                }

            } catch (JsonSyntaxException e) {
                // Not valid JSON, skip
            }

        } catch (Exception e) {
            stdout.println("[Data Exposure] Error: " + e.getMessage());
        }

        return issues;
    }

    private List<String> findSensitiveFields(JsonElement element, String path) {
        List<String> found = new ArrayList<>();

        if (element.isJsonObject()) {
            JsonObject obj = element.getAsJsonObject();
            for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
                String fieldName = entry.getKey().toLowerCase();
                String fullPath = path.isEmpty() ? entry.getKey() : path + "." + entry.getKey();

                // Check if field name matches sensitive patterns
                for (String sensitiveField : SENSITIVE_FIELDS) {
                    if (fieldName.contains(sensitiveField)) {
                        // Check if it's actually sensitive (not empty/null)
                        if (!entry.getValue().isJsonNull() &&
                            !(entry.getValue().isJsonPrimitive() &&
                              entry.getValue().getAsString().isEmpty())) {
                            found.add(fullPath);
                            break;
                        }
                    }
                }

                // Recurse into nested objects/arrays
                if (entry.getValue().isJsonObject() || entry.getValue().isJsonArray()) {
                    found.addAll(findSensitiveFields(entry.getValue(), fullPath));
                }
            }
        } else if (element.isJsonArray()) {
            JsonArray array = element.getAsJsonArray();
            for (int i = 0; i < Math.min(array.size(), 10); i++) { // Check first 10 items
                found.addAll(findSensitiveFields(array.get(i), path + "[" + i + "]"));
            }
        }

        return found;
    }

    private Set<String> getAllFields(JsonArray array) {
        Set<String> allFields = new HashSet<>();

        for (int i = 0; i < Math.min(array.size(), 10); i++) {
            if (array.get(i).isJsonObject()) {
                JsonObject obj = array.get(i).getAsJsonObject();
                allFields.addAll(obj.keySet());
            }
        }

        return allFields;
    }

    private String getContentType(List<String> headers) {
        for (String header : headers) {
            if (header.toLowerCase().startsWith("content-type:")) {
                return header.substring(13).trim().toLowerCase();
            }
        }
        return null;
    }

    private IScanIssue createSensitiveDataIssue(IHttpRequestResponse baseRequestResponse,
                                                List<String> sensitiveFields,
                                                String responseBody) {
        String issueName = "API3:2023 - Broken Object Property Level Authorization (Sensitive Data Exposure)";

        StringBuilder fieldList = new StringBuilder();
        for (String field : sensitiveFields) {
            fieldList.append("- ").append(field).append("<br>");
        }

        String issueDetail = "The API response contains sensitive fields that should not be exposed:<br><br>" +
                           fieldList.toString() + "<br>" +
                           "These fields may contain passwords, tokens, internal IDs, or other sensitive " +
                           "information. APIs should filter response data to only include necessary fields.";

        String issueBackground = "API3:2023 - Broken Object Property Level Authorization<br><br>" +
                               "This category combines API3:2019 Excessive Data Exposure and API6:2019 - Mass Assignment, " +
                               "focusing on the root cause: the lack of or improper authorization validation at the object " +
                               "property level. This leads to information exposure or manipulation by unauthorized parties.";

        return new CustomScanIssue(
            baseRequestResponse.getHttpService(),
            helpers.analyzeRequest(baseRequestResponse).getUrl(),
            new IHttpRequestResponse[]{baseRequestResponse},
            issueName,
            issueDetail,
            issueBackground,
            "Medium",
            "Firm"
        );
    }

    private IScanIssue createLargeResponseIssue(IHttpRequestResponse baseRequestResponse, int itemCount) {
        String issueName = "API3:2023 - Broken Object Property Level Authorization (Large Unbounded Response)";
        String issueDetail = "The API returned " + itemCount + " items in a single response without " +
                           "apparent pagination limits. This can lead to:<br><br>" +
                           "- Performance issues<br>" +
                           "- Information disclosure (exposing entire datasets)<br>" +
                           "- Resource exhaustion<br>" +
                           "- Denial of service<br><br>" +
                           "Recommendation: Implement pagination with reasonable default limits (e.g., 10-100 items).";

        String issueBackground = "API3:2023 - Broken Object Property Level Authorization<br><br>" +
                               "This category combines API3:2019 Excessive Data Exposure and API6:2019 - Mass Assignment, " +
                               "focusing on the root cause: the lack of or improper authorization validation at the object " +
                               "property level. This leads to information exposure or manipulation by unauthorized parties.";

        return new CustomScanIssue(
            baseRequestResponse.getHttpService(),
            helpers.analyzeRequest(baseRequestResponse).getUrl(),
            new IHttpRequestResponse[]{baseRequestResponse},
            issueName,
            issueDetail,
            issueBackground,
            "Low",
            "Firm"
        );
    }

    private IScanIssue createExcessiveFieldsIssue(IHttpRequestResponse baseRequestResponse,
                                                  Set<String> fields) {
        String issueName = "API3:2023 - Broken Object Property Level Authorization (Excessive Fields)";
        String issueDetail = "The API response contains " + fields.size() + " different fields. " +
                           "This may indicate that complete internal objects are being returned without " +
                           "proper filtering.<br><br>" +
                           "Fields should be limited to only what the client needs. Consider implementing " +
                           "field filtering (e.g., ?fields=id,name,email) or using DTOs (Data Transfer Objects).";

        String issueBackground = "API3:2023 - Broken Object Property Level Authorization<br><br>" +
                               "This category combines API3:2019 Excessive Data Exposure and API6:2019 - Mass Assignment, " +
                               "focusing on the root cause: the lack of or improper authorization validation at the object " +
                               "property level. This leads to information exposure or manipulation by unauthorized parties.";

        return new CustomScanIssue(
            baseRequestResponse.getHttpService(),
            helpers.analyzeRequest(baseRequestResponse).getUrl(),
            new IHttpRequestResponse[]{baseRequestResponse},
            issueName,
            issueDetail,
            issueBackground,
            "Information",
            "Firm"
        );
    }
}
