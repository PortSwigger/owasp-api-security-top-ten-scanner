package com.security.burp.checks;

import burp.*;
import com.google.gson.*;
import com.security.burp.model.CustomScanIssue;
import java.io.PrintWriter;
import java.util.*;

/**
 * Mass Assignment Check
 * OWASP API3:2023 - Broken Object Property Level Authorization
 * Tests for mass assignment vulnerabilities (manipulation aspect)
 */
public class MassAssignmentCheck {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final PrintWriter stdout;
    private final Gson gson;

    // Common sensitive fields that shouldn't be mass-assignable
    private static final String[] SENSITIVE_FIELDS = {
        "isAdmin", "is_admin", "admin", "role", "roles",
        "permissions", "is_verified", "isVerified", "verified",
        "is_active", "isActive", "active", "status",
        "password", "email_verified", "emailVerified",
        "balance", "credit", "credits", "premium", "isPremium"
    };

    public MassAssignmentCheck(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
                              PrintWriter stdout) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.stdout = stdout;
        this.gson = new Gson();
    }

    public List<IScanIssue> checkMassAssignment(IHttpRequestResponse baseRequestResponse,
                                                IScannerInsertionPoint insertionPoint) {
        List<IScanIssue> issues = new ArrayList<>();

        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);

            // Only check POST, PUT, PATCH requests with JSON bodies
            if (!isModifyingRequest(requestInfo.getMethod())) {
                return issues;
            }

            String contentType = getContentType(requestInfo.getHeaders());
            if (contentType == null || !contentType.contains("application/json")) {
                return issues;
            }

            stdout.println("[Mass Assignment] Testing endpoint: " + requestInfo.getUrl().getPath());

            // Parse request body
            byte[] request = baseRequestResponse.getRequest();
            int bodyOffset = requestInfo.getBodyOffset();
            if (bodyOffset >= request.length) {
                return issues;
            }

            String body = new String(Arrays.copyOfRange(request, bodyOffset, request.length));

            try {
                JsonElement jsonElement = JsonParser.parseString(body);
                if (jsonElement.isJsonObject()) {
                    JsonObject originalJson = jsonElement.getAsJsonObject();

                    // Test each sensitive field
                    for (String sensitiveField : SENSITIVE_FIELDS) {
                        issues.addAll(testSensitiveField(baseRequestResponse, originalJson, sensitiveField));
                    }

                    // Test adding multiple sensitive fields at once
                    issues.addAll(testMultipleSensitiveFields(baseRequestResponse, originalJson));
                }
            } catch (JsonSyntaxException e) {
                stdout.println("[Mass Assignment] Invalid JSON body");
            }

        } catch (Exception e) {
            stdout.println("[Mass Assignment] Error: " + e.getMessage());
        }

        return issues;
    }

    private boolean isModifyingRequest(String method) {
        return method.equals("POST") || method.equals("PUT") || method.equals("PATCH");
    }

    private String getContentType(List<String> headers) {
        for (String header : headers) {
            if (header.toLowerCase().startsWith("content-type:")) {
                return header.substring(13).trim().toLowerCase();
            }
        }
        return null;
    }

    private List<IScanIssue> testSensitiveField(IHttpRequestResponse baseRequestResponse,
                                                JsonObject originalJson, String field) {
        List<IScanIssue> issues = new ArrayList<>();

        try {
            // Skip if field already exists
            if (originalJson.has(field)) {
                return issues;
            }

            // Create modified JSON with sensitive field
            JsonObject modifiedJson = originalJson.deepCopy();

            // Try different values based on field name
            Object[] testValues = getTestValuesForField(field);

            for (Object testValue : testValues) {
                if (testValue instanceof Boolean) {
                    modifiedJson.addProperty(field, (Boolean) testValue);
                } else if (testValue instanceof Number) {
                    modifiedJson.addProperty(field, (Number) testValue);
                } else {
                    modifiedJson.addProperty(field, testValue.toString());
                }

                // Build and send request
                byte[] modifiedRequest = buildRequestWithJson(baseRequestResponse, modifiedJson.toString());
                IHttpRequestResponse testResponse = callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), modifiedRequest);

                // Analyze response
                if (testResponse.getResponse() != null) {
                    IResponseInfo responseInfo = helpers.analyzeResponse(testResponse.getResponse());
                    int statusCode = responseInfo.getStatusCode();

                    // Success indicates potential mass assignment
                    if (statusCode >= 200 && statusCode < 300) {
                        String responseBody = getResponseBody(testResponse.getResponse(), responseInfo);

                        // Check if the field appears in the response
                        if (responseBody.contains("\"" + field + "\"")) {
                            // Check specifically for privilege escalation
                            boolean isPrivilegeEscalation = field.toLowerCase().contains("role") ||
                                                           field.toLowerCase().contains("admin") ||
                                                           field.toLowerCase().contains("permission");

                            if (isPrivilegeEscalation) {
                                stdout.println("[Mass Assignment] 🚨 PRIVILEGE ESCALATION: Field '" + field +
                                             "' can be modified to '" + testValue + "'!");
                            } else {
                                stdout.println("[Mass Assignment] ⚠️  Sensitive field '" + field +
                                             "' accepted and returned!");
                            }

                            issues.add(createMassAssignmentIssue(baseRequestResponse, testResponse,
                                      field, testValue.toString(), isPrivilegeEscalation));
                            return issues; // One finding per field is enough
                        }
                    }
                }
            }

        } catch (Exception e) {
            stdout.println("[Mass Assignment] Field test error: " + e.getMessage());
        }

        return issues;
    }

    private List<IScanIssue> testMultipleSensitiveFields(IHttpRequestResponse baseRequestResponse,
                                                         JsonObject originalJson) {
        List<IScanIssue> issues = new ArrayList<>();

        try {
            JsonObject modifiedJson = originalJson.deepCopy();

            // Add multiple sensitive fields
            modifiedJson.addProperty("isAdmin", true);
            modifiedJson.addProperty("role", "admin");
            modifiedJson.addProperty("verified", true);
            modifiedJson.addProperty("premium", true);

            byte[] modifiedRequest = buildRequestWithJson(baseRequestResponse, modifiedJson.toString());
            IHttpRequestResponse testResponse = callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), modifiedRequest);

            if (testResponse.getResponse() != null) {
                IResponseInfo responseInfo = helpers.analyzeResponse(testResponse.getResponse());
                int statusCode = responseInfo.getStatusCode();

                if (statusCode >= 200 && statusCode < 300) {
                    String responseBody = getResponseBody(testResponse.getResponse(), responseInfo);

                    // Check if any sensitive fields appear in response
                    int acceptedFields = 0;
                    List<String> acceptedFieldsList = new ArrayList<>();

                    for (String field : new String[]{"isAdmin", "role", "verified", "premium"}) {
                        if (responseBody.contains("\"" + field + "\"")) {
                            acceptedFields++;
                            acceptedFieldsList.add(field);
                        }
                    }

                    if (acceptedFields > 0) {
                        stdout.println("[Mass Assignment] ⚠️  Multiple sensitive fields accepted: " +
                                     acceptedFieldsList);
                        issues.add(createMultiFieldMassAssignmentIssue(baseRequestResponse,
                                  testResponse, acceptedFieldsList));
                    }
                }
            }

        } catch (Exception e) {
            stdout.println("[Mass Assignment] Multi-field test error: " + e.getMessage());
        }

        return issues;
    }

    private Object[] getTestValuesForField(String field) {
        String lowerField = field.toLowerCase();

        if (lowerField.contains("admin")) {
            return new Object[]{true};
        } else if (lowerField.contains("role")) {
            return new Object[]{"admin", "administrator", "superuser"};
        } else if (lowerField.contains("verified") || lowerField.contains("active")) {
            return new Object[]{true};
        } else if (lowerField.contains("balance") || lowerField.contains("credit")) {
            return new Object[]{999999, 1000000};
        } else if (lowerField.contains("premium")) {
            return new Object[]{true};
        } else if (lowerField.contains("status")) {
            return new Object[]{"active", "approved", "verified"};
        }

        return new Object[]{true, "admin", 1};
    }

    private byte[] buildRequestWithJson(IHttpRequestResponse baseRequestResponse, String jsonBody) {
        IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);
        List<String> headers = requestInfo.getHeaders();

        return helpers.buildHttpMessage(headers, jsonBody.getBytes());
    }

    private String getResponseBody(byte[] response, IResponseInfo responseInfo) {
        int bodyOffset = responseInfo.getBodyOffset();
        if (bodyOffset < response.length) {
            return new String(Arrays.copyOfRange(response, bodyOffset, response.length));
        }
        return "";
    }

    private IScanIssue createMassAssignmentIssue(IHttpRequestResponse original,
                                                 IHttpRequestResponse modified,
                                                 String field, String value,
                                                 boolean isPrivilegeEscalation) {
        String issueName;
        String issueDetail;
        String severity;

        if (isPrivilegeEscalation) {
            issueName = "API3:2023 - Mass Assignment Privilege Escalation";
            issueDetail = "<b>🚨 CRITICAL: Privilege Escalation via Mass Assignment!</b><br><br>" +
                         "The API endpoint allows modification of the privileged field '<b>" + field + "</b>' " +
                         "through mass assignment.<br><br>" +
                         "<b>Exploit Example:</b> " + field + " = \"" + value + "\"<br><br>" +
                         "<b>Attack Scenario:</b><br>" +
                         "An attacker can escalate their privileges by simply adding this field to API requests:<br>" +
                         "• Regular user → Admin user<br>" +
                         "• Limited permissions → Full access<br>" +
                         "• Unverified account → Verified status<br><br>" +
                         "<b>Proof of Concept:</b><br>" +
                         "Send a PUT/PATCH request with the body including:<br>" +
                         "<code>{\"" + field + "\": \"" + value + "\"}</code><br><br>" +
                         "<b>Impact:</b><br>" +
                         "• Complete account takeover<br>" +
                         "• Unauthorized administrative access<br>" +
                         "• Bypass of access controls<br>" +
                         "• Potential system-wide compromise<br><br>" +
                         "<b>Remediation:</b><br>" +
                         "• Implement a whitelist of allowed fields for each API endpoint<br>" +
                         "• Never allow role/admin/permission fields to be set via user input<br>" +
                         "• Use separate admin-only endpoints for privilege modifications<br>" +
                         "• Validate and authorize every field modification";
            severity = "Critical";
        } else {
            issueName = "API3:2023 - Broken Object Property Level Authorization (Mass Assignment)";
            issueDetail = "The API endpoint accepts and processes the sensitive field '<b>" + field +
                         "</b>' in the request body, even though it was not originally present.<br><br>" +
                         "<b>Test value:</b> " + field + " = " + value + "<br><br>" +
                         "This indicates a mass assignment vulnerability where an attacker could modify " +
                         "sensitive fields by including them in API requests. This can lead to unauthorized " +
                         "data manipulation or access.<br><br>" +
                         "<b>Remediation:</b><br>" +
                         "• Implement field-level authorization checks<br>" +
                         "• Use Data Transfer Objects (DTOs) with explicit field whitelisting<br>" +
                         "• Validate that users can only modify fields they're authorized to change";
            severity = "High";
        }

        String issueBackground = "API3:2023 - Broken Object Property Level Authorization<br><br>" +
                               "This category combines API3:2019 Excessive Data Exposure and API6:2019 - Mass Assignment, " +
                               "focusing on the root cause: the lack of or improper authorization validation at the object " +
                               "property level. This leads to information exposure or manipulation by unauthorized parties.";

        return new CustomScanIssue(
            original.getHttpService(),
            helpers.analyzeRequest(original).getUrl(),
            new IHttpRequestResponse[]{original, modified},
            issueName,
            issueDetail,
            issueBackground,
            severity,
            "Firm"
        );
    }

    private IScanIssue createMultiFieldMassAssignmentIssue(IHttpRequestResponse original,
                                                           IHttpRequestResponse modified,
                                                           List<String> acceptedFields) {
        String issueName = "API3:2023 - Broken Object Property Level Authorization (Multiple Field Mass Assignment)";
        String issueDetail = "<b>🚨 SEVERE: Multiple Sensitive Fields Vulnerable to Mass Assignment</b><br><br>" +
                           "The API endpoint accepts <b>multiple sensitive fields</b> in the request body:<br><br>" +
                           "<b>Accepted Fields:</b> " + String.join(", ", acceptedFields) + "<br><br>" +
                           "This is a <b>severe mass assignment vulnerability</b> that allows attackers to modify " +
                           "multiple sensitive properties simultaneously.<br><br>" +
                           "<b>Impact:</b><br>" +
                           "• <b>Complete account takeover</b><br>" +
                           "• Simultaneous privilege escalation and verification bypass<br>" +
                           "• Administrative access without authorization<br>" +
                           "• Mass manipulation of user attributes<br>" +
                           "• System-wide compromise potential<br><br>" +
                           "<b>Attack Scenario:</b><br>" +
                           "An attacker can send a single request with all privileged fields:<br>" +
                           "<code>{\"isAdmin\": true, \"role\": \"admin\", \"verified\": true, \"premium\": true}</code><br><br>" +
                           "<b>Remediation:</b><br>" +
                           "• <b>URGENT:</b> Implement strict field-level authorization<br>" +
                           "• Use explicit whitelists of allowed fields per endpoint<br>" +
                           "• Separate admin-only modification endpoints<br>" +
                           "• Validate every single field modification";

        String issueBackground = "API3:2023 - Broken Object Property Level Authorization<br><br>" +
                               "This category combines API3:2019 Excessive Data Exposure and API6:2019 - Mass Assignment, " +
                               "focusing on the root cause: the lack of or improper authorization validation at the object " +
                               "property level. Multiple field mass assignment represents the worst case scenario.";

        return new CustomScanIssue(
            original.getHttpService(),
            helpers.analyzeRequest(original).getUrl(),
            new IHttpRequestResponse[]{original, modified},
            issueName,
            issueDetail,
            issueBackground,
            "Critical",
            "Certain"
        );
    }
}
