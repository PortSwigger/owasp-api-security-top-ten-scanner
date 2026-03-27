package com.security.burp.checks;

import burp.*;
import com.security.burp.model.CustomScanIssue;
import java.io.PrintWriter;
import java.util.*;

/**
 * Function Level Authorization Check
 * OWASP API5:2023 - Broken Function Level Authorization
 * Tests if regular users can access admin/privileged endpoints
 */
public class FunctionLevelAuthCheck {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final PrintWriter stdout;

    // Keywords that suggest admin/privileged endpoints
    private static final String[] ADMIN_KEYWORDS = {
        "admin", "administrator", "superuser", "root",
        "delete", "remove", "destroy", "drop",
        "create", "add", "new",
        "update", "modify", "edit", "change",
        "approve", "reject", "verify",
        "config", "configuration", "settings",
        "logs", "audit", "monitor",
        "users", "accounts", "permissions", "roles"
    };

    // HTTP methods that suggest privileged operations
    private static final String[] PRIVILEGED_METHODS = {
        "DELETE", "PUT", "PATCH"
    };

    public FunctionLevelAuthCheck(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
                                  PrintWriter stdout) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.stdout = stdout;
    }

    public List<IScanIssue> checkFunctionLevelAuth(IHttpRequestResponse baseRequestResponse) {
        List<IScanIssue> issues = new ArrayList<>();

        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);
            String path = requestInfo.getUrl().getPath().toLowerCase();
            String method = requestInfo.getMethod();

            // Check if this looks like a privileged endpoint
            if (!isPrivilegedEndpoint(path, method)) {
                return issues;
            }

            stdout.println("[Function Level Auth] Testing privileged endpoint: " + method + " " + path);

            // Test 1: Try without authentication headers
            issues.addAll(testWithoutAuth(baseRequestResponse));

            // Test 2: Try with manipulated role headers (if we find any)
            issues.addAll(testWithLowPrivilegeRole(baseRequestResponse));

        } catch (Exception e) {
            stdout.println("[Function Level Auth] Error: " + e.getMessage());
        }

        return issues;
    }

    private boolean isPrivilegedEndpoint(String path, String method) {
        // Check if path contains admin keywords
        for (String keyword : ADMIN_KEYWORDS) {
            if (path.contains(keyword)) {
                return true;
            }
        }

        // DELETE, PUT, PATCH methods are often privileged
        for (String privMethod : PRIVILEGED_METHODS) {
            if (method.equals(privMethod)) {
                return true;
            }
        }

        return false;
    }

    private List<IScanIssue> testWithoutAuth(IHttpRequestResponse baseRequestResponse) {
        List<IScanIssue> issues = new ArrayList<>();

        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);
            List<String> headers = new ArrayList<>(requestInfo.getHeaders());

            // Check if original request has auth
            boolean hasAuth = false;
            for (String header : headers) {
                if (header.toLowerCase().startsWith("authorization:")) {
                    hasAuth = true;
                    break;
                }
            }

            if (!hasAuth) {
                return issues; // Already tested without auth
            }

            // Remove all authentication headers
            List<String> noAuthHeaders = new ArrayList<>();
            for (String header : headers) {
                String lowerHeader = header.toLowerCase();
                if (!lowerHeader.startsWith("authorization:") &&
                    !lowerHeader.startsWith("cookie:") &&
                    !lowerHeader.startsWith("x-api-key:") &&
                    !lowerHeader.startsWith("x-auth-token:")) {
                    noAuthHeaders.add(header);
                }
            }

            byte[] body = Arrays.copyOfRange(baseRequestResponse.getRequest(),
                                           requestInfo.getBodyOffset(),
                                           baseRequestResponse.getRequest().length);

            byte[] noAuthRequest = helpers.buildHttpMessage(noAuthHeaders, body);

            IHttpRequestResponse testResponse = callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), noAuthRequest);

            if (testResponse.getResponse() != null) {
                IResponseInfo responseInfo = helpers.analyzeResponse(testResponse.getResponse());
                int statusCode = responseInfo.getStatusCode();

                // Successful without auth = broken function level authorization
                if (statusCode >= 200 && statusCode < 300) {
                    stdout.println("[Function Level Auth] 🚨 Privileged endpoint accessible without authentication!");
                    issues.add(createFunctionLevelAuthIssue(baseRequestResponse, testResponse,
                              "no authentication required"));
                }
            }

        } catch (Exception e) {
            stdout.println("[Function Level Auth] Test without auth error: " + e.getMessage());
        }

        return issues;
    }

    private List<IScanIssue> testWithLowPrivilegeRole(IHttpRequestResponse baseRequestResponse) {
        List<IScanIssue> issues = new ArrayList<>();

        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);
            List<String> headers = new ArrayList<>(requestInfo.getHeaders());

            // Add/modify role header to simulate regular user
            List<String> modifiedHeaders = new ArrayList<>();
            boolean hasRoleHeader = false;

            for (String header : headers) {
                String lowerHeader = header.toLowerCase();
                if (lowerHeader.startsWith("x-user-role:") ||
                    lowerHeader.startsWith("x-role:") ||
                    lowerHeader.startsWith("role:")) {
                    // Replace with low privilege role
                    modifiedHeaders.add("X-User-Role: user");
                    hasRoleHeader = true;
                } else {
                    modifiedHeaders.add(header);
                }
            }

            // If no role header found, add one
            if (!hasRoleHeader) {
                modifiedHeaders.add("X-User-Role: user");
            }

            byte[] body = Arrays.copyOfRange(baseRequestResponse.getRequest(),
                                           requestInfo.getBodyOffset(),
                                           baseRequestResponse.getRequest().length);

            byte[] modifiedRequest = helpers.buildHttpMessage(modifiedHeaders, body);

            IHttpRequestResponse testResponse = callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), modifiedRequest);

            if (testResponse.getResponse() != null) {
                IResponseInfo responseInfo = helpers.analyzeResponse(testResponse.getResponse());
                int statusCode = responseInfo.getStatusCode();

                // Successful with low privilege role = broken function level authorization
                if (statusCode >= 200 && statusCode < 300) {
                    stdout.println("[Function Level Auth] 🚨 Privileged endpoint accessible with user role!");
                    issues.add(createFunctionLevelAuthIssue(baseRequestResponse, testResponse,
                              "accessible with low-privilege role (X-User-Role: user)"));
                }
            }

        } catch (Exception e) {
            stdout.println("[Function Level Auth] Test with role error: " + e.getMessage());
        }

        return issues;
    }

    private IScanIssue createFunctionLevelAuthIssue(IHttpRequestResponse original,
                                                   IHttpRequestResponse attack,
                                                   String testCondition) {
        IRequestInfo requestInfo = helpers.analyzeRequest(original);
        String method = requestInfo.getMethod();
        String path = requestInfo.getUrl().getPath();

        String issueName = "API5:2023 - Broken Function Level Authorization";
        String issueDetail = "<b>🚨 CRITICAL: Privileged Endpoint Accessible Without Proper Authorization!</b><br><br>" +
                           "<b>Endpoint:</b> " + method + " " + path + "<br>" +
                           "<b>Test Condition:</b> " + testCondition + "<br><br>" +
                           "This <b>privileged administrative endpoint</b> should only be accessible to administrators, " +
                           "but it can be accessed by <b>regular users or without authentication</b>.<br><br>" +
                           "<b>Why This Endpoint is Considered Privileged:</b><br>";

        // Explain why we think it's privileged
        for (String keyword : ADMIN_KEYWORDS) {
            if (path.toLowerCase().contains(keyword)) {
                issueDetail += "• Path contains privileged keyword: '<b>" + keyword + "</b>'<br>";
            }
        }

        for (String privMethod : PRIVILEGED_METHODS) {
            if (method.equals(privMethod)) {
                issueDetail += "• Uses privileged HTTP method: <b>" + privMethod + "</b><br>";
            }
        }

        issueDetail += "<br><b>Impact:</b><br>" +
                      "• <b>Regular users can perform administrative actions</b><br>" +
                      "• Unauthorized data deletion or modification<br>" +
                      "• Access to sensitive administrative functions<br>" +
                      "• View confidential logs and system information<br>" +
                      "• Modify system configuration<br>" +
                      "• Create/delete user accounts<br>" +
                      "• <b>Potential complete system compromise</b><br><br>" +
                      "<b>Common Vulnerable Scenarios:</b><br>" +
                      "• Admin endpoints: /api/admin/*, /api/admin-panel/*<br>" +
                      "• DELETE endpoints for critical resources<br>" +
                      "• Configuration/settings endpoints<br>" +
                      "• User management endpoints<br>" +
                      "• Audit log access<br><br>" +
                      "<b>Exploitation:</b><br>" +
                      "An attacker with a regular user account (or no account at all) can:<br>" +
                      "1. Access admin-only endpoints directly<br>" +
                      "2. Delete other users' data<br>" +
                      "3. View system logs and sensitive information<br>" +
                      "4. Modify critical system settings<br><br>" +
                      "<b>Remediation:</b><br>" +
                      "• <b>URGENT:</b> Implement role-based access control (RBAC)<br>" +
                      "• Check user roles/permissions for EVERY privileged function<br>" +
                      "• Use middleware/decorators to enforce admin-only access<br>" +
                      "• Deny by default - explicitly whitelist allowed actions<br>" +
                      "• Example: <code>if (user.role !== 'admin') return res.status(403).json({error: 'Admin only'});</code>";

        String issueBackground = "API5:2023 - Broken Function Level Authorization<br><br>" +
                               "Complex access control policies with different hierarchies, groups, and roles, and " +
                               "an unclear separation between administrative and regular functions, tend to lead to " +
                               "authorization flaws. By exploiting these issues, attackers can access other users' " +
                               "resources and/or administrative functions. This is particularly dangerous when admin " +
                               "functions are accessible to regular users.";

        return new CustomScanIssue(
            original.getHttpService(),
            helpers.analyzeRequest(original).getUrl(),
            new IHttpRequestResponse[]{original, attack},
            issueName,
            issueDetail,
            issueBackground,
            "Critical",
            "Firm"
        );
    }
}
