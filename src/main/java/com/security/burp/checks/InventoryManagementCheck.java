package com.security.burp.checks;

import burp.*;
import com.security.burp.model.CustomScanIssue;
import java.io.PrintWriter;
import java.util.*;

/**
 * Inventory Management Check
 * OWASP API9:2023 - Improper Inventory Management
 * Detects potential API inventory management issues
 */
public class InventoryManagementCheck {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final PrintWriter stdout;

    public InventoryManagementCheck(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
                                   PrintWriter stdout) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.stdout = stdout;
    }

    public List<IScanIssue> checkPassive(IHttpRequestResponse baseRequestResponse) {
        List<IScanIssue> issues = new ArrayList<>();

        try {
            if (baseRequestResponse.getResponse() == null) {
                return issues;
            }

            IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);
            IResponseInfo responseInfo = helpers.analyzeResponse(baseRequestResponse.getResponse());
            String path = requestInfo.getUrl().getPath();

            // Check for deprecated API versions
            if (isDeprecatedApiVersion(path)) {
                stdout.println("[Inventory Check] Deprecated API version detected: " + path);
                issues.add(createDeprecatedVersionIssue(baseRequestResponse, path));
            }

            // Check for debug endpoints in production
            if (isDebugEndpoint(path)) {
                stdout.println("[Inventory Check] Debug endpoint exposed: " + path);
                issues.add(createDebugEndpointIssue(baseRequestResponse, path));
            }

            // Check for version disclosure in headers
            List<String> headers = responseInfo.getHeaders();
            for (String header : headers) {
                if (header.toLowerCase().startsWith("x-api-version:") ||
                    header.toLowerCase().startsWith("api-version:")) {
                    String version = header.substring(header.indexOf(":") + 1).trim();
                    stdout.println("[Inventory Check] API version disclosed in header: " + version);
                    issues.add(createVersionDisclosureIssue(baseRequestResponse, version));
                    break;
                }
            }

        } catch (Exception e) {
            stdout.println("[Inventory Check] Error: " + e.getMessage());
        }

        return issues;
    }

    private boolean isDeprecatedApiVersion(String path) {
        String lowerPath = path.toLowerCase();

        // Check for old API versions (v1, v0, deprecated)
        return lowerPath.matches(".*/v0/.*") ||
               lowerPath.matches(".*/v1/.*") ||
               lowerPath.contains("/deprecated/") ||
               lowerPath.contains("/legacy/") ||
               lowerPath.contains("/old/") ||
               lowerPath.contains("-old") ||
               lowerPath.contains("-v1") ||
               lowerPath.contains("-deprecated");
    }

    private boolean isDebugEndpoint(String path) {
        String lowerPath = path.toLowerCase();

        // Common debug/test endpoints
        return lowerPath.contains("/debug") ||
               lowerPath.contains("/test") ||
               lowerPath.contains("/dev") ||
               lowerPath.contains("/staging") ||
               lowerPath.contains("/_debug") ||
               lowerPath.contains("/internal") ||
               lowerPath.contains("/admin") ||
               lowerPath.contains("/actuator") ||
               lowerPath.contains("/metrics") ||
               lowerPath.contains("/health") ||
               lowerPath.contains("/status") ||
               lowerPath.contains("/swagger") ||
               lowerPath.contains("/api-docs") ||
               lowerPath.contains("/openapi");
    }

    private IScanIssue createDeprecatedVersionIssue(IHttpRequestResponse baseRequestResponse, String path) {
        String issueName = "API9:2023 - Improper Inventory Management (Deprecated API Version)";
        String issueDetail = "The API endpoint appears to use a deprecated or old API version.<br><br>" +
                           "Endpoint: " + path + "<br><br>" +
                           "Deprecated API versions can:<br>" +
                           "- Contain unpatched security vulnerabilities<br>" +
                           "- Lack current security controls<br>" +
                           "- Increase attack surface<br>" +
                           "- Lead to inconsistent security posture<br><br>" +
                           "Recommendation: Migrate to current API version, deprecate old versions with proper " +
                           "sunset periods, maintain proper API inventory documentation.";

        String issueBackground = "API9:2023 - Improper Inventory Management<br><br>" +
                               "APIs tend to expose more endpoints than traditional web applications, making proper and " +
                               "updated documentation highly important. A proper inventory of hosts and deployed API versions " +
                               "also are important to mitigate issues such as deprecated API versions and exposed debug endpoints.";

        return new CustomScanIssue(
            baseRequestResponse.getHttpService(),
            helpers.analyzeRequest(baseRequestResponse).getUrl(),
            new IHttpRequestResponse[]{baseRequestResponse},
            issueName,
            issueDetail,
            issueBackground,
            "Medium",
            "Tentative"
        );
    }

    private IScanIssue createDebugEndpointIssue(IHttpRequestResponse baseRequestResponse, String path) {
        String issueName = "API9:2023 - Improper Inventory Management (Debug Endpoint Exposed)";
        String issueDetail = "The API exposes what appears to be a debug, test, or internal endpoint.<br><br>" +
                           "Endpoint: " + path + "<br><br>" +
                           "Exposed debug endpoints can:<br>" +
                           "- Reveal sensitive system information<br>" +
                           "- Provide administrative access<br>" +
                           "- Expose internal API documentation<br>" +
                           "- Allow unauthorized operations<br><br>" +
                           "Recommendation: Remove debug endpoints from production, implement proper access controls, " +
                           "maintain inventory of all deployed endpoints.";

        String issueBackground = "API9:2023 - Improper Inventory Management<br><br>" +
                               "APIs tend to expose more endpoints than traditional web applications, making proper and " +
                               "updated documentation highly important. A proper inventory of hosts and deployed API versions " +
                               "also are important to mitigate issues such as deprecated API versions and exposed debug endpoints.";

        return new CustomScanIssue(
            baseRequestResponse.getHttpService(),
            helpers.analyzeRequest(baseRequestResponse).getUrl(),
            new IHttpRequestResponse[]{baseRequestResponse},
            issueName,
            issueDetail,
            issueBackground,
            "Medium",
            "Certain"
        );
    }

    private IScanIssue createVersionDisclosureIssue(IHttpRequestResponse baseRequestResponse, String version) {
        String issueName = "API9:2023 - Improper Inventory Management (API Version Disclosure)";
        String issueDetail = "The API discloses version information in response headers.<br><br>" +
                           "Disclosed version: " + version + "<br><br>" +
                           "While not directly exploitable, version disclosure:<br>" +
                           "- Aids attackers in identifying vulnerable versions<br>" +
                           "- Reveals information about API architecture<br>" +
                           "- Can indicate poor inventory management practices<br><br>" +
                           "Recommendation: Remove version headers or ensure disclosed versions are current and documented.";

        String issueBackground = "API9:2023 - Improper Inventory Management<br><br>" +
                               "APIs tend to expose more endpoints than traditional web applications, making proper and " +
                               "updated documentation highly important. A proper inventory of hosts and deployed API versions " +
                               "also are important to mitigate issues such as deprecated API versions and exposed debug endpoints.";

        return new CustomScanIssue(
            baseRequestResponse.getHttpService(),
            helpers.analyzeRequest(baseRequestResponse).getUrl(),
            new IHttpRequestResponse[]{baseRequestResponse},
            issueName,
            issueDetail,
            issueBackground,
            "Information",
            "Certain"
        );
    }
}
