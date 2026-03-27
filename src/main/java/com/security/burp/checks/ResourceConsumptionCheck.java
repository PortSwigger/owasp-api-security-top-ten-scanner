package com.security.burp.checks;

import burp.*;
import com.security.burp.model.CustomScanIssue;
import java.io.PrintWriter;
import java.util.*;

/**
 * Resource Consumption Check
 * OWASP API4:2023 - Unrestricted Resource Consumption
 * Detects potential resource consumption issues
 */
public class ResourceConsumptionCheck {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final PrintWriter stdout;

    public ResourceConsumptionCheck(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
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

            // Check for missing rate limiting headers
            List<String> responseHeaders = responseInfo.getHeaders();
            boolean hasRateLimitHeader = false;

            for (String header : responseHeaders) {
                String lowerHeader = header.toLowerCase();
                if (lowerHeader.startsWith("x-ratelimit-") ||
                    lowerHeader.startsWith("x-rate-limit-") ||
                    lowerHeader.startsWith("ratelimit-")) {
                    hasRateLimitHeader = true;
                    break;
                }
            }

            // Check for very large responses (potential for resource exhaustion)
            int responseSize = baseRequestResponse.getResponse().length;
            if (responseSize > 5000000) { // 5MB
                stdout.println("[Resource Check] Large response detected: " + responseSize + " bytes");
                issues.add(createLargeResponseIssue(baseRequestResponse, responseSize));
            }

            // Check if endpoint looks like it could be resource intensive but lacks rate limiting
            String path = requestInfo.getUrl().getPath().toLowerCase();
            if (!hasRateLimitHeader && isResourceIntensiveEndpoint(path)) {
                stdout.println("[Resource Check] Resource-intensive endpoint without rate limiting: " + path);
                issues.add(createMissingRateLimitIssue(baseRequestResponse, path));
            }

        } catch (Exception e) {
            stdout.println("[Resource Check] Error: " + e.getMessage());
        }

        return issues;
    }

    private boolean isResourceIntensiveEndpoint(String path) {
        // Endpoints that typically consume significant resources
        return path.contains("/search") ||
               path.contains("/export") ||
               path.contains("/report") ||
               path.contains("/download") ||
               path.contains("/bulk") ||
               path.contains("/batch") ||
               path.contains("/query");
    }

    private IScanIssue createLargeResponseIssue(IHttpRequestResponse baseRequestResponse, int size) {
        String issueName = "API4:2023 - Unrestricted Resource Consumption (Large Response)";
        String issueDetail = "The API returned a very large response (" + (size / 1024) + " KB).<br><br>" +
                           "Large responses can lead to:<br>" +
                           "- Client-side memory exhaustion<br>" +
                           "- Network bandwidth consumption<br>" +
                           "- Denial of Service<br><br>" +
                           "Recommendation: Implement pagination, response size limits, and streaming for large datasets.";

        String issueBackground = "API4:2023 - Unrestricted Resource Consumption<br><br>" +
                               "Satisfying API requests requires resources such as network bandwidth, CPU, memory, and " +
                               "storage. Other resources such as emails/SMS/phone calls or biometrics validation are made " +
                               "available by service providers via API integrations, and paid for per request. Successful " +
                               "attacks can lead to Denial of Service or an increase of operational costs.";

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

    private IScanIssue createMissingRateLimitIssue(IHttpRequestResponse baseRequestResponse, String path) {
        String issueName = "API4:2023 - Unrestricted Resource Consumption (Missing Rate Limiting)";
        String issueDetail = "The API endpoint appears to perform resource-intensive operations but lacks " +
                           "rate limiting headers.<br><br>" +
                           "Endpoint: " + path + "<br><br>" +
                           "Without rate limiting, attackers can:<br>" +
                           "- Execute denial of service attacks<br>" +
                           "- Exhaust API quotas<br>" +
                           "- Increase operational costs<br>" +
                           "- Degrade service for legitimate users<br><br>" +
                           "Recommendation: Implement rate limiting with headers like X-RateLimit-Limit, " +
                           "X-RateLimit-Remaining, and X-RateLimit-Reset.";

        String issueBackground = "API4:2023 - Unrestricted Resource Consumption<br><br>" +
                               "Satisfying API requests requires resources such as network bandwidth, CPU, memory, and " +
                               "storage. Other resources such as emails/SMS/phone calls or biometrics validation are made " +
                               "available by service providers via API integrations, and paid for per request. Successful " +
                               "attacks can lead to Denial of Service or an increase of operational costs.";

        return new CustomScanIssue(
            baseRequestResponse.getHttpService(),
            helpers.analyzeRequest(baseRequestResponse).getUrl(),
            new IHttpRequestResponse[]{baseRequestResponse},
            issueName,
            issueDetail,
            issueBackground,
            "Low",
            "Tentative"
        );
    }
}
