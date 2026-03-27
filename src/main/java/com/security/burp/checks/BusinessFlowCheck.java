package com.security.burp.checks;

import burp.*;
import com.security.burp.model.CustomScanIssue;
import java.io.PrintWriter;
import java.util.*;

/**
 * Business Flow Check
 * OWASP API6:2023 - Unrestricted Access to Sensitive Business Flows
 * Detects potential business flow abuse issues
 */
public class BusinessFlowCheck {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final PrintWriter stdout;

    // Track request frequency per endpoint
    private final Map<String, List<Long>> requestTimestamps;

    public BusinessFlowCheck(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
                            PrintWriter stdout) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.stdout = stdout;
        this.requestTimestamps = new HashMap<>();
    }

    public List<IScanIssue> checkPassive(IHttpRequestResponse baseRequestResponse) {
        List<IScanIssue> issues = new ArrayList<>();

        try {
            if (baseRequestResponse.getResponse() == null) {
                return issues;
            }

            IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);
            String path = requestInfo.getUrl().getPath();

            // Check if endpoint is sensitive to business flow abuse
            if (isSensitiveBusinessEndpoint(path)) {
                IResponseInfo responseInfo = helpers.analyzeResponse(baseRequestResponse.getResponse());

                // Check for missing anti-automation mechanisms
                if (!hasAntiAutomationMechanisms(responseInfo)) {
                    stdout.println("[Business Flow] Sensitive endpoint without anti-automation: " + path);
                    issues.add(createBusinessFlowIssue(baseRequestResponse, path));
                }
            }

        } catch (Exception e) {
            stdout.println("[Business Flow] Error: " + e.getMessage());
        }

        return issues;
    }

    private boolean isSensitiveBusinessEndpoint(String path) {
        String lowerPath = path.toLowerCase();

        // Endpoints commonly vulnerable to business flow abuse
        return lowerPath.contains("/purchase") ||
               lowerPath.contains("/order") ||
               lowerPath.contains("/payment") ||
               lowerPath.contains("/checkout") ||
               lowerPath.contains("/book") ||
               lowerPath.contains("/reserve") ||
               lowerPath.contains("/ticket") ||
               lowerPath.contains("/vote") ||
               lowerPath.contains("/transfer") ||
               lowerPath.contains("/withdraw") ||
               lowerPath.contains("/comment") ||
               lowerPath.contains("/review") ||
               lowerPath.contains("/submit") ||
               lowerPath.contains("/create");
    }

    private boolean hasAntiAutomationMechanisms(IResponseInfo responseInfo) {
        List<String> headers = responseInfo.getHeaders();

        for (String header : headers) {
            String lowerHeader = header.toLowerCase();

            // Check for common anti-automation mechanisms
            if (lowerHeader.contains("x-captcha") ||
                lowerHeader.contains("recaptcha") ||
                lowerHeader.contains("hcaptcha") ||
                lowerHeader.contains("x-csrf-token") ||
                lowerHeader.contains("x-xsrf-token")) {
                return true;
            }
        }

        return false;
    }

    private IScanIssue createBusinessFlowIssue(IHttpRequestResponse baseRequestResponse, String path) {
        String issueName = "API6:2023 - Unrestricted Access to Sensitive Business Flows";
        String issueDetail = "The API endpoint performs sensitive business operations but lacks visible " +
                           "anti-automation protections.<br><br>" +
                           "Endpoint: " + path + "<br><br>" +
                           "Without proper protections, attackers can:<br>" +
                           "- Automate purchases/bookings to scalp items<br>" +
                           "- Mass submit spam comments/reviews<br>" +
                           "- Manipulate voting or rating systems<br>" +
                           "- Exhaust inventory through automated orders<br>" +
                           "- Perform financial fraud through automation<br><br>" +
                           "Recommendation: Implement CAPTCHA, rate limiting with progressive delays, " +
                           "device fingerprinting, behavioral analysis, or transaction value thresholds.";

        String issueBackground = "API6:2023 - Unrestricted Access to Sensitive Business Flows<br><br>" +
                               "APIs vulnerable to this risk expose a business flow - such as buying a ticket, or posting " +
                               "a comment - without compensating for how the functionality could harm the business if used " +
                               "excessively in an automated manner. This doesn't necessarily come from implementation bugs.";

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
}
