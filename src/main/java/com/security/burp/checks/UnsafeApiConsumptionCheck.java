package com.security.burp.checks;

import burp.*;
import com.security.burp.model.CustomScanIssue;
import java.io.PrintWriter;
import java.util.*;

/**
 * Unsafe API Consumption Check
 * OWASP API10:2023 - Unsafe Consumption of APIs
 * Detects potential unsafe consumption of third-party APIs
 */
public class UnsafeApiConsumptionCheck {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final PrintWriter stdout;

    // Common third-party API domains
    private static final String[] THIRD_PARTY_APIS = {
        "googleapis.com", "github.com", "stripe.com", "twilio.com",
        "sendgrid.com", "amazonaws.com", "azure.com", "cloudflare.com",
        "slack.com", "api.twitter.com", "graph.facebook.com"
    };

    public UnsafeApiConsumptionCheck(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
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

            // Get response body
            int bodyOffset = responseInfo.getBodyOffset();
            if (bodyOffset >= baseRequestResponse.getResponse().length) {
                return issues;
            }

            String responseBody = new String(Arrays.copyOfRange(
                baseRequestResponse.getResponse(),
                bodyOffset,
                baseRequestResponse.getResponse().length
            ));

            // Check if API response contains data from third-party APIs
            for (String thirdPartyApi : THIRD_PARTY_APIS) {
                if (responseBody.contains(thirdPartyApi)) {
                    stdout.println("[API Consumption] Third-party API reference found: " + thirdPartyApi);

                    // Check if there's validation/sanitization indicators
                    if (!hasValidationIndicators(responseBody)) {
                        issues.add(createUnsafeConsumptionIssue(baseRequestResponse, thirdPartyApi));
                        break; // Only report once per response
                    }
                }
            }

            // Check for webhook endpoints (commonly vulnerable to unsafe consumption)
            String path = requestInfo.getUrl().getPath().toLowerCase();
            if (isWebhookEndpoint(path)) {
                stdout.println("[API Consumption] Webhook endpoint detected: " + path);
                issues.add(createWebhookIssue(baseRequestResponse, path));
            }

        } catch (Exception e) {
            stdout.println("[API Consumption] Error: " + e.getMessage());
        }

        return issues;
    }

    private boolean hasValidationIndicators(String responseBody) {
        // Look for signs that data is being validated/sanitized
        // This is a basic check - real validation would need deeper analysis
        return responseBody.contains("\"validated\"") ||
               responseBody.contains("\"sanitized\"") ||
               responseBody.contains("\"verified\"");
    }

    private boolean isWebhookEndpoint(String path) {
        return path.contains("/webhook") ||
               path.contains("/callback") ||
               path.contains("/notify") ||
               path.contains("/event") ||
               path.contains("/integration");
    }

    private IScanIssue createUnsafeConsumptionIssue(IHttpRequestResponse baseRequestResponse,
                                                    String thirdPartyApi) {
        String issueName = "API10:2023 - Unsafe Consumption of APIs (Third-Party API Integration)";
        String issueDetail = "The API appears to consume data from third-party APIs without visible validation.<br><br>" +
                           "Third-party API detected: " + thirdPartyApi + "<br><br>" +
                           "Unsafe consumption of third-party APIs can lead to:<br>" +
                           "- Injection attacks through untrusted data<br>" +
                           "- Data integrity issues<br>" +
                           "- Business logic bypass<br>" +
                           "- Supply chain attacks<br><br>" +
                           "Recommendation: Always validate and sanitize data from third-party APIs. Don't blindly " +
                           "trust external sources. Implement schema validation, input sanitization, and rate limiting " +
                           "for third-party API consumption.";

        String issueBackground = "API10:2023 - Unsafe Consumption of APIs<br><br>" +
                               "Developers tend to trust data received from third-party APIs more than user input, and so " +
                               "tend to adopt weaker security standards. In order to compromise APIs, attackers go after " +
                               "integrated third-party services instead of trying to compromise the target API directly.";

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

    private IScanIssue createWebhookIssue(IHttpRequestResponse baseRequestResponse, String path) {
        String issueName = "API10:2023 - Unsafe Consumption of APIs (Webhook Endpoint)";
        String issueDetail = "The API exposes a webhook endpoint that receives data from external sources.<br><br>" +
                           "Webhook endpoint: " + path + "<br><br>" +
                           "Webhooks are particularly vulnerable to unsafe API consumption because:<br>" +
                           "- They accept unsolicited data from external sources<br>" +
                           "- Data validation is often insufficient<br>" +
                           "- Signature verification may be missing<br>" +
                           "- Rate limiting is frequently absent<br><br>" +
                           "Recommendation: Implement strict webhook signature verification (HMAC), validate all " +
                           "incoming data against a schema, use allowlists for webhook sources, implement rate limiting, " +
                           "and never trust webhook data without validation.";

        String issueBackground = "API10:2023 - Unsafe Consumption of APIs<br><br>" +
                               "Developers tend to trust data received from third-party APIs more than user input, and so " +
                               "tend to adopt weaker security standards. In order to compromise APIs, attackers go after " +
                               "integrated third-party services instead of trying to compromise the target API directly.";

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
