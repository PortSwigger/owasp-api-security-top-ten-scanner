package com.security.burp.checks;

import burp.*;
import com.security.burp.model.CustomScanIssue;
import java.io.PrintWriter;
import java.net.URL;
import java.util.*;

/**
 * HTTP Method Fuzzing Check - Core Feature
 * OWASP API5:2023 - Broken Function Level Authorization
 * Tests all HTTP methods on each discovered endpoint regardless of documented methods
 */
public class MethodFuzzingCheck {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final PrintWriter stdout;
    private final boolean isDastMode;

    // All HTTP methods to test (Interactive mode)
    private static final String[] HTTP_METHODS = {
        "GET", "POST", "PUT", "DELETE", "PATCH",
        "HEAD", "OPTIONS", "TRACE", "CONNECT"
    };

    // Reduced set for DAST mode (most critical methods only)
    private static final String[] DAST_HTTP_METHODS = {
        "GET", "POST", "PUT", "DELETE", "PATCH"
    };

    public MethodFuzzingCheck(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
                             PrintWriter stdout, boolean isDastMode) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.stdout = stdout;
        this.isDastMode = isDastMode;
    }

    public List<IScanIssue> performMethodFuzzing(IHttpRequestResponse baseRequestResponse) {
        List<IScanIssue> issues = new ArrayList<>();

        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);
            String originalMethod = requestInfo.getMethod();
            URL url = requestInfo.getUrl();

            // Use reduced method set in DAST mode
            String[] methodsToTest = isDastMode ? DAST_HTTP_METHODS : HTTP_METHODS;
            stdout.println("[Method Fuzzing] Testing " + methodsToTest.length + " HTTP methods on: " + url.getPath() +
                         (isDastMode ? " (DAST mode - reduced set)" : ""));
            stdout.println("[Method Fuzzing] Original method: " + originalMethod);

            Map<String, MethodTestResult> results = new HashMap<>();

            // Test each HTTP method
            for (String method : methodsToTest) {
                // Skip the original method (already tested)
                if (method.equals(originalMethod)) {
                    continue;
                }

                MethodTestResult result = testMethod(baseRequestResponse, method);
                results.put(method, result);

                // Check for security issues
                if (result.isSuccessful()) {
                    stdout.println("[Method Fuzzing] ⚠️  Method " + method +
                                 " returned " + result.getStatusCode() +
                                 " (may be unintended)");

                    // High severity: Dangerous methods working unexpectedly
                    if (isDangerousMethod(method) && result.getStatusCode() < 400) {
                        issues.add(createMethodIssue(baseRequestResponse, method, result,
                                  "High", originalMethod));
                    }
                    // Medium severity: Unexpected successful methods
                    else if (result.getStatusCode() >= 200 && result.getStatusCode() < 300) {
                        issues.add(createMethodIssue(baseRequestResponse, method, result,
                                  "Medium", originalMethod));
                    }
                    // Info: Methods that return something other than 405
                    else if (result.getStatusCode() != 405) {
                        issues.add(createMethodIssue(baseRequestResponse, method, result,
                                  "Information", originalMethod));
                    }
                }
            }

            // Check for OPTIONS disclosure
            MethodTestResult optionsResult = results.get("OPTIONS");
            if (optionsResult != null && optionsResult.getAllowHeader() != null) {
                issues.add(createOptionsIssue(baseRequestResponse, optionsResult));
            }

            // Check for TRACE vulnerability (XST)
            MethodTestResult traceResult = results.get("TRACE");
            if (traceResult != null && traceResult.isSuccessful() &&
                traceResult.getStatusCode() == 200) {
                issues.add(createTraceIssue(baseRequestResponse, traceResult));
            }

        } catch (Exception e) {
            stdout.println("[Method Fuzzing] Error: " + e.getMessage());
        }

        return issues;
    }

    private MethodTestResult testMethod(IHttpRequestResponse baseRequestResponse, String method) {
        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);

            // Build new request with different method
            List<String> headers = requestInfo.getHeaders();

            // Replace method in first line
            String firstLine = headers.get(0);
            String[] parts = firstLine.split(" ");
            parts[0] = method;
            headers.set(0, String.join(" ", parts));

            // For methods that shouldn't have a body, remove it
            byte[] body = new byte[0];
            if (shouldHaveBody(method)) {
                int bodyOffset = requestInfo.getBodyOffset();
                byte[] originalRequest = baseRequestResponse.getRequest();
                if (bodyOffset < originalRequest.length) {
                    body = Arrays.copyOfRange(originalRequest, bodyOffset, originalRequest.length);
                }
            }

            byte[] newRequest = helpers.buildHttpMessage(headers, body);

            // Send request
            IHttpRequestResponse response = callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), newRequest);

            // Analyze response
            IResponseInfo responseInfo = helpers.analyzeResponse(response.getResponse());
            int statusCode = responseInfo.getStatusCode();
            List<String> responseHeaders = responseInfo.getHeaders();

            String allowHeader = null;
            for (String header : responseHeaders) {
                if (header.toLowerCase().startsWith("allow:")) {
                    allowHeader = header.substring(6).trim();
                    break;
                }
            }

            return new MethodTestResult(true, statusCode, allowHeader, response);

        } catch (Exception e) {
            return new MethodTestResult(false, 0, null, null);
        }
    }

    private boolean shouldHaveBody(String method) {
        return method.equals("POST") || method.equals("PUT") ||
               method.equals("PATCH") || method.equals("DELETE");
    }

    private boolean isDangerousMethod(String method) {
        return method.equals("PUT") || method.equals("DELETE") ||
               method.equals("PATCH") || method.equals("TRACE");
    }

    private IScanIssue createMethodIssue(IHttpRequestResponse baseRequestResponse,
                                         String method, MethodTestResult result,
                                         String severity, String originalMethod) {
        String issueName = "API5:2023 - Broken Function Level Authorization (Unexpected HTTP Method: " + method + ")";
        String issueDetail = "The API endpoint responded to HTTP " + method +
                           " method with status code " + result.getStatusCode() + ".<br><br>" +
                           "Original method documented: " + originalMethod + "<br>" +
                           "Method tested: " + method + "<br><br>" +
                           "This may indicate:<br>" +
                           "- Incomplete API specification/documentation<br>" +
                           "- Missing HTTP method restrictions<br>" +
                           "- Potential for unauthorized operations<br>" +
                           "- Broken Function Level Authorization<br><br>" +
                           "Recommendation: Implement proper HTTP method whitelisting and ensure only " +
                           "intended methods are allowed.";

        String issueBackground = "API5:2023 - Broken Function Level Authorization<br><br>" +
                               "Complex access control policies with different hierarchies, group roles, and an unclear " +
                               "separation between administrative and regular functions, tend to lead to authorization flaws. " +
                               "By exploiting these issues, attackers can gain access to other users' resources and/or " +
                               "administrative functions.";

        return new CustomScanIssue(
            baseRequestResponse.getHttpService(),
            helpers.analyzeRequest(baseRequestResponse).getUrl(),
            new IHttpRequestResponse[]{result.getResponse()},
            issueName,
            issueDetail,
            issueBackground,
            severity,
            "Firm"
        );
    }

    private IScanIssue createOptionsIssue(IHttpRequestResponse baseRequestResponse,
                                          MethodTestResult result) {
        String issueName = "API8:2023 - Security Misconfiguration (OPTIONS Method Disclosure)";
        String issueDetail = "The API endpoint responds to HTTP OPTIONS requests and discloses " +
                           "allowed methods via the Allow header: " + result.getAllowHeader() + "<br><br>" +
                           "This information disclosure can help attackers identify all available " +
                           "HTTP methods for further testing.";

        String issueBackground = "API8:2023 - Security Misconfiguration<br><br>" +
                               "APIs and the systems supporting them typically contain complex configurations, meant to " +
                               "make the APIs more customizable. Software and DevOps engineers can miss these configurations, " +
                               "or don't follow security best practices when it comes to configuration, opening the door for " +
                               "different types of attacks.";

        return new CustomScanIssue(
            baseRequestResponse.getHttpService(),
            helpers.analyzeRequest(baseRequestResponse).getUrl(),
            new IHttpRequestResponse[]{result.getResponse()},
            issueName,
            issueDetail,
            issueBackground,
            "Information",
            "Certain"
        );
    }

    private IScanIssue createTraceIssue(IHttpRequestResponse baseRequestResponse,
                                        MethodTestResult result) {
        String issueName = "API8:2023 - Security Misconfiguration (TRACE Method Enabled - XST Risk)";
        String issueDetail = "The API endpoint responds to HTTP TRACE requests. This can be " +
                           "exploited for Cross-Site Tracing (XST) attacks to bypass HTTPOnly " +
                           "cookie protections and steal sensitive headers.<br><br>" +
                           "TRACE method should be disabled on production systems.";

        String issueBackground = "API8:2023 - Security Misconfiguration<br><br>" +
                               "APIs and the systems supporting them typically contain complex configurations, meant to " +
                               "make the APIs more customizable. Software and DevOps engineers can miss these configurations, " +
                               "or don't follow security best practices when it comes to configuration, opening the door for " +
                               "different types of attacks.";

        return new CustomScanIssue(
            baseRequestResponse.getHttpService(),
            helpers.analyzeRequest(baseRequestResponse).getUrl(),
            new IHttpRequestResponse[]{result.getResponse()},
            issueName,
            issueDetail,
            issueBackground,
            "Medium",
            "Certain"
        );
    }

    // Inner class to hold test results
    private static class MethodTestResult {
        private final boolean successful;
        private final int statusCode;
        private final String allowHeader;
        private final IHttpRequestResponse response;

        public MethodTestResult(boolean successful, int statusCode, String allowHeader,
                               IHttpRequestResponse response) {
            this.successful = successful;
            this.statusCode = statusCode;
            this.allowHeader = allowHeader;
            this.response = response;
        }

        public boolean isSuccessful() {
            return successful;
        }

        public int getStatusCode() {
            return statusCode;
        }

        public String getAllowHeader() {
            return allowHeader;
        }

        public IHttpRequestResponse getResponse() {
            return response;
        }
    }
}
