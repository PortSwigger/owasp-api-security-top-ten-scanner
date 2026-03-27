package com.security.burp.checks;

import burp.*;
import com.security.burp.model.CustomScanIssue;
import java.io.PrintWriter;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * BOLA (Broken Object Level Authorization) Check
 * OWASP API1:2023 - Broken Object Level Authorization
 * Tests for insecure direct object references in APIs
 */
public class BrokenObjectAuthCheck {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final PrintWriter stdout;
    private final boolean isDastMode;

    // Patterns to detect object identifiers
    private static final Pattern[] ID_PATTERNS = {
        Pattern.compile("/\\d+(?:/|$)"),           // Numeric IDs: /users/123
        Pattern.compile("/[a-f0-9]{24}(?:/|$)"),   // MongoDB ObjectID
        Pattern.compile("/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}(?:/|$)"), // UUID
        Pattern.compile("[?&]id=\\d+"),             // Query param IDs
        Pattern.compile("[?&]user_?id=\\d+"),
        Pattern.compile("[?&]account_?id=\\d+")
    };

    public BrokenObjectAuthCheck(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
                                 PrintWriter stdout, boolean isDastMode) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.stdout = stdout;
        this.isDastMode = isDastMode;
    }

    public List<IScanIssue> checkBOLA(IHttpRequestResponse baseRequestResponse,
                                      IScannerInsertionPoint insertionPoint) {
        List<IScanIssue> issues = new ArrayList<>();

        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);
            String url = requestInfo.getUrl().toString();

            // Check if URL contains object identifiers
            if (!containsObjectIdentifier(url)) {
                return issues;
            }

            stdout.println("[BOLA Check] Testing endpoint: " + url);

            // Test 1: Try accessing with modified ID
            issues.addAll(testIdManipulation(baseRequestResponse));

            // Test 2: Try accessing without authentication
            // Skip this in DAST mode to reduce expected 401/403 responses
            if (!isDastMode) {
                stdout.println("[BOLA Check] Testing unauthenticated access (skipped in DAST mode)");
                issues.addAll(testUnauthenticatedAccess(baseRequestResponse));
            } else {
                stdout.println("[BOLA Check] Skipping unauthenticated access test (DAST mode)");
            }

            // Test 3: Test sequential ID enumeration
            issues.addAll(testIdEnumeration(baseRequestResponse));

        } catch (Exception e) {
            stdout.println("[BOLA Check] Error: " + e.getMessage());
        }

        return issues;
    }

    private boolean containsObjectIdentifier(String url) {
        for (Pattern pattern : ID_PATTERNS) {
            if (pattern.matcher(url).find()) {
                return true;
            }
        }
        return false;
    }

    private List<IScanIssue> testIdManipulation(IHttpRequestResponse baseRequestResponse) {
        List<IScanIssue> issues = new ArrayList<>();

        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);
            String originalUrl = requestInfo.getUrl().toString();
            byte[] originalRequest = baseRequestResponse.getRequest();

            // Extract and modify IDs
            List<String> modifiedUrls = generateModifiedIds(originalUrl);

            for (String modifiedUrl : modifiedUrls) {
                // Replace URL in request
                byte[] modifiedRequest = replaceUrlInRequest(originalRequest, modifiedUrl);

                // Send request
                IHttpRequestResponse testResponse = callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), modifiedRequest);

                // Check response
                if (testResponse.getResponse() != null) {
                    IResponseInfo responseInfo = helpers.analyzeResponse(testResponse.getResponse());
                    int statusCode = responseInfo.getStatusCode();

                    // Successful access with modified ID = BOLA vulnerability
                    if (statusCode >= 200 && statusCode < 300) {
                        stdout.println("[BOLA Check] ⚠️  Vulnerable! Modified ID returned " + statusCode);
                        issues.add(createBOLAIssue(baseRequestResponse, testResponse,
                                  originalUrl, modifiedUrl));
                        break; // One finding is enough
                    }
                }
            }

        } catch (Exception e) {
            stdout.println("[BOLA Check] ID manipulation test error: " + e.getMessage());
        }

        return issues;
    }

    private List<IScanIssue> testUnauthenticatedAccess(IHttpRequestResponse baseRequestResponse) {
        List<IScanIssue> issues = new ArrayList<>();

        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);
            List<String> headers = new ArrayList<>(requestInfo.getHeaders());

            // Remove authentication headers
            headers.removeIf(header ->
                header.toLowerCase().startsWith("authorization:") ||
                header.toLowerCase().startsWith("cookie:") ||
                header.toLowerCase().startsWith("x-api-key:") ||
                header.toLowerCase().startsWith("x-auth-token:")
            );

            byte[] body = Arrays.copyOfRange(baseRequestResponse.getRequest(),
                                           requestInfo.getBodyOffset(),
                                           baseRequestResponse.getRequest().length);

            byte[] unauthRequest = helpers.buildHttpMessage(headers, body);

            // Send unauthenticated request
            IHttpRequestResponse testResponse = callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), unauthRequest);

            if (testResponse.getResponse() != null) {
                IResponseInfo responseInfo = helpers.analyzeResponse(testResponse.getResponse());
                int statusCode = responseInfo.getStatusCode();

                // Success without auth = broken authorization
                if (statusCode >= 200 && statusCode < 300) {
                    stdout.println("[BOLA Check] ⚠️  Accessible without authentication!");
                    issues.add(createUnauthAccessIssue(baseRequestResponse, testResponse));
                }
            }

        } catch (Exception e) {
            stdout.println("[BOLA Check] Unauth access test error: " + e.getMessage());
        }

        return issues;
    }

    private List<IScanIssue> testIdEnumeration(IHttpRequestResponse baseRequestResponse) {
        List<IScanIssue> issues = new ArrayList<>();

        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);
            String url = requestInfo.getUrl().toString();

            // Extract numeric ID
            Pattern numericPattern = Pattern.compile("/(\\d+)(?:/|$)");
            Matcher matcher = numericPattern.matcher(url);

            if (matcher.find()) {
                int originalId = Integer.parseInt(matcher.group(1));
                int successCount = 0;

                // Test adjacent IDs
                for (int offset : new int[]{-1, -2, 1, 2}) {
                    int testId = originalId + offset;
                    if (testId <= 0) continue;

                    String testUrl = url.replaceFirst("/" + originalId + "(?=/|$)",
                                                     "/" + testId);
                    byte[] testRequest = replaceUrlInRequest(baseRequestResponse.getRequest(), testUrl);

                    IHttpRequestResponse testResponse = callbacks.makeHttpRequest(
                        baseRequestResponse.getHttpService(), testRequest);

                    if (testResponse.getResponse() != null) {
                        IResponseInfo responseInfo = helpers.analyzeResponse(testResponse.getResponse());
                        if (responseInfo.getStatusCode() >= 200 && responseInfo.getStatusCode() < 300) {
                            successCount++;
                        }
                    }
                }

                // If multiple sequential IDs are accessible, it's enumerable
                if (successCount >= 2) {
                    stdout.println("[BOLA Check] ⚠️  Sequential ID enumeration possible!");
                    issues.add(createEnumerationIssue(baseRequestResponse));
                }
            }

        } catch (Exception e) {
            stdout.println("[BOLA Check] ID enumeration test error: " + e.getMessage());
        }

        return issues;
    }

    private List<String> generateModifiedIds(String url) {
        List<String> modifiedUrls = new ArrayList<>();

        // Try modifying numeric IDs
        Pattern numericPattern = Pattern.compile("/(\\d+)(?:/|$)");
        Matcher matcher = numericPattern.matcher(url);
        if (matcher.find()) {
            int originalId = Integer.parseInt(matcher.group(1));
            // Test with different IDs
            for (int testId : new int[]{1, 2, 100, 999, originalId + 1, originalId - 1}) {
                if (testId != originalId && testId > 0) {
                    String modified = url.replaceFirst("/" + originalId + "(?=/|$)", "/" + testId);
                    modifiedUrls.add(modified);
                }
            }
        }

        return modifiedUrls;
    }

    private byte[] replaceUrlInRequest(byte[] originalRequest, String newUrl) {
        String request = helpers.bytesToString(originalRequest);
        String[] lines = request.split("\r\n", 2);

        if (lines.length > 0) {
            String[] firstLineParts = lines[0].split(" ");
            if (firstLineParts.length >= 3) {
                // Extract path from URL
                String path = newUrl.substring(newUrl.indexOf('/', 8)); // Skip protocol
                firstLineParts[1] = path;
                lines[0] = String.join(" ", firstLineParts);
                return helpers.stringToBytes(String.join("\r\n", lines));
            }
        }

        return originalRequest;
    }

    private IScanIssue createBOLAIssue(IHttpRequestResponse original, IHttpRequestResponse modified,
                                       String originalUrl, String modifiedUrl) {
        String issueName = "API1:2023 - Broken Object Level Authorization (BOLA)";
        String issueDetail = "<b>🚨 Broken Object Level Authorization Vulnerability Detected</b><br><br>" +
                           "The API endpoint is vulnerable to BOLA - the #1 OWASP API Security vulnerability. " +
                           "An attacker can access objects belonging to other users by manipulating object identifiers.<br><br>" +
                           "<b>Original URL:</b> " + originalUrl + "<br>" +
                           "<b>Modified URL:</b> " + modifiedUrl + "<br><br>" +
                           "The modified request returned a <b>successful response</b>, indicating insufficient " +
                           "authorization checks at the object level.<br><br>" +
                           "<b>Impact:</b><br>" +
                           "• Unauthorized access to sensitive user data<br>" +
                           "• Privacy violations and data breaches<br>" +
                           "• Compliance violations (GDPR, CCPA, HIPAA)<br>" +
                           "• Account takeover potential<br>" +
                           "• Mass data enumeration and extraction<br><br>" +
                           "<b>Exploitation:</b><br>" +
                           "An attacker can iterate through IDs (1, 2, 3...) to access all users' data without authorization.<br><br>" +
                           "<b>Remediation:</b><br>" +
                           "• Implement object-level authorization checks<br>" +
                           "• Verify user ownership before returning resources<br>" +
                           "• Use indirect reference maps instead of direct IDs<br>" +
                           "• Example: <code>if (resource.userId !== currentUser.id) return 403;</code>";

        String issueBackground = "API1:2023 - Broken Object Level Authorization<br><br>" +
                               "APIs tend to expose endpoints that handle object identifiers, creating a wide " +
                               "attack surface of Object Level Access Control issues. Object level authorization " +
                               "checks should be considered in every function that accesses a data source using " +
                               "an ID from the user. This is the #1 most common and impactful API vulnerability.";

        return new CustomScanIssue(
            original.getHttpService(),
            helpers.analyzeRequest(original).getUrl(),
            new IHttpRequestResponse[]{original, modified},
            issueName,
            issueDetail,
            issueBackground,
            "Critical",
            "Firm"
        );
    }

    private IScanIssue createUnauthAccessIssue(IHttpRequestResponse original,
                                               IHttpRequestResponse unauth) {
        String issueName = "API1:2023 - Broken Object Level Authorization (Unauthenticated Access)";
        String issueDetail = "<b>🚨 Unauthenticated Access to Protected Resources</b><br><br>" +
                           "The API endpoint returned a <b>successful response</b> without any authentication " +
                           "credentials, indicating missing authorization controls.<br><br>" +
                           "The request was sent <b>without</b>:<br>" +
                           "• Authorization headers<br>" +
                           "• Session cookies<br>" +
                           "• API keys<br>" +
                           "• Any authentication mechanism<br><br>" +
                           "Yet the endpoint still returned <b>200 OK</b> with sensitive data.<br><br>" +
                           "<b>Impact:</b><br>" +
                           "• <b>Complete bypass of authentication</b><br>" +
                           "• Public access to private user data<br>" +
                           "• Data breach and privacy violations<br>" +
                           "• No audit trail of unauthorized access<br><br>" +
                           "<b>Remediation:</b><br>" +
                           "• Implement authentication checks on ALL endpoints<br>" +
                           "• Use middleware to enforce authentication<br>" +
                           "• Return 401 Unauthorized for missing credentials<br>" +
                           "• Never skip authentication for any API endpoint";

        String issueBackground = "API1:2023 - Broken Object Level Authorization<br><br>" +
                               "While this appears to be a missing authentication issue, it falls under BOLA because " +
                               "the endpoint should be checking both authentication (who you are) and authorization " +
                               "(what you can access). Complete absence of checks is the most severe form of BOLA.";

        return new CustomScanIssue(
            original.getHttpService(),
            helpers.analyzeRequest(original).getUrl(),
            new IHttpRequestResponse[]{original, unauth},
            issueName,
            issueDetail,
            issueBackground,
            "Critical",
            "Certain"
        );
    }

    private IScanIssue createEnumerationIssue(IHttpRequestResponse baseRequestResponse) {
        String issueName = "API1:2023 - Broken Object Level Authorization (ID Enumeration)";
        String issueDetail = "The API allows sequential ID enumeration. Multiple sequential object IDs " +
                           "returned successful responses, indicating an attacker could iterate through " +
                           "IDs to discover all objects in the system.<br><br>" +
                           "Combined with BOLA, this enables mass data extraction.";

        String issueBackground = "API1:2023 - Broken Object Level Authorization<br><br>" +
                               "APIs tend to expose endpoints that handle object identifiers, creating a wide " +
                               "attack surface of Object Level Access Control issues. Object level authorization " +
                               "checks should be considered in every function that accesses a data source using " +
                               "an ID from the user.";

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
}
