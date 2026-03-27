package com.security.burp.checks;

import burp.*;
import com.security.burp.model.CustomScanIssue;
import java.io.PrintWriter;
import java.util.*;

/**
 * Security Misconfiguration Check
 * OWASP API8:2023 - Security Misconfiguration
 * Detects security misconfigurations in API implementations
 */
public class SecurityMisconfigCheck {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final PrintWriter stdout;

    // Security headers that should be present
    private static final Map<String, String> RECOMMENDED_HEADERS = new HashMap<String, String>() {{
        put("X-Content-Type-Options", "nosniff");
        put("X-Frame-Options", "DENY or SAMEORIGIN");
        put("Content-Security-Policy", "restrictive policy");
        put("Strict-Transport-Security", "max-age value");
    }};

    // Headers that shouldn't be present (information disclosure)
    private static final String[] DISCLOSURE_HEADERS = {
        "Server", "X-Powered-By", "X-AspNet-Version",
        "X-AspNetMvc-Version", "X-Runtime"
    };

    public SecurityMisconfigCheck(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
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

            // Check for missing security headers
            issues.addAll(checkMissingSecurityHeaders(baseRequestResponse, responseInfo));

            // Check for information disclosure headers
            issues.addAll(checkDisclosureHeaders(baseRequestResponse, responseInfo));

            // Check for CORS misconfigurations
            issues.addAll(checkCORSMisconfig(baseRequestResponse, requestInfo, responseInfo));

            // Check for HTTP instead of HTTPS
            issues.addAll(checkInsecureProtocol(baseRequestResponse, requestInfo));

            // Check for verbose error messages
            issues.addAll(checkVerboseErrors(baseRequestResponse, responseInfo));

        } catch (Exception e) {
            stdout.println("[Misconfig Check] Error: " + e.getMessage());
        }

        return issues;
    }

    private List<IScanIssue> checkMissingSecurityHeaders(IHttpRequestResponse baseRequestResponse,
                                                         IResponseInfo responseInfo) {
        List<IScanIssue> issues = new ArrayList<>();
        List<String> headers = responseInfo.getHeaders();
        Map<String, String> headerMap = new HashMap<>();

        // Build header map
        for (String header : headers) {
            int colonIndex = header.indexOf(':');
            if (colonIndex > 0) {
                String name = header.substring(0, colonIndex).trim();
                String value = header.substring(colonIndex + 1).trim();
                headerMap.put(name.toLowerCase(), value);
            }
        }

        List<String> missingHeaders = new ArrayList<>();
        for (String recommendedHeader : RECOMMENDED_HEADERS.keySet()) {
            if (!headerMap.containsKey(recommendedHeader.toLowerCase())) {
                missingHeaders.add(recommendedHeader);
            }
        }

        if (!missingHeaders.isEmpty()) {
            stdout.println("[Misconfig Check] Missing security headers: " + missingHeaders);
            issues.add(createMissingHeadersIssue(baseRequestResponse, missingHeaders));
        }

        return issues;
    }

    private List<IScanIssue> checkDisclosureHeaders(IHttpRequestResponse baseRequestResponse,
                                                    IResponseInfo responseInfo) {
        List<IScanIssue> issues = new ArrayList<>();
        List<String> headers = responseInfo.getHeaders();
        List<String> foundDisclosureHeaders = new ArrayList<>();

        for (String header : headers) {
            String lowerHeader = header.toLowerCase();
            for (String disclosureHeader : DISCLOSURE_HEADERS) {
                if (lowerHeader.startsWith(disclosureHeader.toLowerCase() + ":")) {
                    foundDisclosureHeaders.add(header);
                    break;
                }
            }
        }

        if (!foundDisclosureHeaders.isEmpty()) {
            stdout.println("[Misconfig Check] Information disclosure headers: " + foundDisclosureHeaders);
            issues.add(createDisclosureHeadersIssue(baseRequestResponse, foundDisclosureHeaders));
        }

        return issues;
    }

    private List<IScanIssue> checkCORSMisconfig(IHttpRequestResponse baseRequestResponse,
                                                IRequestInfo requestInfo,
                                                IResponseInfo responseInfo) {
        List<IScanIssue> issues = new ArrayList<>();
        List<String> responseHeaders = responseInfo.getHeaders();

        for (String header : responseHeaders) {
            if (header.toLowerCase().startsWith("access-control-allow-origin:")) {
                String value = header.substring(header.indexOf(':') + 1).trim();

                // Check for wildcard with credentials
                if (value.equals("*")) {
                    boolean hasCredentials = false;
                    for (String h : responseHeaders) {
                        if (h.toLowerCase().contains("access-control-allow-credentials: true")) {
                            hasCredentials = true;
                            break;
                        }
                    }

                    if (hasCredentials) {
                        stdout.println("[Misconfig Check] ⚠️  CORS: wildcard origin with credentials!");
                        issues.add(createCORSCredentialsIssue(baseRequestResponse));
                    } else {
                        stdout.println("[Misconfig Check] CORS: wildcard origin (potential issue)");
                        issues.add(createCORSWildcardIssue(baseRequestResponse));
                    }
                }

                // Check for reflected origin
                String origin = getRequestHeader(requestInfo.getHeaders(), "Origin");
                if (origin != null && value.equals(origin)) {
                    stdout.println("[Misconfig Check] ⚠️  CORS: reflected origin!");
                    issues.add(createCORSReflectedIssue(baseRequestResponse, origin));
                }

                break;
            }
        }

        return issues;
    }

    private List<IScanIssue> checkInsecureProtocol(IHttpRequestResponse baseRequestResponse,
                                                   IRequestInfo requestInfo) {
        List<IScanIssue> issues = new ArrayList<>();

        if (requestInfo.getUrl().getProtocol().equals("http")) {
            stdout.println("[Misconfig Check] API using HTTP (insecure)");
            issues.add(createInsecureProtocolIssue(baseRequestResponse));
        }

        return issues;
    }

    private List<IScanIssue> checkVerboseErrors(IHttpRequestResponse baseRequestResponse,
                                                IResponseInfo responseInfo) {
        List<IScanIssue> issues = new ArrayList<>();
        int statusCode = responseInfo.getStatusCode();

        // Only check error responses
        if (statusCode < 400) {
            return issues;
        }

        String responseBody = getResponseBody(baseRequestResponse.getResponse(), responseInfo).toLowerCase();

        // Check for stack traces or detailed error info
        if (responseBody.contains("stack trace") ||
            responseBody.contains("at line") ||
            responseBody.contains("exception") ||
            responseBody.contains("error message") ||
            responseBody.contains("stacktrace") ||
            responseBody.contains("traceback")) {

            stdout.println("[Misconfig Check] Verbose error messages detected");
            issues.add(createVerboseErrorIssue(baseRequestResponse));
        }

        return issues;
    }

    private String getRequestHeader(List<String> headers, String headerName) {
        String lowerName = headerName.toLowerCase() + ":";
        for (String header : headers) {
            if (header.toLowerCase().startsWith(lowerName)) {
                return header.substring(header.indexOf(':') + 1).trim();
            }
        }
        return null;
    }

    private String getResponseBody(byte[] response, IResponseInfo responseInfo) {
        int bodyOffset = responseInfo.getBodyOffset();
        if (bodyOffset < response.length) {
            return new String(Arrays.copyOfRange(response, bodyOffset, response.length));
        }
        return "";
    }

    private IScanIssue createMissingHeadersIssue(IHttpRequestResponse baseRequestResponse,
                                                 List<String> missingHeaders) {
        StringBuilder headerList = new StringBuilder();
        for (String header : missingHeaders) {
            headerList.append("- ").append(header).append(": ")
                     .append(RECOMMENDED_HEADERS.get(header)).append("<br>");
        }

        String issueName = "API8:2023 - Security Misconfiguration (Missing Security Headers)";
        String issueDetail = "The API response is missing important security headers:<br><br>" +
                           headerList.toString() + "<br>" +
                           "These headers help protect against various attacks including XSS, " +
                           "clickjacking, and MIME type confusion.";

        String issueBackground = "API8:2023 - Security Misconfiguration<br><br>" +
                               "APIs and the systems supporting them typically contain complex configurations, meant to " +
                               "make the APIs more customizable. Software and DevOps engineers can miss these configurations, " +
                               "or don't follow security best practices when it comes to configuration, opening the door for " +
                               "different types of attacks.";

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

    private IScanIssue createDisclosureHeadersIssue(IHttpRequestResponse baseRequestResponse,
                                                    List<String> headers) {
        StringBuilder headerList = new StringBuilder();
        for (String header : headers) {
            headerList.append("- ").append(header).append("<br>");
        }

        String issueName = "API8:2023 - Security Misconfiguration (Information Disclosure via Headers)";
        String issueDetail = "The API response contains headers that disclose server information:<br><br>" +
                           headerList.toString() + "<br>" +
                           "These headers reveal technology stack details that can help attackers " +
                           "identify specific vulnerabilities to exploit.";

        String issueBackground = "API8:2023 - Security Misconfiguration<br><br>" +
                               "APIs and the systems supporting them typically contain complex configurations, meant to " +
                               "make the APIs more customizable. Software and DevOps engineers can miss these configurations, " +
                               "or don't follow security best practices when it comes to configuration, opening the door for " +
                               "different types of attacks.";

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

    private IScanIssue createCORSWildcardIssue(IHttpRequestResponse baseRequestResponse) {
        String issueBackground = "API8:2023 - Security Misconfiguration<br><br>" +
                               "APIs and the systems supporting them typically contain complex configurations, meant to " +
                               "make the APIs more customizable. Software and DevOps engineers can miss these configurations, " +
                               "or don't follow security best practices when it comes to configuration, opening the door for " +
                               "different types of attacks.";

        return new CustomScanIssue(
            baseRequestResponse.getHttpService(),
            helpers.analyzeRequest(baseRequestResponse).getUrl(),
            new IHttpRequestResponse[]{baseRequestResponse},
            "API8:2023 - Security Misconfiguration (CORS Wildcard Origin)",
            "The API uses 'Access-Control-Allow-Origin: *' which allows any website to read " +
            "the API response. While this doesn't allow credential-based attacks, it may expose " +
            "public API data to unauthorized origins.<br><br>" +
            "Recommendation: Use specific allowed origins instead of wildcard.",
            issueBackground,
            "Low",
            "Certain"
        );
    }

    private IScanIssue createCORSCredentialsIssue(IHttpRequestResponse baseRequestResponse) {
        String issueBackground = "API8:2023 - Security Misconfiguration<br><br>" +
                               "APIs and the systems supporting them typically contain complex configurations, meant to " +
                               "make the APIs more customizable. Software and DevOps engineers can miss these configurations, " +
                               "or don't follow security best practices when it comes to configuration, opening the door for " +
                               "different types of attacks.";

        return new CustomScanIssue(
            baseRequestResponse.getHttpService(),
            helpers.analyzeRequest(baseRequestResponse).getUrl(),
            new IHttpRequestResponse[]{baseRequestResponse},
            "API8:2023 - Security Misconfiguration (CORS Wildcard with Credentials)",
            "The API uses 'Access-Control-Allow-Origin: *' together with " +
            "'Access-Control-Allow-Credentials: true'. This is invalid and blocked by browsers, " +
            "but indicates a severe misconfiguration.<br><br>" +
            "This configuration would allow any website to make authenticated requests to the API.",
            issueBackground,
            "High",
            "Certain"
        );
    }

    private IScanIssue createCORSReflectedIssue(IHttpRequestResponse baseRequestResponse, String origin) {
        String issueBackground = "API8:2023 - Security Misconfiguration<br><br>" +
                               "APIs and the systems supporting them typically contain complex configurations, meant to " +
                               "make the APIs more customizable. Software and DevOps engineers can miss these configurations, " +
                               "or don't follow security best practices when it comes to configuration, opening the door for " +
                               "different types of attacks.";

        return new CustomScanIssue(
            baseRequestResponse.getHttpService(),
            helpers.analyzeRequest(baseRequestResponse).getUrl(),
            new IHttpRequestResponse[]{baseRequestResponse},
            "API8:2023 - Security Misconfiguration (CORS Reflected Origin)",
            "The API reflects the Origin header in Access-Control-Allow-Origin without validation. " +
            "This allows any website to read API responses.<br><br>" +
            "Origin sent: " + origin + "<br>" +
            "Origin reflected in response<br><br>" +
            "If credentials are allowed, this enables full cross-origin attacks.",
            issueBackground,
            "High",
            "Firm"
        );
    }

    private IScanIssue createInsecureProtocolIssue(IHttpRequestResponse baseRequestResponse) {
        String issueBackground = "API8:2023 - Security Misconfiguration<br><br>" +
                               "APIs and the systems supporting them typically contain complex configurations, meant to " +
                               "make the APIs more customizable. Software and DevOps engineers can miss these configurations, " +
                               "or don't follow security best practices when it comes to configuration, opening the door for " +
                               "different types of attacks.";

        return new CustomScanIssue(
            baseRequestResponse.getHttpService(),
            helpers.analyzeRequest(baseRequestResponse).getUrl(),
            new IHttpRequestResponse[]{baseRequestResponse},
            "API8:2023 - Security Misconfiguration (API Using HTTP - Insecure)",
            "The API is accessible over unencrypted HTTP. All data including authentication " +
            "tokens, credentials, and sensitive information is transmitted in cleartext and " +
            "can be intercepted by attackers.<br><br>" +
            "Recommendation: Use HTTPS exclusively for all API communications.",
            issueBackground,
            "High",
            "Certain"
        );
    }

    private IScanIssue createVerboseErrorIssue(IHttpRequestResponse baseRequestResponse) {
        String issueBackground = "API8:2023 - Security Misconfiguration<br><br>" +
                               "APIs and the systems supporting them typically contain complex configurations, meant to " +
                               "make the APIs more customizable. Software and DevOps engineers can miss these configurations, " +
                               "or don't follow security best practices when it comes to configuration, opening the door for " +
                               "different types of attacks.";

        return new CustomScanIssue(
            baseRequestResponse.getHttpService(),
            helpers.analyzeRequest(baseRequestResponse).getUrl(),
            new IHttpRequestResponse[]{baseRequestResponse},
            "API8:2023 - Security Misconfiguration (Verbose Error Messages)",
            "The API returns detailed error messages including stack traces or internal details. " +
            "This information can help attackers understand the internal structure and identify " +
            "specific vulnerabilities.<br><br>" +
            "Recommendation: Return generic error messages to clients and log detailed errors server-side.",
            issueBackground,
            "Low",
            "Firm"
        );
    }
}
