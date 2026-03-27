package com.security.burp.checks;

import burp.*;
import com.security.burp.model.CustomScanIssue;
import java.io.PrintWriter;
import java.util.*;

/**
 * Server-Side Request Forgery (SSRF) Check
 * OWASP API7:2023 - Server Side Request Forgery
 * Tests for SSRF vulnerabilities
 */
public class SsrfCheck {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final PrintWriter stdout;

    // SSRF test payloads
    private static final String[] SSRF_PAYLOADS = {
        "http://127.0.0.1",
        "http://localhost",
        "http://169.254.169.254/latest/meta-data/",  // AWS metadata
        "http://metadata.google.internal/",           // GCP metadata
        "http://[::1]",                               // IPv6 localhost
        "http://0.0.0.0",
        "file:///etc/passwd",
        "http://internal.local"
    };

    // Indicators of SSRF success
    private static final String[] SSRF_INDICATORS = {
        "ami-id", "instance-id", "local-ipv4",       // AWS metadata
        "root:", "daemon:", "/bin/bash",              // /etc/passwd
        "kube-env", "attributes/"                     // GCP metadata
    };

    public SsrfCheck(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
                    PrintWriter stdout) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.stdout = stdout;
    }

    public List<IScanIssue> checkSSRF(IHttpRequestResponse baseRequestResponse,
                                     IScannerInsertionPoint insertionPoint) {
        List<IScanIssue> issues = new ArrayList<>();

        try {
            String insertionPointName = insertionPoint.getInsertionPointName().toLowerCase();

            // Focus on URL-related parameters
            if (!isUrlParameter(insertionPointName)) {
                return issues;
            }

            stdout.println("[SSRF Check] Testing parameter: " + insertionPoint.getInsertionPointName());

            for (String payload : SSRF_PAYLOADS) {
                byte[] checkRequest = insertionPoint.buildRequest(payload.getBytes());

                IHttpRequestResponse checkResponse = callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), checkRequest);

                if (checkResponse.getResponse() != null) {
                    IResponseInfo responseInfo = helpers.analyzeResponse(checkResponse.getResponse());
                    int statusCode = responseInfo.getStatusCode();
                    String responseBody = getResponseBody(checkResponse.getResponse(), responseInfo);

                    // Check for SSRF success indicators
                    for (String indicator : SSRF_INDICATORS) {
                        if (responseBody.contains(indicator)) {
                            stdout.println("[SSRF Check] ⚠️  SSRF vulnerability confirmed!");
                            issues.add(createSSRFIssue(baseRequestResponse, checkResponse,
                                      insertionPoint, payload, indicator, "High"));
                            return issues;
                        }
                    }

                    // Check for successful connection (200 OK to internal resource)
                    if (statusCode == 200 && (payload.contains("127.0.0.1") ||
                        payload.contains("localhost") || payload.contains("169.254.169.254"))) {
                        stdout.println("[SSRF Check] ⚠️  Potential SSRF - internal URL accessible");
                        issues.add(createSSRFIssue(baseRequestResponse, checkResponse,
                                  insertionPoint, payload, "200 OK response", "Medium"));
                    }

                    // Check for timing differences (blind SSRF)
                    // This would require more sophisticated timing analysis
                }
            }

        } catch (Exception e) {
            stdout.println("[SSRF Check] Error: " + e.getMessage());
        }

        return issues;
    }

    private boolean isUrlParameter(String paramName) {
        return paramName.contains("url") ||
               paramName.contains("uri") ||
               paramName.contains("link") ||
               paramName.contains("redirect") ||
               paramName.contains("callback") ||
               paramName.contains("webhook") ||
               paramName.contains("destination") ||
               paramName.contains("target") ||
               paramName.contains("next") ||
               paramName.contains("proxy") ||
               paramName.contains("host") ||
               paramName.contains("domain") ||
               paramName.contains("path");
    }

    private String getResponseBody(byte[] response, IResponseInfo responseInfo) {
        int bodyOffset = responseInfo.getBodyOffset();
        if (bodyOffset < response.length) {
            return new String(Arrays.copyOfRange(response, bodyOffset, response.length));
        }
        return "";
    }

    private IScanIssue createSSRFIssue(IHttpRequestResponse original,
                                      IHttpRequestResponse attack,
                                      IScannerInsertionPoint insertionPoint,
                                      String payload, String indicator,
                                      String severity) {
        String issueName = "API7:2023 - Server Side Request Forgery";
        String issueDetail = "SSRF vulnerability detected - the API makes requests to attacker-controlled URLs.<br><br>" +
                           "Insertion point: " + insertionPoint.getInsertionPointName() + "<br>" +
                           "Payload: " + payload + "<br>" +
                           "Indicator: " + indicator + "<br><br>" +
                           "SSRF vulnerabilities allow attackers to:<br>" +
                           "- Access internal services and metadata endpoints<br>" +
                           "- Bypass firewalls and access controls<br>" +
                           "- Steal cloud credentials (AWS, GCP, Azure metadata)<br>" +
                           "- Port scan internal networks<br>" +
                           "- Read local files<br>" +
                           "- Perform attacks on behalf of the server";

        String issueBackground = "API7:2023 - Server Side Request Forgery<br><br>" +
                               "Server-Side Request Forgery (SSRF) flaws can occur when an API is fetching a remote " +
                               "resource without validating the user-supplied URI. This enables an attacker to coerce " +
                               "the application to send a crafted request to an unexpected destination, even when " +
                               "protected by a firewall or a VPN.";

        return new CustomScanIssue(
            original.getHttpService(),
            helpers.analyzeRequest(original).getUrl(),
            new IHttpRequestResponse[]{original, attack},
            issueName,
            issueDetail,
            issueBackground,
            severity,
            "Firm"
        );
    }
}
