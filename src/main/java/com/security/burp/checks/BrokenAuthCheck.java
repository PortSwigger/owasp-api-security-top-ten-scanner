package com.security.burp.checks;

import burp.*;
import com.security.burp.model.CustomScanIssue;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import java.io.PrintWriter;
import java.util.*;

/**
 * Broken Authentication Check
 * OWASP API2:2023 - Tests for authentication vulnerabilities
 */
public class BrokenAuthCheck {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final PrintWriter stdout;
    private final boolean isDastMode;

    public BrokenAuthCheck(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
                          PrintWriter stdout, boolean isDastMode) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.stdout = stdout;
        this.isDastMode = isDastMode;
    }

    public List<IScanIssue> checkAuthentication(IHttpRequestResponse baseRequestResponse) {
        List<IScanIssue> issues = new ArrayList<>();

        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);
            List<String> headers = requestInfo.getHeaders();

            stdout.println("[Auth Check] Analyzing authentication mechanisms");

            // Check JWT tokens
            issues.addAll(checkJWTVulnerabilities(baseRequestResponse, headers));

            // Check for weak authentication
            issues.addAll(checkWeakAuthentication(baseRequestResponse, headers));

            // Check token expiration
            issues.addAll(checkTokenExpiration(baseRequestResponse));

        } catch (Exception e) {
            stdout.println("[Auth Check] Error: " + e.getMessage());
        }

        return issues;
    }

    private List<IScanIssue> checkJWTVulnerabilities(IHttpRequestResponse baseRequestResponse,
                                                     List<String> headers) {
        List<IScanIssue> issues = new ArrayList<>();

        try {
            for (String header : headers) {
                if (header.toLowerCase().startsWith("authorization: bearer ")) {
                    String token = header.substring(22).trim();

                    try {
                        DecodedJWT jwt = JWT.decode(token);

                        stdout.println("[Auth Check] JWT found, analyzing...");

                        // Check 1: No signature (alg: none)
                        if ("none".equalsIgnoreCase(jwt.getAlgorithm())) {
                            stdout.println("[Auth Check] ⚠️  JWT uses 'none' algorithm!");
                            issues.add(createJWTNoneAlgIssue(baseRequestResponse, token));
                        }

                        // Check 2: Weak algorithms
                        if ("HS256".equalsIgnoreCase(jwt.getAlgorithm()) ||
                            "HS384".equalsIgnoreCase(jwt.getAlgorithm()) ||
                            "HS512".equalsIgnoreCase(jwt.getAlgorithm())) {
                            stdout.println("[Auth Check] ⚠️  JWT uses symmetric algorithm (HMAC)");
                            issues.add(createWeakJWTAlgIssue(baseRequestResponse, jwt.getAlgorithm()));
                        }

                        // Check 3: No expiration
                        if (jwt.getExpiresAt() == null) {
                            stdout.println("[Auth Check] ⚠️  JWT has no expiration!");
                            issues.add(createJWTNoExpirationIssue(baseRequestResponse));
                        }

                        // Check 4: Long expiration (> 24 hours)
                        if (jwt.getExpiresAt() != null) {
                            long expiresIn = jwt.getExpiresAt().getTime() - System.currentTimeMillis();
                            long hoursUntilExpiry = expiresIn / (1000 * 60 * 60);
                            if (hoursUntilExpiry > 24) {
                                stdout.println("[Auth Check] ⚠️  JWT expires in " + hoursUntilExpiry + " hours");
                                issues.add(createJWTLongExpirationIssue(baseRequestResponse, hoursUntilExpiry));
                            }
                        }

                    } catch (Exception e) {
                        // Not a valid JWT or couldn't decode
                        stdout.println("[Auth Check] Could not decode JWT: " + e.getMessage());
                    }
                }
            }
        } catch (Exception e) {
            stdout.println("[Auth Check] JWT check error: " + e.getMessage());
        }

        return issues;
    }

    private List<IScanIssue> checkWeakAuthentication(IHttpRequestResponse baseRequestResponse,
                                                     List<String> headers) {
        List<IScanIssue> issues = new ArrayList<>();

        try {
            for (String header : headers) {
                String lowerHeader = header.toLowerCase();

                // Check for Basic Auth
                if (lowerHeader.startsWith("authorization: basic ")) {
                    stdout.println("[Auth Check] ⚠️  Basic authentication detected");
                    issues.add(createBasicAuthIssue(baseRequestResponse));
                }

                // Check for API keys in headers
                if (lowerHeader.startsWith("x-api-key:") ||
                    lowerHeader.startsWith("api-key:") ||
                    lowerHeader.startsWith("apikey:")) {
                    stdout.println("[Auth Check] API key authentication detected");
                    // Check if over HTTP
                    if (helpers.analyzeRequest(baseRequestResponse).getUrl().getProtocol().equals("http")) {
                        issues.add(createInsecureApiKeyIssue(baseRequestResponse));
                    }
                }
            }
        } catch (Exception e) {
            stdout.println("[Auth Check] Weak auth check error: " + e.getMessage());
        }

        return issues;
    }

    private List<IScanIssue> checkTokenExpiration(IHttpRequestResponse baseRequestResponse) {
        List<IScanIssue> issues = new ArrayList<>();

        // This would require storing tokens and retesting later
        // For now, we'll just flag information about token mechanisms

        return issues;
    }

    private IScanIssue createJWTNoneAlgIssue(IHttpRequestResponse baseRequestResponse, String token) {
        String issueBackground = "API2:2023 - Broken Authentication<br><br>" +
                               "Authentication mechanisms are often implemented incorrectly, allowing attackers " +
                               "to compromise authentication tokens or to exploit implementation flaws to assume " +
                               "other user's identities temporarily or permanently. Compromising a system's ability " +
                               "to identify the client/user, compromises API security overall.";

        return new CustomScanIssue(
            baseRequestResponse.getHttpService(),
            helpers.analyzeRequest(baseRequestResponse).getUrl(),
            new IHttpRequestResponse[]{baseRequestResponse},
            "API2:2023 - Broken Authentication (JWT 'none' Algorithm)",
            "The API accepts JWT tokens with algorithm 'none', which means no signature verification. " +
            "An attacker can forge arbitrary tokens by setting the algorithm to 'none' and removing the signature.<br><br>" +
            "Token: " + token.substring(0, Math.min(50, token.length())) + "...<br><br>" +
            "This completely bypasses authentication and is a critical vulnerability.",
            issueBackground,
            "Critical",
            "Certain"
        );
    }

    private IScanIssue createWeakJWTAlgIssue(IHttpRequestResponse baseRequestResponse, String algorithm) {
        String issueBackground = "API2:2023 - Broken Authentication<br><br>" +
                               "Authentication mechanisms are often implemented incorrectly, allowing attackers " +
                               "to compromise authentication tokens or to exploit implementation flaws to assume " +
                               "other user's identities temporarily or permanently. Compromising a system's ability " +
                               "to identify the client/user, compromises API security overall.";

        return new CustomScanIssue(
            baseRequestResponse.getHttpService(),
            helpers.analyzeRequest(baseRequestResponse).getUrl(),
            new IHttpRequestResponse[]{baseRequestResponse},
            "API2:2023 - Broken Authentication (Weak JWT Algorithm: " + algorithm + ")",
            "The API uses a symmetric HMAC algorithm (" + algorithm + ") for JWT signatures. " +
            "This is weaker than asymmetric algorithms (RS256, ES256) and requires the same secret " +
            "to be shared between multiple services, increasing the attack surface.<br><br>" +
            "Recommendation: Use RS256 (RSA) or ES256 (ECDSA) instead.",
            issueBackground,
            "Low",
            "Certain"
        );
    }

    private IScanIssue createJWTNoExpirationIssue(IHttpRequestResponse baseRequestResponse) {
        String issueBackground = "API2:2023 - Broken Authentication<br><br>" +
                               "Authentication mechanisms are often implemented incorrectly, allowing attackers " +
                               "to compromise authentication tokens or to exploit implementation flaws to assume " +
                               "other user's identities temporarily or permanently. Compromising a system's ability " +
                               "to identify the client/user, compromises API security overall.";

        return new CustomScanIssue(
            baseRequestResponse.getHttpService(),
            helpers.analyzeRequest(baseRequestResponse).getUrl(),
            new IHttpRequestResponse[]{baseRequestResponse},
            "API2:2023 - Broken Authentication (JWT Without Expiration)",
            "The JWT token does not contain an 'exp' (expiration) claim. This means the token " +
            "never expires and can be used indefinitely if compromised.<br><br>" +
            "Recommendation: Always set expiration times on JWTs (e.g., 1-24 hours).",
            issueBackground,
            "Medium",
            "Certain"
        );
    }

    private IScanIssue createJWTLongExpirationIssue(IHttpRequestResponse baseRequestResponse,
                                                    long hours) {
        String issueBackground = "API2:2023 - Broken Authentication<br><br>" +
                               "Authentication mechanisms are often implemented incorrectly, allowing attackers " +
                               "to compromise authentication tokens or to exploit implementation flaws to assume " +
                               "other user's identities temporarily or permanently. Compromising a system's ability " +
                               "to identify the client/user, compromises API security overall.";

        return new CustomScanIssue(
            baseRequestResponse.getHttpService(),
            helpers.analyzeRequest(baseRequestResponse).getUrl(),
            new IHttpRequestResponse[]{baseRequestResponse},
            "API2:2023 - Broken Authentication (Long JWT Expiration)",
            "The JWT token expires in " + hours + " hours. Long-lived tokens increase the " +
            "window of opportunity for attackers if the token is compromised.<br><br>" +
            "Recommendation: Use shorter expiration times (e.g., 1-24 hours) and implement refresh tokens.",
            issueBackground,
            "Low",
            "Certain"
        );
    }

    private IScanIssue createBasicAuthIssue(IHttpRequestResponse baseRequestResponse) {
        String issueBackground = "API2:2023 - Broken Authentication<br><br>" +
                               "Authentication mechanisms are often implemented incorrectly, allowing attackers " +
                               "to compromise authentication tokens or to exploit implementation flaws to assume " +
                               "other user's identities temporarily or permanently. Compromising a system's ability " +
                               "to identify the client/user, compromises API security overall.";

        return new CustomScanIssue(
            baseRequestResponse.getHttpService(),
            helpers.analyzeRequest(baseRequestResponse).getUrl(),
            new IHttpRequestResponse[]{baseRequestResponse},
            "API2:2023 - Broken Authentication (HTTP Basic Authentication)",
            "The API uses HTTP Basic Authentication, which transmits credentials in Base64 encoding " +
            "(easily decoded). While acceptable over HTTPS, this is weaker than modern token-based " +
            "authentication and requires sending credentials with every request.<br><br>" +
            "Recommendation: Use OAuth 2.0, JWT, or other token-based authentication.",
            issueBackground,
            "Information",
            "Certain"
        );
    }

    private IScanIssue createInsecureApiKeyIssue(IHttpRequestResponse baseRequestResponse) {
        String issueBackground = "API2:2023 - Broken Authentication<br><br>" +
                               "Authentication mechanisms are often implemented incorrectly, allowing attackers " +
                               "to compromise authentication tokens or to exploit implementation flaws to assume " +
                               "other user's identities temporarily or permanently. Compromising a system's ability " +
                               "to identify the client/user, compromises API security overall.";

        return new CustomScanIssue(
            baseRequestResponse.getHttpService(),
            helpers.analyzeRequest(baseRequestResponse).getUrl(),
            new IHttpRequestResponse[]{baseRequestResponse},
            "API2:2023 - Broken Authentication (API Key Over HTTP)",
            "The API key is being transmitted over unencrypted HTTP. API keys transmitted in " +
            "cleartext can be intercepted by attackers through man-in-the-middle attacks.<br><br>" +
            "Recommendation: Always use HTTPS for API communications.",
            issueBackground,
            "High",
            "Certain"
        );
    }
}
