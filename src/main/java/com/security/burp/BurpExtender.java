package com.security.burp;

import burp.*;
import com.security.burp.scanner.ApiScanner;
import com.security.burp.ui.ScannerTab;
import java.io.PrintWriter;
import java.util.List;
import javax.swing.*;

public class BurpExtender implements IBurpExtender, IHttpListener, IScannerCheck {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private ApiScanner apiScanner;
    private ScannerTab scannerTab;
    private boolean isDastMode;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        // Set up output streams
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);

        // Detect DAST/headless mode
        isDastMode = java.awt.GraphicsEnvironment.isHeadless();

        // Set extension name
        callbacks.setExtensionName("Advanced API Security Scanner V1");

        // Initialize components with DAST mode flag
        apiScanner = new ApiScanner(callbacks, helpers, stdout, stderr, isDastMode);

        // Register as HTTP listener and scanner check
        callbacks.registerHttpListener(this);
        callbacks.registerScannerCheck(this);

        // Create and add UI tab (only if not running in headless mode)
        try {
            if (!java.awt.GraphicsEnvironment.isHeadless()) {
                SwingUtilities.invokeLater(() -> {
                    try {
                        scannerTab = new ScannerTab(callbacks, apiScanner);
                        callbacks.addSuiteTab(scannerTab);
                        stdout.println("UI tab loaded successfully");
                    } catch (Exception e) {
                        stdout.println("Running in headless mode - UI tab disabled");
                    }
                });
            } else {
                stdout.println("Running in headless mode (Burp Enterprise/DAST) - UI tab disabled");
            }
        } catch (Exception e) {
            stdout.println("UI initialization skipped: " + e.getMessage());
        }

        stdout.println("====================================");
        stdout.println("Advanced API Security Scanner V1");
        stdout.println("OWASP API Security Top 10 2023");
        stdout.println("Enhanced OWASP Categorization & Severity Levels");
        stdout.println("Compatible with Burp Suite Professional & Enterprise Edition");
        stdout.println("====================================");
        stdout.println("Features:");
        stdout.println("  ✅ API1:2023 - Broken Object Level Authorization");
        stdout.println("  ✅ API2:2023 - Broken Authentication");
        stdout.println("  ✅ API3:2023 - Broken Object Property Level Authorization");
        stdout.println("  ⚠️ API4:2023 - Unrestricted Resource Consumption");
        stdout.println("  ✅ API5:2023 - Broken Function Level Authorization");
        stdout.println("  ⚠️ API6:2023 - Unrestricted Access to Sensitive Business Flows");
        stdout.println("  ✅ API7:2023 - Server Side Request Forgery");
        stdout.println("  ✅ API8:2023 - Security Misconfiguration");
        stdout.println("  ⚠️ API9:2023 - Improper Inventory Management");
        stdout.println("  ⚠️ API10:2023 - Unsafe Consumption of APIs");
        stdout.println("====================================");
        stdout.println("Key Features:");
        stdout.println("  - HTTP Method Fuzzing (9 methods tested)");
        stdout.println("  - Active + Passive Scanning");
        stdout.println("  - JWT Security Testing");
        stdout.println("  - Mass Assignment Detection");
        stdout.println("  - SSRF Detection");
        stdout.println("  - SQL/NoSQL/Command Injection");
        stdout.println("====================================");
        stdout.println("Extension loaded successfully!");
        stdout.println("Mode: " + (java.awt.GraphicsEnvironment.isHeadless() ? "Headless (Enterprise)" : "Interactive (Pro)"));
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // Only process proxy and scanner traffic
        if (toolFlag != IBurpExtenderCallbacks.TOOL_PROXY &&
            toolFlag != IBurpExtenderCallbacks.TOOL_SCANNER) {
            return;
        }

        try {
            if (messageIsRequest) {
                // Log request details (minimal logging in DAST mode)
                IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
                String url = requestInfo.getUrl().toString();
                String method = requestInfo.getMethod();

                if (!isDastMode) {
                    stdout.println("\n═══════════════════════════════════════");
                    stdout.println("[REQUEST] " + method + " " + url);
                    stdout.println("═══════════════════════════════════════");
                }

                // Check for Authorization header
                List<String> headers = requestInfo.getHeaders();
                boolean hasAuth = false;
                boolean hasBearer = false;

                for (String header : headers) {
                    String lowerHeader = header.toLowerCase();
                    if (lowerHeader.startsWith("authorization:")) {
                        hasAuth = true;
                        if (lowerHeader.contains("bearer")) {
                            hasBearer = true;
                            if (!isDastMode) {
                                // Show first 50 chars of token for debugging
                                stdout.println("  ✓ Authorization: " + header.substring(0, Math.min(50, header.length())) + "...");
                            }
                        } else {
                            if (!isDastMode) {
                                stdout.println("  ✓ Authorization: " + header);
                            }
                        }
                    }
                    // Also log other important headers
                    if (lowerHeader.startsWith("content-type:") && !isDastMode) {
                        stdout.println("  ✓ " + header);
                    }
                }

                // Only warn about missing auth in Interactive mode
                if (!hasAuth && !isDastMode) {
                    stdout.println("  ⚠️  WARNING: No Authorization header found");
                } else if (!hasBearer && hasAuth && !isDastMode) {
                    stdout.println("  ⚠️  WARNING: Authorization header found but not Bearer token");
                }

                // Log request body for POST/PUT (Interactive mode only)
                if (!isDastMode && (method.equals("POST") || method.equals("PUT") || method.equals("PATCH"))) {
                    int bodyOffset = requestInfo.getBodyOffset();
                    byte[] request = messageInfo.getRequest();
                    if (bodyOffset < request.length) {
                        String body = new String(request, bodyOffset, Math.min(200, request.length - bodyOffset));
                        stdout.println("  📄 Body: " + body.replace("\n", "").replace("\r", "") +
                                     (request.length - bodyOffset > 200 ? "..." : ""));
                    }
                }

                // Analyze request
                apiScanner.analyzeRequest(messageInfo);

            } else {
                // Log response details
                byte[] response = messageInfo.getResponse();
                if (response != null) {
                    IResponseInfo responseInfo = helpers.analyzeResponse(response);
                    IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
                    String url = requestInfo.getUrl().toString();
                    String urlPath = requestInfo.getUrl().getPath().toLowerCase();
                    short statusCode = responseInfo.getStatusCode();

                    // Check if request had Authorization header
                    List<String> requestHeaders = requestInfo.getHeaders();
                    boolean hadAuthHeader = false;
                    for (String header : requestHeaders) {
                        if (header.toLowerCase().startsWith("authorization:")) {
                            hadAuthHeader = true;
                            break;
                        }
                    }

                    // Determine if this is a login/auth endpoint
                    boolean isAuthEndpoint = urlPath.contains("/login") ||
                                           urlPath.contains("/auth") ||
                                           urlPath.contains("/signin") ||
                                           urlPath.contains("/token") ||
                                           urlPath.contains("/register");

                    // Color code status
                    String statusColor;
                    String statusEmoji;
                    if (statusCode >= 200 && statusCode < 300) {
                        statusColor = "SUCCESS";
                        statusEmoji = "✅";
                    } else if (statusCode == 401 || statusCode == 403) {
                        // Determine if this is expected or unexpected
                        if (!hadAuthHeader) {
                            // Expected: Testing without auth (security test)
                            statusColor = "AUTH REQUIRED (Expected)";
                            statusEmoji = "🔒";
                        } else if (isAuthEndpoint) {
                            // Expected: Testing login with invalid creds
                            statusColor = "AUTH FAILED (Expected)";
                            statusEmoji = "🔒";
                        } else {
                            // Unexpected: Had auth but still got 401/403
                            statusColor = "AUTH ERROR (Token Issue)";
                            statusEmoji = "⚠️";
                        }
                    } else if (statusCode >= 400 && statusCode < 500) {
                        statusColor = "CLIENT ERROR";
                        statusEmoji = "⚠️";
                    } else if (statusCode >= 500) {
                        statusColor = "SERVER ERROR";
                        statusEmoji = "❌";
                    } else {
                        statusColor = "REDIRECT";
                        statusEmoji = "↪️";
                    }

                    // In DAST mode, suppress expected auth failure messages to reduce noise
                    if (!isDastMode) {
                        stdout.println("[RESPONSE] " + statusEmoji + " " + statusCode + " (" + statusColor + ") for " + url);
                    }

                    // Only show detailed troubleshooting for UNEXPECTED auth errors
                    if ((statusCode == 401 || statusCode == 403) && hadAuthHeader && !isAuthEndpoint) {
                        // UNEXPECTED auth failure - always log this
                        stdout.println("[RESPONSE] " + statusEmoji + " " + statusCode + " (" + statusColor + ") for " + url);
                        stdout.println("─────────────────────────────────────");
                        stdout.println("⚠️ UNEXPECTED AUTH FAILURE (Token may be invalid/expired)");
                        stdout.println("─────────────────────────────────────");

                        // Parse and show error message
                        int bodyOffset = responseInfo.getBodyOffset();
                        if (bodyOffset < response.length) {
                            String responseBody = new String(response, bodyOffset, Math.min(500, response.length - bodyOffset));
                            stdout.println("  Error Response: " + responseBody);
                        }

                        stdout.println("\n  💡 Action Required:");
                        stdout.println("  - Token may be expired or invalid");
                        stdout.println("  - Check Burp's Session Handling Rules");
                        stdout.println("  - Verify token is still valid");
                        stdout.println("─────────────────────────────────────\n");
                    } else if ((statusCode == 401 || statusCode == 403) && !hadAuthHeader && !isDastMode) {
                        // Expected auth failure - only log in Interactive mode
                        stdout.println("  ℹ️  Security Test: Endpoint requires authentication (as expected)");
                    } else if (statusCode >= 200 && statusCode < 300 && !isDastMode) {
                        // Success - log in Interactive mode
                        stdout.println("[RESPONSE] " + statusEmoji + " " + statusCode + " (" + statusColor + ") for " + url);
                    }

                    // Always report 500 errors as these indicate potential DoS/resource exhaustion
                    if (statusCode >= 500) {
                        stdout.println("  ⚠️  POTENTIAL VULNERABILITY: Server error may indicate resource exhaustion or crash");
                    }
                }
            }
        } catch (Exception e) {
            stderr.println("[ERROR] Exception in processHttpMessage: " + e.getMessage());
            e.printStackTrace(stderr);
        }
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        stdout.println("[BurpExtender] doPassiveScan called for: " +
                      helpers.analyzeRequest(baseRequestResponse).getUrl().toString());
        return apiScanner.doPassiveScan(baseRequestResponse);
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        stdout.println("[BurpExtender] doActiveScan called for: " +
                      helpers.analyzeRequest(baseRequestResponse).getUrl().toString());
        return apiScanner.doActiveScan(baseRequestResponse, insertionPoint);
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        // Consolidate if same issue type and URL
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()) &&
            existingIssue.getUrl().equals(newIssue.getUrl())) {
            return -1; // Keep existing issue
        }
        return 0; // Keep both issues
    }
}
