package com.security.burp.scanner;

import burp.*;
import com.security.burp.checks.*;
import com.security.burp.utils.ApiEndpoint;
import java.io.PrintWriter;
import java.net.URL;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class ApiScanner {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final PrintWriter stdout;
    private final PrintWriter stderr;
    private final boolean isDastMode;

    // Store discovered API endpoints
    private final Map<String, ApiEndpoint> discoveredEndpoints;

    // Security checks
    private final MethodFuzzingCheck methodFuzzingCheck;
    private final BrokenObjectAuthCheck bolaCheck;
    private final BrokenAuthCheck authCheck;
    private final MassAssignmentCheck massAssignmentCheck;
    private final ExcessiveDataExposureCheck dataExposureCheck;
    private final InjectionCheck injectionCheck;
    private final SsrfCheck ssrfCheck;
    private final SecurityMisconfigCheck misconfigCheck;
    private final ResourceConsumptionCheck resourceCheck;
    private final BusinessFlowCheck businessFlowCheck;
    private final InventoryManagementCheck inventoryCheck;
    private final UnsafeApiConsumptionCheck unsafeConsumptionCheck;
    private final FunctionLevelAuthCheck functionLevelAuthCheck;

    public ApiScanner(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
                     PrintWriter stdout, PrintWriter stderr, boolean isDastMode) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.stdout = stdout;
        this.stderr = stderr;
        this.isDastMode = isDastMode;
        this.discoveredEndpoints = new ConcurrentHashMap<>();

        stdout.println("[ApiScanner] Initializing in " + (isDastMode ? "DAST" : "Interactive") + " mode");

        // Initialize security checks with DAST mode awareness
        // In DAST mode, these checks will be less aggressive to reduce false auth errors
        this.methodFuzzingCheck = new MethodFuzzingCheck(callbacks, helpers, stdout, isDastMode);
        this.bolaCheck = new BrokenObjectAuthCheck(callbacks, helpers, stdout, isDastMode);
        this.authCheck = new BrokenAuthCheck(callbacks, helpers, stdout, isDastMode);
        this.massAssignmentCheck = new MassAssignmentCheck(callbacks, helpers, stdout);
        this.dataExposureCheck = new ExcessiveDataExposureCheck(callbacks, helpers, stdout);
        this.injectionCheck = new InjectionCheck(callbacks, helpers, stdout);
        this.ssrfCheck = new SsrfCheck(callbacks, helpers, stdout);
        this.misconfigCheck = new SecurityMisconfigCheck(callbacks, helpers, stdout);
        this.resourceCheck = new ResourceConsumptionCheck(callbacks, helpers, stdout);
        this.businessFlowCheck = new BusinessFlowCheck(callbacks, helpers, stdout);
        this.inventoryCheck = new InventoryManagementCheck(callbacks, helpers, stdout);
        this.unsafeConsumptionCheck = new UnsafeApiConsumptionCheck(callbacks, helpers, stdout);
        this.functionLevelAuthCheck = new FunctionLevelAuthCheck(callbacks, helpers, stdout);
    }

    public void analyzeRequest(IHttpRequestResponse messageInfo) {
        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
            URL url = requestInfo.getUrl();
            String method = requestInfo.getMethod();

            // Create endpoint signature
            String endpointKey = normalizeEndpoint(url.getPath());

            // Track discovered endpoints
            ApiEndpoint endpoint = discoveredEndpoints.computeIfAbsent(endpointKey,
                k -> new ApiEndpoint(endpointKey, url.getHost()));
            endpoint.addMethod(method);

            // Log API endpoint discovery
            if (isApiEndpoint(url.getPath())) {
                stdout.println("[API Discovery] " + method + " " + url.getPath());
            }
        } catch (Exception e) {
            stderr.println("Error analyzing request: " + e.getMessage());
        }
    }

    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        List<IScanIssue> issues = new ArrayList<>();

        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);

            // Only scan API endpoints
            if (!isApiEndpoint(requestInfo.getUrl().getPath())) {
                return issues;
            }

            // Passive checks
            issues.addAll(dataExposureCheck.checkPassive(baseRequestResponse));
            issues.addAll(misconfigCheck.checkPassive(baseRequestResponse));
            issues.addAll(resourceCheck.checkPassive(baseRequestResponse));
            issues.addAll(businessFlowCheck.checkPassive(baseRequestResponse));
            issues.addAll(inventoryCheck.checkPassive(baseRequestResponse));
            issues.addAll(unsafeConsumptionCheck.checkPassive(baseRequestResponse));

        } catch (Exception e) {
            stderr.println("Error in passive scan: " + e.getMessage());
        }

        return issues;
    }

    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse,
                                         IScannerInsertionPoint insertionPoint) {
        List<IScanIssue> issues = new ArrayList<>();

        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);

            // Active scan runs on ALL endpoints that user explicitly selects
            // No filtering - scan everything the user chooses to scan

            if (isDastMode) {
                stdout.println("[Active Scan] DAST Mode - Minimal active testing: " +
                              requestInfo.getUrl().getPath());

                // In DAST mode, only run passive-style checks that analyze without modifying requests
                // This prevents DAST from seeing 401/403 responses from test variations

                // Passive JWT analysis (no additional requests)
                issues.addAll(authCheck.checkAuthentication(baseRequestResponse));

                stdout.println("[Active Scan] DAST Mode - Skipping all active checks (method fuzzing, BOLA, injection)");
                stdout.println("[Active Scan] DAST Mode - Use Burp Pro for comprehensive active testing");

            } else {
                stdout.println("[Active Scan] Starting comprehensive API security scan: " +
                              requestInfo.getUrl().getPath());

                // HTTP Method Fuzzing - KEY FEATURE
                issues.addAll(methodFuzzingCheck.performMethodFuzzing(baseRequestResponse));

                // OWASP API Security Top 10 Checks
                issues.addAll(bolaCheck.checkBOLA(baseRequestResponse, insertionPoint));
                issues.addAll(authCheck.checkAuthentication(baseRequestResponse));
                issues.addAll(massAssignmentCheck.checkMassAssignment(baseRequestResponse, insertionPoint));
                issues.addAll(functionLevelAuthCheck.checkFunctionLevelAuth(baseRequestResponse));
                issues.addAll(injectionCheck.checkInjections(baseRequestResponse, insertionPoint));
                issues.addAll(ssrfCheck.checkSSRF(baseRequestResponse, insertionPoint));
            }

            stdout.println("[Active Scan] Found " + issues.size() + " issues");

            // Debug: Print all issues found
            for (IScanIssue issue : issues) {
                stdout.println("  - " + issue.getSeverity() + ": " + issue.getIssueName() +
                             " (confidence: " + issue.getConfidence() + ")");
                // Explicitly add to Burp's issue tracker
                callbacks.addScanIssue(issue);
            }

        } catch (Exception e) {
            stderr.println("Error in active scan: " + e.getMessage());
            e.printStackTrace(stderr);
        }

        return issues;
    }

    private boolean isApiEndpoint(String path) {
        String lowerPath = path.toLowerCase();
        return lowerPath.contains("/api/") ||
               lowerPath.matches(".*/v\\d+/.*") ||
               lowerPath.endsWith(".json") ||
               lowerPath.endsWith("/graphql");
    }

    private String normalizeEndpoint(String path) {
        // Replace numeric IDs and UUIDs with placeholders for grouping
        return path.replaceAll("/\\d+", "/{id}")
                   .replaceAll("/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", "/{uuid}")
                   .replaceAll("/[a-f0-9]{24}", "/{id}"); // MongoDB ObjectID
    }

    public Map<String, ApiEndpoint> getDiscoveredEndpoints() {
        return new HashMap<>(discoveredEndpoints);
    }
}
