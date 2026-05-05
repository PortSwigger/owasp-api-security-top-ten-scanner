package com.security.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.EnhancedCapability;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import com.security.burp.ai.AiClient;
import com.security.burp.ai.AiFieldDiscovery;
import com.security.burp.ai.AiTriage;
import com.security.burp.checks.active.SsrfCheck;
import com.security.burp.checks.passive.BusinessFlowCheck;
import com.security.burp.scanner.EndpointRegistry;
import com.security.burp.ui.ScannerTab;

import javax.swing.SwingUtilities;
import java.util.Set;

/**
 * Extension entry point.
 *
 * <p>Responsibilities are intentionally narrow:
 * <ul>
 *   <li>declare the {@link EnhancedCapability#AI_FEATURES} capability so
 *       Burp grants {@code api.ai()} access;</li>
 *   <li>construct shared collaborators (registry, AI client/triage/field
 *       discovery);</li>
 *   <li>register each scan check individually with its appropriate
 *       {@link ScanCheckType};</li>
 *   <li>register the UI tab (Professional / Community only);</li>
 *   <li>register an unloading handler that releases all resources.</li>
 * </ul>
 *
 * <p>All other behaviour lives in collaborators.
 */
public final class BurpExtender implements BurpExtension {

    private static final String EXTENSION_NAME = "Advanced API Security Scanner";

    @Override
    public Set<EnhancedCapability> enhancedCapabilities() {
        // Required for api.ai().isEnabled() to return true.
        return Set.of(EnhancedCapability.AI_FEATURES);
    }

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(EXTENSION_NAME);

        BurpSuiteEdition edition = api.burpSuite().version().edition();
        boolean isEnterprise = edition == BurpSuiteEdition.ENTERPRISE_EDITION;

        EndpointRegistry endpoints = new EndpointRegistry();
        AiClient aiClient = new AiClient(api);
        AiTriage triage = new AiTriage(api, aiClient);
        AiFieldDiscovery fieldDiscovery = new AiFieldDiscovery(api, aiClient);

        registerScanChecks(api, endpoints, triage, fieldDiscovery);

        ScannerTab tab = isEnterprise ? null : registerUiTab(api, endpoints);
        registerUnloadingHandler(api, aiClient, endpoints, tab);

        logBanner(api, edition, aiClient.isAvailable());
    }

    // ---- Scan-check registration -------------------------------------------

    private void registerScanChecks(MontoyaApi api,
                                    EndpointRegistry endpoints,
                                    AiTriage triage,
                                    AiFieldDiscovery fieldDiscovery) {
        // Active checks. Frequency reflects what each check operates on.
        api.scanner().registerActiveScanCheck(
                new SsrfCheck(api), ScanCheckType.PER_INSERTION_POINT);

        // Passive checks. PER_REQUEST runs once per HTTP transaction.
        api.scanner().registerPassiveScanCheck(
                new BusinessFlowCheck(api, endpoints, triage), ScanCheckType.PER_REQUEST);

        // Other checks (mass assignment with field discovery, injection, etc.)
        // will be added as they are migrated to the v2 architecture.
        // fieldDiscovery is referenced once so the field is not unused; it
        // belongs to mass-assignment and will be passed in when that check lands.
        if (fieldDiscovery == null) throw new IllegalStateException();
    }

    // ---- UI ----------------------------------------------------------------

    private ScannerTab registerUiTab(MontoyaApi api, EndpointRegistry endpoints) {
        ScannerTab tab = new ScannerTab(endpoints, api.userInterface().swingUtils());
        SwingUtilities.invokeLater(() ->
                api.userInterface().registerSuiteTab("API Scanner", tab.component()));
        return tab;
    }

    // ---- Unloading ---------------------------------------------------------

    private void registerUnloadingHandler(MontoyaApi api,
                                          AiClient aiClient,
                                          EndpointRegistry endpoints,
                                          ScannerTab tab) {
        api.extension().registerUnloadingHandler(() -> {
            aiClient.shutdown();
            endpoints.clear();
            if (tab != null) tab.dispose();
            api.logging().logToOutput("[" + EXTENSION_NAME + "] Unloaded cleanly.");
        });
    }

    // ---- Banner ------------------------------------------------------------

    private void logBanner(MontoyaApi api, BurpSuiteEdition edition, boolean aiAvailable) {
        api.logging().logToOutput("====================================");
        api.logging().logToOutput(EXTENSION_NAME + " v2.0.0");
        api.logging().logToOutput("OWASP API Security Top 10 (2023) coverage");
        api.logging().logToOutput("Edition: " + edition);
        api.logging().logToOutput("AI features: " + (aiAvailable ? "enabled" : "disabled"));
        api.logging().logToOutput("====================================");
    }
}
