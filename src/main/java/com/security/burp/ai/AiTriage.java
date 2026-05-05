package com.security.burp.ai;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Filters passive scan findings through Burp AI to suppress contextual
 * false positives.
 *
 * <p>For each issue we ask the model whether the finding is exploitable
 * given the request/response context. The reply must be JSON; anything
 * else is treated as KEEP. KEEP is also the response to AI being
 * unavailable, slow, or erroring.
 *
 * <p>Conservative by design: the only states are KEEP and SUPPRESS. The
 * detector is the source of truth; AI may only filter, never invent.
 */
public final class AiTriage {

    private static final int MAX_HEADER_BYTES = 500;
    private static final int MAX_BODY_BYTES = 400;

    private static final String SYSTEM_PROMPT =
            "You triage Burp Suite passive scan findings. Decide whether each finding is " +
            "exploitable in this specific request/response context. Reply with JSON only, " +
            "no prose:\n" +
            "{\"verdict\": \"KEEP\" | \"SUPPRESS\", \"reason\": \"<one sentence>\"}\n" +
            "Use SUPPRESS only when the finding is clearly not exploitable here (for " +
            "example: missing X-Frame-Options on a JSON-only API response that never " +
            "renders HTML, or missing CSP on an API endpoint that returns no markup). " +
            "Otherwise reply KEEP. If in doubt, KEEP.";

    private final MontoyaApi api;
    private final AiClient ai;
    private final boolean disabled;

    public AiTriage(MontoyaApi api, AiClient ai) {
        this.api = api;
        this.ai = ai;
        this.disabled = Boolean.getBoolean("com.security.burp.ai.triage.disabled");
    }

    /** Filters {@code issues} in order; returns a possibly-shorter list. */
    public List<AuditIssue> filter(List<AuditIssue> issues, HttpRequestResponse rr) {
        if (disabled || issues.isEmpty() || !ai.isAvailable()) return issues;
        List<AuditIssue> kept = new ArrayList<>(issues.size());
        for (AuditIssue issue : issues) {
            if (verdict(issue, rr) == Verdict.SUPPRESS) {
                api.logging().logToOutput("[AI Triage] Suppressed: " + issue.name());
            } else {
                kept.add(issue);
            }
        }
        return kept;
    }

    private Verdict verdict(AuditIssue issue, HttpRequestResponse rr) {
        String reply = ai.ask(SYSTEM_PROMPT, buildUserPrompt(issue, rr));
        if (reply == null) return Verdict.KEEP;
        try {
            JsonObject json = JsonParser.parseString(reply).getAsJsonObject();
            String verdict = json.has("verdict") ? json.get("verdict").getAsString() : "";
            return "SUPPRESS".equalsIgnoreCase(verdict) ? Verdict.SUPPRESS : Verdict.KEEP;
        } catch (Exception e) {
            // Unparseable reply — fall back to KEEP rather than guessing.
            return Verdict.KEEP;
        }
    }

    private static String buildUserPrompt(AuditIssue issue, HttpRequestResponse rr) {
        String url = truncate(rr.request().url(), 200);
        String reqHeaders = truncate(rr.request().headers().toString(), MAX_HEADER_BYTES);
        String respHeaders = rr.hasResponse()
                ? truncate(rr.response().headers().toString(), MAX_HEADER_BYTES)
                : "(no response)";
        String respBody = rr.hasResponse()
                ? truncate(rr.response().bodyToString(), MAX_BODY_BYTES)
                : "";

        return "Finding: " + issue.name() + "\n" +
               "Severity: " + issue.severity() + "\n" +
               "URL: " + url + "\n" +
               "Request headers: " + reqHeaders + "\n" +
               "Response headers: " + respHeaders + "\n" +
               "Response body excerpt: " + respBody;
    }

    private static String truncate(String s, int maxBytes) {
        if (s == null) return "";
        String oneLine = s.replace('\n', ' ').replace('\r', ' ');
        return oneLine.length() <= maxBytes ? oneLine : oneLine.substring(0, maxBytes) + "...";
    }

    private enum Verdict { KEEP, SUPPRESS }

    @SuppressWarnings("unused")
    private static String normalise(String s) {
        return s == null ? "" : s.toLowerCase(Locale.ROOT);
    }
}
