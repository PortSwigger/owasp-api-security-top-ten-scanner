package com.security.burp.checks.active;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.security.burp.checks.AbstractActiveCheck;
import com.security.burp.util.HttpUtils;
import com.security.burp.util.IssueBuilder;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * OWASP API2:2023 — Broken Authentication.
 *
 * <p>Pure-inspection check (no outbound traffic): looks at the request's
 * authentication headers and reports common JWT and HTTP Basic
 * weaknesses. Registered as an active check by category but does not
 * itself issue requests.
 *
 * <p>JWT decoding is hand-rolled (no third-party JWT library) — we only
 * need the {@code alg} claim from the header and the {@code exp} claim
 * from the payload. Bringing in a full JWT verifier just for two field
 * lookups would be over-engineering.
 *
 * <p>Registered {@code PER_HOST}; deduped per token so the same JWT seen
 * many times is analysed once.
 */
public final class BrokenAuthCheck extends AbstractActiveCheck {

    /** JWTs whose remaining lifetime exceeds this threshold are flagged. */
    private static final Duration LONG_LIFETIME_THRESHOLD = Duration.ofHours(24);

    private static final Set<String> SYMMETRIC_JWT_ALGS = Set.of("HS256", "HS384", "HS512");

    private static final Set<String> API_KEY_HEADER_NAMES = Set.of(
            "x-api-key", "api-key", "apikey");

    private static final String ISSUE_BACKGROUND =
            "API2:2023 - Broken Authentication<br><br>" +
            "Authentication weaknesses let an attacker assume another user's identity, either " +
            "by forging tokens or by abusing implementation flaws. Long-lived or unsigned " +
            "tokens, weak transport, and predictable schemes all sit under this category.";

    /** Cross-reference to Burp's native JWT scan checks. */
    private static final String RELATED_JWT =
            "<br><br><b>Related Burp Scanner checks:</b> for further detail refer to the native " +
            "<b>JWT signature not verified</b>, <b>JWT none algorithm supported</b>, " +
            "<b>JWT self-signed JWK header supported</b>, <b>JWT weak HMAC secret</b> and " +
            "<b>JSON Web Key Set disclosed</b> checks in the " +
            "<a href=\"https://portswigger.net/burp/documentation/scanner/vulnerabilities-list\">" +
            "Burp Scanner vulnerabilities list</a>.";

    /** Cross-reference to Burp's native cleartext-credential scan checks. */
    private static final String RELATED_CLEARTEXT =
            "<br><br><b>Related Burp Scanner checks:</b> for further detail refer to the native " +
            "<b>Cleartext submission of password</b> and <b>Unencrypted communications</b> " +
            "checks in the " +
            "<a href=\"https://portswigger.net/burp/documentation/scanner/vulnerabilities-list\">" +
            "Burp Scanner vulnerabilities list</a>.";

    private final Set<String> seenTokens = Collections.newSetFromMap(new ConcurrentHashMap<>());

    public BrokenAuthCheck(MontoyaApi api) {
        super(api);
    }

    @Override
    public String checkName() {
        return "API2:2023 Broken Authentication";
    }

    @Override
    protected List<AuditIssue> audit(HttpRequestResponse rr, AuditInsertionPoint ip, Http http) {
        List<AuditIssue> issues = new ArrayList<>();

        String bearer = bearerToken(rr.request());
        if (bearer != null && seenTokens.add(bearer)) {
            issues.addAll(analyseJwt(rr, bearer));
        }

        if (hasBasicAuth(rr.request())) issues.add(buildBasicAuthIssue(rr));
        if (hasApiKeyOverHttp(rr.request())) issues.add(buildInsecureApiKeyIssue(rr));

        return issues;
    }

    // ---- Header inspection -------------------------------------------------

    private static String bearerToken(HttpRequest request) {
        String value = headerValueLower(request, "authorization");
        if (value == null) return null;
        if (!value.startsWith("bearer ")) return null;
        // Use the original-case value so we don't lose-case-sensitive base64.
        return originalAuthorizationHeader(request).substring("Bearer ".length()).trim();
    }

    private static String originalAuthorizationHeader(HttpRequest request) {
        for (HttpHeader header : request.headers()) {
            if (header.name() != null && "authorization".equalsIgnoreCase(header.name())) {
                return header.value() == null ? "" : header.value();
            }
        }
        return "";
    }

    private static String headerValueLower(HttpRequest request, String nameLower) {
        for (HttpHeader header : request.headers()) {
            if (header.name() != null && nameLower.equals(header.name().toLowerCase(Locale.ROOT))) {
                String v = header.value();
                return v == null ? null : v.toLowerCase(Locale.ROOT);
            }
        }
        return null;
    }

    private static boolean hasBasicAuth(HttpRequest request) {
        String value = headerValueLower(request, "authorization");
        return value != null && value.startsWith("basic ");
    }

    private static boolean hasApiKeyOverHttp(HttpRequest request) {
        if (request.url() == null || !request.url().startsWith("http://")) return false;
        // Loopback HTTP has no network intermediary, so the key never leaves
        // the local machine — flagging http://localhost dev endpoints High is
        // a false positive. Skip loopback hosts.
        if (HttpUtils.isLoopbackHost(request.httpService().host())) return false;
        for (HttpHeader header : request.headers()) {
            if (header.name() != null
                    && API_KEY_HEADER_NAMES.contains(header.name().toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    // ---- JWT analysis ------------------------------------------------------

    private List<AuditIssue> analyseJwt(HttpRequestResponse rr, String token) {
        Jwt jwt = parseJwt(token);
        if (jwt == null) return List.of();

        List<AuditIssue> issues = new ArrayList<>();
        if ("none".equalsIgnoreCase(jwt.algorithm)) {
            issues.add(buildNoneAlgIssue(rr, token));
        }
        if (SYMMETRIC_JWT_ALGS.contains(jwt.algorithm == null ? "" : jwt.algorithm.toUpperCase(Locale.ROOT))) {
            issues.add(buildWeakAlgIssue(rr, jwt.algorithm));
        }
        if (jwt.expiresAt == null) {
            issues.add(buildNoExpirationIssue(rr));
        } else {
            Duration remaining = Duration.between(Instant.now(), jwt.expiresAt);
            if (remaining.compareTo(LONG_LIFETIME_THRESHOLD) > 0) {
                issues.add(buildLongExpirationIssue(rr, remaining.toHours()));
            }
        }
        return issues;
    }

    private static Jwt parseJwt(String token) {
        String[] parts = token.split("\\.");
        if (parts.length < 2) return null;
        try {
            JsonObject header = parseBase64Json(parts[0]);
            JsonObject payload = parseBase64Json(parts[1]);
            String alg = header == null || !header.has("alg") ? null : header.get("alg").getAsString();
            Instant exp = null;
            if (payload != null && payload.has("exp")) {
                JsonElement element = payload.get("exp");
                if (element.isJsonPrimitive()) exp = Instant.ofEpochSecond(element.getAsLong());
            }
            return new Jwt(alg, exp);
        } catch (Exception e) {
            return null;
        }
    }

    private static JsonObject parseBase64Json(String segment) {
        if (segment == null || segment.isEmpty()) return null;
        byte[] decoded = Base64.getUrlDecoder().decode(padBase64(segment));
        String json = new String(decoded, StandardCharsets.UTF_8);
        JsonElement element = JsonParser.parseString(json);
        return element.isJsonObject() ? element.getAsJsonObject() : null;
    }

    /** Base64-url segments may omit padding; restore it. */
    private static String padBase64(String s) {
        int pad = (4 - s.length() % 4) % 4;
        return pad == 0 ? s : s + "=".repeat(pad);
    }

    private record Jwt(String algorithm, Instant expiresAt) {}

    // ---- Issues ------------------------------------------------------------

    private AuditIssue buildNoneAlgIssue(HttpRequestResponse rr, String token) {
        String snippet = token.length() > 50 ? token.substring(0, 50) + "..." : token;
        String detail =
                "The request carries a JWT whose <code>alg</code> header is <code>none</code>. " +
                "Servers that accept this can be coerced into trusting unsigned tokens — an " +
                "attacker can forge any identity.<br><br>" +
                "Token (truncated): <code>" + IssueBuilder.escapeHtml(snippet) + "</code>";
        return IssueBuilder.issue(rr)
                .name("API2:2023 - Broken Authentication (JWT 'none' Algorithm)")
                .detail(detail + RELATED_JWT)
                .remediation("Reject tokens whose alg is 'none'; pin the accepted algorithm " +
                        "list at the verifier.")
                .background(ISSUE_BACKGROUND)
                .severity("Critical")
                .confidence("Certain")
                .build();
    }

    private AuditIssue buildWeakAlgIssue(HttpRequestResponse rr, String alg) {
        String escapedAlg = IssueBuilder.escapeHtml(alg);
        String detail =
                "The JWT uses a symmetric HMAC algorithm (<code>" + escapedAlg + "</code>). HMAC " +
                "secrets are necessarily shared between issuer and verifier; any service that " +
                "verifies tokens can also forge them.";
        return IssueBuilder.issue(rr)
                .name("API2:2023 - Broken Authentication (Weak JWT Algorithm: " + escapedAlg + ")")
                .detail(detail + RELATED_JWT)
                .remediation("Prefer asymmetric algorithms (RS256, ES256) so verifiers cannot " +
                        "mint new tokens.")
                .background(ISSUE_BACKGROUND)
                .severity("Low")
                .confidence("Certain")
                .build();
    }

    private AuditIssue buildNoExpirationIssue(HttpRequestResponse rr) {
        return IssueBuilder.issue(rr)
                .name("API2:2023 - Broken Authentication (JWT Without Expiration)")
                .detail("The JWT has no <code>exp</code> claim. Tokens without expiry remain " +
                        "valid forever once issued; a single leak compromises the account " +
                        "indefinitely." + RELATED_JWT)
                .remediation("Always include an <code>exp</code> claim. 1–24 hours is typical.")
                .background(ISSUE_BACKGROUND)
                .severity("Medium")
                .confidence("Certain")
                .build();
    }

    private AuditIssue buildLongExpirationIssue(HttpRequestResponse rr, long hours) {
        return IssueBuilder.issue(rr)
                .name("API2:2023 - Broken Authentication (Long JWT Expiration)")
                .detail("The JWT expires in approximately " + hours + " hours. Long-lived " +
                        "tokens widen the window of compromise." + RELATED_JWT)
                .remediation("Shorten the expiry window and use refresh tokens for continued " +
                        "session lifetime.")
                .background(ISSUE_BACKGROUND)
                .severity("Low")
                .confidence("Certain")
                .build();
    }

    private AuditIssue buildBasicAuthIssue(HttpRequestResponse rr) {
        return IssueBuilder.issue(rr)
                .name("API2:2023 - Broken Authentication (HTTP Basic Authentication)")
                .detail("The request uses HTTP Basic Authentication. Credentials are sent " +
                        "with every request and are merely Base64-encoded; over HTTPS this is " +
                        "tolerable but it remains weaker than modern token-based auth." +
                        RELATED_CLEARTEXT)
                .remediation("Switch to OAuth 2.0 / OIDC or another token-based scheme.")
                .background(ISSUE_BACKGROUND)
                .severity("Information")
                .confidence("Certain")
                .build();
    }

    private AuditIssue buildInsecureApiKeyIssue(HttpRequestResponse rr) {
        return IssueBuilder.issue(rr)
                .name("API2:2023 - Broken Authentication (API Key Over HTTP)")
                .detail("An API key header is being sent over unencrypted HTTP. Any " +
                        "intermediary on the path can capture and reuse the key." +
                        RELATED_CLEARTEXT)
                .remediation("Serve the API exclusively over HTTPS.")
                .background(ISSUE_BACKGROUND)
                .severity("High")
                .confidence("Certain")
                .build();
    }
}
