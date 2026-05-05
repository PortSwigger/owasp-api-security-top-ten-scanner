package com.security.burp.ai;

import burp.api.montoya.MontoyaApi;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Asks Burp AI to suggest contextually privileged JSON field names for
 * mass-assignment testing, given an observed request body and endpoint.
 *
 * <p>Augments the static {@code SENSITIVE_FIELDS} list in
 * {@code MassAssignmentCheck} with names the model thinks the server might
 * accept, e.g. {@code accountTier}, {@code organizationRole},
 * {@code billingPlan}, {@code priceOverride}.
 *
 * <p>Cached per {@code (host, path, method, body-keys-hash)} so an active
 * scan does not pay for the same prompt many times.
 */
public final class AiFieldDiscovery {

    private static final int MAX_FIELDS = 8;
    private static final int MAX_NAME_LENGTH = 40;
    private static final int CACHE_LIMIT = 256;

    private static final Pattern JSON_KEY = Pattern.compile("\"([A-Za-z_][A-Za-z0-9_]*)\"\\s*:");
    private static final Pattern NON_NAME_CHAR = Pattern.compile("[^A-Za-z0-9_]");

    private static final String SYSTEM_PROMPT =
            "You suggest privileged JSON field names that a server might accept via " +
            "mass assignment but that are NOT already present in the user's request body. " +
            "Reply with JSON only, no prose:\n" +
            "{\"fields\": [\"<name>\", ...]}\n" +
            "Up to " + MAX_FIELDS + " names, camelCase or snake_case, no quotes within names.";

    private final MontoyaApi api;
    private final AiClient ai;
    private final ConcurrentMap<String, List<String>> cache = new ConcurrentHashMap<>();
    private final boolean disabled;

    public AiFieldDiscovery(MontoyaApi api, AiClient ai) {
        this.api = api;
        this.ai = ai;
        this.disabled = Boolean.getBoolean("com.security.burp.ai.discovery.disabled");
    }

    public boolean isAvailable() {
        return !disabled && ai.isAvailable();
    }

    /**
     * @return up to {@value #MAX_FIELDS} candidate field names, or empty list if
     *         AI is unavailable, the response is unparseable, or no novel names
     *         were proposed. Names are validated and de-duplicated against
     *         {@code jsonBody}'s existing keys.
     */
    public List<String> suggestFields(String host, String path, String method, String jsonBody) {
        if (!isAvailable()) return Collections.emptyList();

        Set<String> existingKeys = extractKeys(jsonBody);
        String cacheKey = buildCacheKey(host, path, method, existingKeys);
        List<String> cached = cache.get(cacheKey);
        if (cached != null) return cached;

        String reply = ai.ask(SYSTEM_PROMPT, buildUserPrompt(method, path, existingKeys));
        List<String> suggestions = parseSuggestions(reply, existingKeys);
        cache(cacheKey, suggestions);

        if (!suggestions.isEmpty()) {
            api.logging().logToOutput("[AI Field Discovery] " + path + " -> " + suggestions);
        }
        return suggestions;
    }

    // ---- Helpers ------------------------------------------------------------

    private static String buildUserPrompt(String method, String path, Set<String> existingKeys) {
        return "Endpoint: " + method + " " + path + "\n"
             + "Existing body fields: " + String.join(", ", existingKeys) + "\n"
             + "Suggest privileged or sensitive fields the server might accept that aren't already present.";
    }

    private static Set<String> extractKeys(String json) {
        if (json == null) return Collections.emptySet();
        Set<String> keys = new LinkedHashSet<>();
        Matcher m = JSON_KEY.matcher(json);
        while (m.find()) keys.add(m.group(1));
        return keys;
    }

    private static String buildCacheKey(String host, String path, String method, Set<String> keys) {
        return host + "|" + path + "|" + method + "|" + Integer.toHexString(keys.hashCode());
    }

    private void cache(String key, List<String> value) {
        if (cache.size() < CACHE_LIMIT) cache.put(key, value);
    }

    private static List<String> parseSuggestions(String reply, Set<String> existingKeys) {
        if (reply == null || reply.isBlank()) return Collections.emptyList();
        try {
            JsonObject root = JsonParser.parseString(reply).getAsJsonObject();
            JsonArray fields = root.has("fields") ? root.getAsJsonArray("fields") : new JsonArray();
            return sanitiseAndDedupe(fields, existingKeys);
        } catch (Exception e) {
            return Collections.emptyList();
        }
    }

    private static List<String> sanitiseAndDedupe(JsonArray fields, Set<String> existingKeys) {
        Set<String> existingLower = new LinkedHashSet<>();
        for (String key : existingKeys) existingLower.add(key.toLowerCase(Locale.ROOT));

        List<String> out = new ArrayList<>();
        for (var element : fields) {
            String raw = element.isJsonPrimitive() ? element.getAsString() : "";
            String name = NON_NAME_CHAR.matcher(raw.trim()).replaceAll("");
            if (name.isEmpty() || name.length() > MAX_NAME_LENGTH) continue;
            if (existingLower.contains(name.toLowerCase(Locale.ROOT))) continue;
            if (!out.contains(name)) out.add(name);
            if (out.size() >= MAX_FIELDS) break;
        }
        return out;
    }
}
