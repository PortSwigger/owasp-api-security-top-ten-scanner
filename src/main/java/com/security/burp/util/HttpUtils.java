package com.security.burp.util;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.Locale;

/**
 * Stateless helpers for inspecting HTTP messages. No business logic — just
 * the small predicates we'd otherwise duplicate across every check.
 */
public final class HttpUtils {

    private HttpUtils() {}

    public static boolean isJson(HttpRequest request) {
        return contentTypeContains(request, "application/json");
    }

    public static boolean isJson(HttpResponse response) {
        return contentTypeContains(response, "application/json");
    }

    public static boolean isApiPath(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase(Locale.ROOT);
        return lower.contains("/api/")
                || lower.matches(".*/v\\d+/.*")
                || lower.endsWith("/graphql")
                || lower.endsWith(".json");
    }

    public static boolean isModifyingMethod(String method) {
        return "POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method);
    }

    private static boolean contentTypeContains(HttpRequest request, String needle) {
        for (HttpHeader header : request.headers()) {
            if ("content-type".equalsIgnoreCase(header.name())) {
                return header.value() != null
                        && header.value().toLowerCase(Locale.ROOT).contains(needle);
            }
        }
        return false;
    }

    private static boolean contentTypeContains(HttpResponse response, String needle) {
        for (HttpHeader header : response.headers()) {
            if ("content-type".equalsIgnoreCase(header.name())) {
                return header.value() != null
                        && header.value().toLowerCase(Locale.ROOT).contains(needle);
            }
        }
        return false;
    }
}
