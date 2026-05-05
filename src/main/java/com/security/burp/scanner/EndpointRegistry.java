package com.security.burp.scanner;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Thread-safe registry of API endpoints discovered during scanning.
 *
 * Used by passive checks to record what they see, and by the UI tab to
 * display discovery state. Bounded so a long-running scan against a large
 * site cannot exhaust memory.
 */
public final class EndpointRegistry {

    private static final int MAX_ENTRIES = 10_000;

    private final ConcurrentMap<String, ApiEndpoint> endpoints = new ConcurrentHashMap<>();

    /** Records that {@code method host path} was observed. No-op when full. */
    public void record(String host, String path, String method) {
        if (host == null || path == null || method == null) return;
        if (endpoints.size() >= MAX_ENTRIES && !endpoints.containsKey(key(host, path))) return;
        endpoints
                .computeIfAbsent(key(host, path), k -> new ApiEndpoint(host, path))
                .addMethod(method);
    }

    public Collection<ApiEndpoint> snapshot() {
        return Collections.unmodifiableCollection(endpoints.values());
    }

    public int size() {
        return endpoints.size();
    }

    /** Called from the unloading handler. */
    public void clear() {
        endpoints.clear();
    }

    private static String key(String host, String path) {
        return host + "|" + path;
    }

    /** Aggregated view of one path on one host: which methods have we seen? */
    public static final class ApiEndpoint {
        private final String host;
        private final String path;
        private final Set<String> methods = ConcurrentHashMap.newKeySet();

        ApiEndpoint(String host, String path) {
            this.host = host;
            this.path = path;
        }

        void addMethod(String method) { methods.add(method); }

        public String host() { return host; }
        public String path() { return path; }
        public Set<String> methods() { return Collections.unmodifiableSet(methods); }
    }
}
