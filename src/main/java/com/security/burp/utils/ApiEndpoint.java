package com.security.burp.utils;

import java.util.HashSet;
import java.util.Set;

public class ApiEndpoint {
    private final String path;
    private final String host;
    private final Set<String> methods;
    private int requestCount;

    public ApiEndpoint(String path, String host) {
        this.path = path;
        this.host = host;
        this.methods = new HashSet<>();
        this.requestCount = 0;
    }

    public void addMethod(String method) {
        methods.add(method);
        requestCount++;
    }

    public String getPath() {
        return path;
    }

    public String getHost() {
        return host;
    }

    public Set<String> getMethods() {
        return new HashSet<>(methods);
    }

    public int getRequestCount() {
        return requestCount;
    }

    @Override
    public String toString() {
        return host + path + " [" + String.join(", ", methods) + "] (" + requestCount + " requests)";
    }
}
