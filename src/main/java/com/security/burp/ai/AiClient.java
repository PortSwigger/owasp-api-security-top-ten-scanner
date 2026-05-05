package com.security.burp.ai;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ai.chat.Message;
import burp.api.montoya.ai.chat.PromptOptions;
import burp.api.montoya.ai.chat.PromptResponse;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Thin wrapper around {@code api.ai()}.
 *
 * <p>Three responsibilities:
 * <ul>
 *   <li><b>Threading.</b> Calls run on a dedicated executor with a hard
 *       timeout, so a slow or stuck prompt never blocks a scan thread
 *       indefinitely (PortSwigger BApp criterion #5).</li>
 *   <li><b>Caching.</b> Identical prompts (same system + user message) are
 *       deduplicated to keep credit consumption bounded.</li>
 *   <li><b>Failure tolerance.</b> Any exception, timeout, or unavailability
 *       returns {@code null}. AI failures must never break a scan.</li>
 * </ul>
 *
 * <p>Lifecycle: created in {@code BurpExtender.initialize()}, shut down by
 * the registered unloading handler.
 */
public final class AiClient {

    private static final int CACHE_LIMIT = 1024;
    private static final long DEFAULT_TIMEOUT_SECONDS = 10;
    private static final double DETERMINISTIC_TEMPERATURE = 0.0;

    private final MontoyaApi api;
    private final ExecutorService executor;
    private final ConcurrentMap<String, String> cache;
    private final boolean killSwitch;

    public AiClient(MontoyaApi api) {
        this.api = api;
        this.executor = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "burp-api-scanner-ai");
            thread.setDaemon(true);
            return thread;
        });
        this.cache = new ConcurrentHashMap<>();
        this.killSwitch = Boolean.getBoolean("com.security.burp.ai.disabled");
    }

    /** True iff the extension is allowed to use AI and Burp says it's available. */
    public boolean isAvailable() {
        if (killSwitch) return false;
        try {
            return api.ai().isEnabled();
        } catch (Throwable t) {
            return false;
        }
    }

    /**
     * Send a system + user prompt with deterministic temperature.
     * Returns the model's content, or {@code null} on any failure or timeout.
     */
    public String ask(String system, String user) {
        if (!isAvailable()) return null;
        String cacheKey = system + "" + user;
        String cached = cache.get(cacheKey);
        if (cached != null) return cached;

        Future<String> future = executor.submit(() -> sendPrompt(system, user));
        try {
            String content = future.get(DEFAULT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            if (content != null) cache(cacheKey, content);
            return content;
        } catch (TimeoutException e) {
            future.cancel(true);
            api.logging().logToError("[AI] Prompt timed out after " + DEFAULT_TIMEOUT_SECONDS + "s");
            return null;
        } catch (Throwable t) {
            logFailure(t);
            return null;
        }
    }

    /** Stops the executor. Safe to call multiple times. */
    public void shutdown() {
        executor.shutdown();
        try {
            if (!executor.awaitTermination(2, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
        cache.clear();
    }

    private String sendPrompt(String system, String user) {
        PromptOptions opts = PromptOptions.promptOptions().withTemperature(DETERMINISTIC_TEMPERATURE);
        PromptResponse response = api.ai().prompt().execute(opts,
                Message.systemMessage(system),
                Message.userMessage(user));
        return response == null ? null : trimToNull(response.content());
    }

    private void cache(String key, String value) {
        if (cache.size() < CACHE_LIMIT) cache.put(key, value);
    }

    private static String trimToNull(String s) {
        if (s == null) return null;
        String trimmed = s.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private void logFailure(Throwable t) {
        StringWriter trace = new StringWriter();
        t.printStackTrace(new PrintWriter(trace));
        api.logging().logToError("[AI] Prompt failed:\n" + trace);
    }
}
