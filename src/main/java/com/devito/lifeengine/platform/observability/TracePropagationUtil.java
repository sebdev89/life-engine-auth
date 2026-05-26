package com.devito.lifeengine.platform.observability;

import java.util.List;

/**
 * Resolves a stable correlation trace id from W3C {@code traceparent} or {@code X-Trace-Id}. Does not allocate a
 * synthetic id when absent — callers store an empty string and omit from logs/payloads if desired.
 */
public final class TracePropagationUtil {

    private TracePropagationUtil() {}

    /**
     * @param traceparent W3C header value, e.g. {@code 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01}
     * @param xTraceId optional explicit trace id (32+ hex typical)
     */
    public static String resolveTraceId(List<String> traceparent, List<String> xTraceId) {
        if (xTraceId != null && !xTraceId.isEmpty()) {
            String x = xTraceId.getFirst();
            if (x != null && !x.isBlank()) {
                return x.trim();
            }
        }
        if (traceparent == null || traceparent.isEmpty()) {
            return "";
        }
        String tp = traceparent.getFirst();
        if (tp == null || tp.isBlank()) {
            return "";
        }
        String[] parts = tp.split("-", 4);
        if (parts.length >= 2) {
            String tid = parts[1].trim();
            if (tid.length() == 32 && tid.chars().allMatch(TracePropagationUtil::isHex)) {
                return tid.toLowerCase();
            }
        }
        return "";
    }

    private static boolean isHex(int c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }
}
