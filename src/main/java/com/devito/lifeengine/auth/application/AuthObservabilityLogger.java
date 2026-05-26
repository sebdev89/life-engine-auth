package com.devito.lifeengine.auth.application;

import java.util.Locale;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Structured, grep-friendly auth logs: {@code level}, {@code eventType}, {@code userId}, {@code email}, {@code detail}.
 */
public final class AuthObservabilityLogger {

    private static final Logger LOG = LoggerFactory.getLogger("com.devito.lifeengine.auth.events");

    private AuthObservabilityLogger() {}

    public static void info(String eventType, UUID userId, String email, String detail) {
        LOG.info(
                "auth_event level=INFO eventType={} userId={} email={} detail={}",
                eventType,
                userId,
                normalizeEmail(email),
                detail == null ? "" : detail);
    }

    public static void warn(String eventType, UUID userId, String email, String detail) {
        LOG.warn(
                "auth_event level=WARN eventType={} userId={} email={} detail={}",
                eventType,
                userId,
                normalizeEmail(email),
                detail == null ? "" : detail);
    }

    public static void error(String eventType, UUID userId, String email, String detail) {
        LOG.error(
                "auth_event level=ERROR eventType={} userId={} email={} detail={}",
                eventType,
                userId,
                normalizeEmail(email),
                detail == null ? "" : detail);
    }

    private static String normalizeEmail(String s) {
        if (s == null) {
            return "";
        }
        return s.trim().toLowerCase(Locale.ROOT);
    }
}
