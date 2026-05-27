package com.devito.lifeengine.config;

import com.devito.lifeengine.auth.application.AuditContext;
import jakarta.annotation.PostConstruct;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

/**
 * Pushes the {@code lifeengine.http.trusted-proxies} comma-separated allow-list into {@link AuditContext}
 * during startup. Empty (default) means forwarded headers are ignored entirely and {@link AuditContext}
 * uses {@code getRemoteAddress()} only — see {@link AuditContext#configureTrustedProxies(Set)}.
 *
 * <p>Operators behind a reverse proxy / load balancer that rewrites {@code X-Forwarded-For} should set
 * the env var {@code LIFEENGINE_HTTP_TRUSTED_PROXIES} to the literal peer IPs of the proxy hop(s).
 */
@Configuration
public class AuditTrustedProxyConfig {

    private final String rawTrustedProxies;

    public AuditTrustedProxyConfig(
            @Value("${lifeengine.http.trusted-proxies:}") String rawTrustedProxies) {
        this.rawTrustedProxies = rawTrustedProxies;
    }

    @PostConstruct
    void publishTrustedProxies() {
        if (rawTrustedProxies == null || rawTrustedProxies.isBlank()) {
            AuditContext.configureTrustedProxies(Set.of());
            return;
        }
        Set<String> ips = new LinkedHashSet<>();
        Arrays.stream(rawTrustedProxies.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .forEach(ips::add);
        AuditContext.configureTrustedProxies(ips);
    }
}
