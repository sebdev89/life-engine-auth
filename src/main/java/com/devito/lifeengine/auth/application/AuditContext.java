package com.devito.lifeengine.auth.application;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.server.ServerWebExchange;

/**
 * Request metadata for security audit rows (IP / User-Agent).
 *
 * <p><b>IP resolution:</b>
 *
 * <ul>
 *   <li>Default (no trusted-proxy mechanism configured): use {@link ServerHttpRequest#getRemoteAddress()}
 *       and ignore {@code Forwarded} / {@code X-Forwarded-For}. We do <i>not</i> trust headers from arbitrary
 *       clients — anyone can spoof them.</li>
 *   <li>When the operator configures a trusted-proxy allow-list via
 *       {@link #configureTrustedProxies(Set)} (typically wired from a {@code @Configuration} bean reading
 *       {@code lifeengine.http.trusted-proxies}), and the immediate peer's IP matches the allow-list, the
 *       leftmost client IP from RFC 7239 {@code Forwarded: for=} or de-facto {@code X-Forwarded-For} is
 *       used instead. Falls back to {@code getRemoteAddress()} if neither header is present.</li>
 * </ul>
 *
 * <p>This keeps audit rows accurate behind a load balancer that strips/sets {@code X-Forwarded-For}, without
 * blindly trusting forwarded headers in deployments that have no such proxy.
 */
public record AuditContext(String ip, String userAgent) {

    private static volatile Set<String> trustedProxyIps = Collections.emptySet();

    /**
     * Replace the trusted-proxy allow-list. Wired by a {@code @Configuration} bean during startup from
     * {@code lifeengine.http.trusted-proxies} (comma-separated literal IP addresses). Empty set (the
     * default) disables forwarded-header trust entirely.
     */
    public static void configureTrustedProxies(Set<String> trustedIps) {
        if (trustedIps == null || trustedIps.isEmpty()) {
            trustedProxyIps = Collections.emptySet();
            return;
        }
        trustedProxyIps = Set.copyOf(trustedIps);
    }

    public static AuditContext from(ServerWebExchange exchange) {
        ServerHttpRequest req = exchange.getRequest();
        String remoteIp = directRemoteIp(req);
        String ua = req.getHeaders().getFirst("User-Agent");
        String clientIp = resolveClientIp(req, remoteIp);
        return new AuditContext(clientIp, ua);
    }

    public static AuditContext empty() {
        return new AuditContext(null, null);
    }

    private static String directRemoteIp(ServerHttpRequest req) {
        if (req.getRemoteAddress() == null || req.getRemoteAddress().getAddress() == null) {
            return null;
        }
        return req.getRemoteAddress().getAddress().getHostAddress();
    }

    private static String resolveClientIp(ServerHttpRequest req, String remoteIp) {
        if (remoteIp == null || trustedProxyIps.isEmpty() || !trustedProxyIps.contains(remoteIp)) {
            return remoteIp;
        }
        String forwarded = leftmostFromForwardedHeader(req.getHeaders().getFirst("Forwarded"));
        if (forwarded != null) {
            return forwarded;
        }
        String xff = leftmostFromCsv(req.getHeaders().getFirst("X-Forwarded-For"));
        if (xff != null) {
            return xff;
        }
        return remoteIp;
    }

    /**
     * Parse {@code Forwarded: for=…[, …]} (RFC 7239). Returns the leftmost {@code for=} value with any
     * surrounding quotes / port stripped. Conservative: ignores tokens with unparseable shape.
     */
    private static String leftmostFromForwardedHeader(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String firstHop = value.split(",", 2)[0];
        for (String token : firstHop.split(";")) {
            String t = token.trim();
            if (t.regionMatches(true, 0, "for=", 0, 4) && t.length() > 4) {
                String forValue = t.substring(4).trim();
                if (forValue.startsWith("\"") && forValue.endsWith("\"") && forValue.length() >= 2) {
                    forValue = forValue.substring(1, forValue.length() - 1);
                }
                return stripPort(forValue);
            }
        }
        return null;
    }

    private static String leftmostFromCsv(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String first = value.split(",", 2)[0].trim();
        return first.isEmpty() ? null : stripPort(first);
    }

    private static String stripPort(String ipMaybeWithPort) {
        if (ipMaybeWithPort == null || ipMaybeWithPort.isEmpty()) {
            return ipMaybeWithPort;
        }
        if (ipMaybeWithPort.startsWith("[")) {
            int close = ipMaybeWithPort.indexOf(']');
            if (close > 0) {
                return ipMaybeWithPort.substring(1, close);
            }
            return ipMaybeWithPort;
        }
        int colon = ipMaybeWithPort.indexOf(':');
        if (colon > 0 && ipMaybeWithPort.indexOf(':', colon + 1) < 0) {
            return ipMaybeWithPort.substring(0, colon);
        }
        return ipMaybeWithPort;
    }

    /** Convenience for tests / config — copy the current allow-list. */
    static Set<String> currentTrustedProxies() {
        return new LinkedHashSet<>(trustedProxyIps);
    }
}
