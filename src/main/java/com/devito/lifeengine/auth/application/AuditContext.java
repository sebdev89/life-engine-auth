package com.devito.lifeengine.auth.application;

import org.springframework.web.server.ServerWebExchange;

/** Request metadata for security audit rows (IP / User-Agent). */
public record AuditContext(String ip, String userAgent) {

    public static AuditContext from(ServerWebExchange exchange) {
        var req = exchange.getRequest();
        String ip = null;
        if (req.getRemoteAddress() != null && req.getRemoteAddress().getAddress() != null) {
            ip = req.getRemoteAddress().getAddress().getHostAddress();
        }
        String ua = req.getHeaders().getFirst("User-Agent");
        return new AuditContext(ip, ua);
    }

    public static AuditContext empty() {
        return new AuditContext(null, null);
    }
}
