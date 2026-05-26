package com.devito.lifeengine.auth.infrastructure.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "lifeengine.security.jwt")
public class JwtSecurityProperties {

    /** HMAC secret (min 256 bits for HS256). Set via profile YAML / {@code JWT_SECRET}. */
    private String secret = "";

    private int accessTokenValidityMinutes = 15;

    /** Refresh token TTL (rotating opaque token, stored hashed). */
    private int refreshTokenValidityDays = 7;

    /**
     * When true, API requests with a JWT that carries {@code sid} must match a non-revoked {@code user_sessions} row
     * (or legacy refresh chain) — revoked refresh / logout-all take effect before access expiry.
     */
    private boolean requireActiveUserSession = true;

    /**
     * Max concurrent BO user sessions ({@code user_sessions} rows with {@code revoked_at IS NULL}). {@code 0} =
     * unlimited. Enforced before issuing a new session on password / OAuth login.
     */
    private int maxActiveBoUserSessions = 0;

    /** When true, mismatches between stored session IP/UA and current request are written to {@code auth_audit_log}. */
    private boolean sessionClientHintAuditEnabled = true;

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public int getAccessTokenValidityMinutes() {
        return accessTokenValidityMinutes;
    }

    public void setAccessTokenValidityMinutes(int accessTokenValidityMinutes) {
        this.accessTokenValidityMinutes = accessTokenValidityMinutes;
    }

    public int getRefreshTokenValidityDays() {
        return refreshTokenValidityDays;
    }

    public void setRefreshTokenValidityDays(int refreshTokenValidityDays) {
        this.refreshTokenValidityDays = refreshTokenValidityDays;
    }

    public boolean isRequireActiveUserSession() {
        return requireActiveUserSession;
    }

    public void setRequireActiveUserSession(boolean requireActiveUserSession) {
        this.requireActiveUserSession = requireActiveUserSession;
    }

    public int getMaxActiveBoUserSessions() {
        return maxActiveBoUserSessions;
    }

    public void setMaxActiveBoUserSessions(int maxActiveBoUserSessions) {
        this.maxActiveBoUserSessions = maxActiveBoUserSessions;
    }

    public boolean isSessionClientHintAuditEnabled() {
        return sessionClientHintAuditEnabled;
    }

    public void setSessionClientHintAuditEnabled(boolean sessionClientHintAuditEnabled) {
        this.sessionClientHintAuditEnabled = sessionClientHintAuditEnabled;
    }
}
