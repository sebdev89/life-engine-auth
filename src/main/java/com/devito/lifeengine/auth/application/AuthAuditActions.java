package com.devito.lifeengine.auth.application;

/** {@code auth_audit_log.action} values (v1). */
public final class AuthAuditActions {

    public static final String LOGIN = "LOGIN";
    public static final String FAILED_LOGIN = "FAILED_LOGIN";
    public static final String REFRESH = "REFRESH";
    public static final String LOGOUT = "LOGOUT";
    public static final String LOGOUT_ALL = "LOGOUT_ALL";
    public static final String SESSION_REVOKED = "SESSION_REVOKED";
    public static final String SESSION_CLIENT_HINT = "SESSION_CLIENT_HINT";

    private AuthAuditActions() {}
}
