package com.devito.lifeengine.auth.application;

/** Stored in security_audit_event.event_type. */
public final class SecurityAuditEventType {

    public static final String LOGIN_SUCCESS = "LOGIN_SUCCESS";
    /** Successful BO sign-in via Google OAuth (distinct from password {@code LOGIN_SUCCESS}). */
    public static final String GOOGLE_LOGIN_SUCCESS = "GOOGLE_LOGIN_SUCCESS";
    public static final String LOGIN_FAILURE = "LOGIN_FAILURE";
    /** Google OAuth sign-in failed before session issuance (state, token, userinfo, policy). */
    public static final String GOOGLE_LOGIN_FAILURE = "GOOGLE_LOGIN_FAILURE";
    /** Too many failed password attempts — {@code locked_until} set (auto lockout). */
    public static final String LOGIN_TEMP_LOCKOUT = "LOGIN_TEMP_LOCKOUT";
    public static final String REFRESH_SUCCESS = "REFRESH_SUCCESS";
    public static final String REFRESH_FAILURE = "REFRESH_FAILURE";
    public static final String LOGOUT = "LOGOUT";
    /** Self-service: current refresh token invalidated (client called {@code POST /api/auth/revoke}). */
    public static final String TOKEN_REVOKED = "TOKEN_REVOKED";
    /** Self-service: other refresh rows for the same BO user revoked (kept current session). */
    public static final String OTHER_SESSIONS_REVOKED = "OTHER_SESSIONS_REVOKED";
    public static final String GUEST_SESSION_CREATED = "GUEST_SESSION_CREATED";

    /** Control-plane: account disabled (subject = affected BO user). */
    public static final String ADMIN_USER_DISABLED = "ADMIN_USER_DISABLED";
    /** Control-plane: account re-enabled. */
    public static final String ADMIN_USER_ENABLED = "ADMIN_USER_ENABLED";
    /** Control-plane: all refresh rows for a session revoked. */
    public static final String ADMIN_SESSION_KILLED = "ADMIN_SESSION_KILLED";
    /** Control-plane: single refresh row revoked. */
    public static final String ADMIN_TOKEN_REVOKED = "ADMIN_TOKEN_REVOKED";
    /** Control-plane: all sessions for a user revoked. */
    public static final String ADMIN_USER_SESSIONS_REVOKED = "ADMIN_USER_SESSIONS_REVOKED";
    /** Control-plane: BO user primary role changed ({@code bo_user_role} / {@code auth_role}). */
    public static final String ADMIN_USER_ROLE_CHANGED = "ADMIN_USER_ROLE_CHANGED";
    /** Control-plane: admin created a new BO operator ({@code bo_user} + initial {@code bo_user_role}). */
    public static final String ADMIN_USER_CREATED = "ADMIN_USER_CREATED";

    /** Control-plane: security lock applied — user cannot sign in; refresh rows may be bulk-revoked. */
    public static final String ADMIN_USER_LOCKED = "ADMIN_USER_LOCKED";
    /** Control-plane: security lock cleared. */
    public static final String ADMIN_USER_UNLOCKED = "ADMIN_USER_UNLOCKED";
    /** Control-plane: password material cleared + sessions revoked — user must re-provision password or IdP. */
    public static final String ADMIN_PASSWORD_RESET_FORCED = "ADMIN_PASSWORD_RESET_FORCED";

    public static final String USER_PASSWORD_CHANGED = "USER_PASSWORD_CHANGED";
    public static final String PASSWORD_RESET_REQUESTED = "PASSWORD_RESET_REQUESTED";
    public static final String PASSWORD_RESET_COMPLETED = "PASSWORD_RESET_COMPLETED";
    /** Non-production: {@code POST /api/dev-auth/reset-password} applied a new hash and revoked refresh rows. */
    public static final String DEV_PASSWORD_RESET_APPLIED = "DEV_PASSWORD_RESET_APPLIED";
    public static final String USER_SESSION_REVOKED_SELF = "USER_SESSION_REVOKED_SELF";
    public static final String USER_SESSIONS_REVOKED_ALL_SELF = "USER_SESSIONS_REVOKED_ALL_SELF";

    /** Self-service: Google IdP row attached to the BO user. */
    public static final String GOOGLE_ACCOUNT_LINKED = "GOOGLE_ACCOUNT_LINKED";
    /** Self-service: Google IdP row removed (local password must remain). */
    public static final String GOOGLE_ACCOUNT_UNLINKED = "GOOGLE_ACCOUNT_UNLINKED";
    /** Google account linking callback failed (email mismatch, sub already bound elsewhere, etc.). */
    public static final String GOOGLE_LINK_FAILURE = "GOOGLE_LINK_FAILURE";

    public static final String RBAC_ROLE_CREATED = "RBAC_ROLE_CREATED";
    public static final String RBAC_ROLE_UPDATED = "RBAC_ROLE_UPDATED";
    public static final String RBAC_USER_ROLE_ASSIGNED = "RBAC_USER_ROLE_ASSIGNED";
    public static final String RBAC_USER_ROLE_REMOVED = "RBAC_USER_ROLE_REMOVED";

    private SecurityAuditEventType() {}
}
