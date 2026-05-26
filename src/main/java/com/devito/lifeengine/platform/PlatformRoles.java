package com.devito.lifeengine.platform;

import java.util.Locale;

/** Canonical Spring Security–style role names for the Life Engine control plane. */
public final class PlatformRoles {

    public static final String ROLE_ADMIN = "ROLE_ADMIN";
    /** Application role USER → Spring authority for JWT / SecurityContext. */
    public static final String ROLE_USER = "ROLE_USER";
    /** Limited exploration role (JWT guest sessions). */
    public static final String ROLE_GUEST = "ROLE_GUEST";
    public static final String ROLE_BO_ADMIN = "ROLE_BO_ADMIN";
    public static final String ROLE_OPERATOR = "ROLE_OPERATOR";
    public static final String ROLE_VIEWER = "ROLE_VIEWER";

    private PlatformRoles() {}

    /**
     * Maps persisted app role to the single Spring authority placed on the JWT. Non-admin app roles
     * ({@code USER}, {@code BO_ADMIN}, {@code OPERATOR}, {@code VIEWER}) resolve to {@link #ROLE_USER} so
     * existing {@code hasAnyAuthority(ROLE_ADMIN, ROLE_USER)} route rules keep working; fine-grained semantics come
     * from RBAC permission codes on the JWT — primary app role code is derived in auth from {@code bo_user_role} /
     * {@code auth_role}.
     */
    public static String toAuthority(String appRole) {
        if (appRole == null || appRole.isBlank()) {
            return ROLE_USER;
        }
        String r = appRole.trim().toUpperCase(Locale.ROOT);
        if ("ADMIN".equals(r)) {
            return ROLE_ADMIN;
        }
        if ("GUEST".equals(r)) {
            return ROLE_GUEST;
        }
        return ROLE_USER;
    }
}
