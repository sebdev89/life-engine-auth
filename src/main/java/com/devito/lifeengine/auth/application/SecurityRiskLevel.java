package com.devito.lifeengine.auth.application;

/** Discrete risk labels for Security Control Plane sessions and users. */
public final class SecurityRiskLevel {

    public static final String SAFE = "SAFE";
    public static final String UNUSUAL = "UNUSUAL";
    public static final String SUSPICIOUS = "SUSPICIOUS";

    public static final String SIGNAL_NEW_IP = "NEW_IP";
    public static final String SIGNAL_NEW_USER_AGENT = "NEW_USER_AGENT";
    public static final String SIGNAL_MULTIPLE_SESSIONS = "MULTIPLE_ACTIVE_SESSIONS";
    public static final String SIGNAL_FAILED_LOGINS = "REPEATED_FAILED_LOGINS";

    private SecurityRiskLevel() {}
}
