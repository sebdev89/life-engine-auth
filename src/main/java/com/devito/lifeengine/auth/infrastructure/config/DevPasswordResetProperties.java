package com.devito.lifeengine.auth.infrastructure.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Non-production password reset by email — for local/CI recovery without email delivery. Disabled by default; never
 * enable in production YAML.
 */
@ConfigurationProperties(prefix = "lifeengine.security.dev-password-reset")
public class DevPasswordResetProperties {

    private boolean enabled = false;

    /**
     * Shared secret required on every request as header {@code X-Life-Engine-Dev-Password-Reset-Key}. When blank, the
     * endpoint refuses all calls even if {@link #enabled} is true.
     */
    private String apiKey = "";

    /** When true, skips {@link com.devito.lifeengine.auth.application.PasswordPolicy} (length bounds still enforced). */
    private boolean relaxPasswordPolicy = true;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getApiKey() {
        return apiKey;
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey == null ? "" : apiKey;
    }

    public boolean isRelaxPasswordPolicy() {
        return relaxPasswordPolicy;
    }

    public void setRelaxPasswordPolicy(boolean relaxPasswordPolicy) {
        this.relaxPasswordPolicy = relaxPasswordPolicy;
    }
}
