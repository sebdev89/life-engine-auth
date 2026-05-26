package com.devito.lifeengine.auth.infrastructure.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "lifeengine.security.guest")
public class GuestAuthProperties {

    /**
     * When false, {@code POST /api/auth/guest} is denied at the edge and returns 404 from the controller.
     * Bind via {@code GUEST_AUTH_ENABLED}.
     */
    private boolean enabled = false;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}
