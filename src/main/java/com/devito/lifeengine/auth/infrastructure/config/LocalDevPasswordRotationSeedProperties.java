package com.devito.lifeengine.auth.infrastructure.config;

import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Dedicated BO user for destructive password-change E2E — never enable in production YAML. Same semantics as
 * {@link LocalDevOperatorSeedProperties} but for {@code e2e-password-rotation@life-engine.local}.
 */
@ConfigurationProperties(prefix = "lifeengine.security.local-dev-password-rotation-seed")
public class LocalDevPasswordRotationSeedProperties {

    private boolean enabled = false;
    private String email = "e2e-password-rotation@life-engine.local";
    private String password = "";
    private boolean syncPassword = true;
    private List<String> roles = new ArrayList<>(List.of("USER"));

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public boolean isSyncPassword() {
        return syncPassword;
    }

    public void setSyncPassword(boolean syncPassword) {
        this.syncPassword = syncPassword;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles == null ? new ArrayList<>() : new ArrayList<>(roles);
    }
}
