package com.devito.lifeengine.auth.infrastructure.config;

import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Optional deterministic admin BO user for local/dev — never enable in production YAML.
 */
@ConfigurationProperties(prefix = "lifeengine.security.admin-seed")
public class AdminSeedProperties {

    private boolean enabled = false;
    private String email = "admin@life-engine.local";
    private String password = "";
    /**
     * When {@code true}, only non-blank + max length are checked (not {@link com.devito.lifeengine.auth.application.PasswordPolicy}).
     * Use for local default passwords like {@code admin}. Must be {@code false} in non-local YAML.
     */
    private boolean relaxPasswordPolicy = false;
    private List<String> roles = new ArrayList<>(List.of("ADMIN"));

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

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles == null ? new ArrayList<>() : new ArrayList<>(roles);
    }

    public boolean isRelaxPasswordPolicy() {
        return relaxPasswordPolicy;
    }

    public void setRelaxPasswordPolicy(boolean relaxPasswordPolicy) {
        this.relaxPasswordPolicy = relaxPasswordPolicy;
    }
}
