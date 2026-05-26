package com.devito.lifeengine.auth.infrastructure.config;

import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Idempotent BO operator for local/dev and Playwright — never enable in production YAML.
 *
 * <p>When {@code enabled=true}, upserts {@link #email} with {@link #password} (hashed) and assigns RBAC roles from
 * {@link #roles} (default {@code USER}). If {@link #syncPassword} is true, the password hash is refreshed on every
 * startup so local credentials stay deterministic.
 */
@ConfigurationProperties(prefix = "lifeengine.security.local-dev-operator-seed")
public class LocalDevOperatorSeedProperties {

    /** Master switch — default {@code false} in {@code application.yml}. */
    private boolean enabled = false;

    /** Fixed operator email (normalized to lower case). */
    private String email = "e2e@life-engine.local";

    /**
     * BCrypt source password — use {@code LOCAL_DEV_E2E_PASSWORD} in env for overrides. When blank and enabled,
     * startup skips seeding and logs a warning (fail-safe).
     */
    private String password = "";

    /** When true, existing users matching {@link #email} get an updated password hash on each run. */
    private boolean syncPassword = true;

    /**
     * Application role codes (e.g. {@code USER}, {@code ADMIN}) — inserted into {@code bo_user_role} idempotently.
     * When empty, the runner defaults to {@code USER}.
     */
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
