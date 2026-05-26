package com.devito.lifeengine.auth.infrastructure.config;

import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Optional self-registration for non-production only. Controller is registered only when {@link #enabled} is
 * {@code true} <em>and</em> {@link com.devito.lifeengine.auth.infrastructure.conditions.NotProductionEnvironmentCondition}
 * matches.
 */
@ConfigurationProperties(prefix = "lifeengine.security.local-dev-registration")
public class LocalDevRegistrationProperties {

    private boolean enabled = false;

    /**
     * Only emails ending with one of these suffixes (case-insensitive) may register, e.g. {@code @life-engine.local}.
     */
    private List<String> allowedEmailDomainSuffixes = new ArrayList<>(List.of("@life-engine.local", "@it.local"));

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public List<String> getAllowedEmailDomainSuffixes() {
        return allowedEmailDomainSuffixes;
    }

    public void setAllowedEmailDomainSuffixes(List<String> allowedEmailDomainSuffixes) {
        this.allowedEmailDomainSuffixes = allowedEmailDomainSuffixes;
    }
}
