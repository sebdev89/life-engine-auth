package com.devito.lifeengine.auth.infrastructure.conditions;

import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.ConfigurationCondition;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.core.type.AnnotatedTypeMetadata;

/**
 * Matches when auth dev tooling (seed helpers, reset-password) may run: {@code lifeengine.deployment.env} is
 * {@code local} or {@code test}, or Spring profiles {@code local}/{@code test} are active — and the process is not
 * production ({@code prod} profile / {@code lifeengine.deployment.env=prod}).
 */
public final class LocalTestOnlyAuthToolingCondition implements ConfigurationCondition {

    @Override
    public ConfigurationPhase getConfigurationPhase() {
        return ConfigurationPhase.REGISTER_BEAN;
    }

    @Override
    public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
        Environment env = context.getEnvironment();
        if (env.acceptsProfiles(Profiles.of("prod"))) {
            return false;
        }
        String app = env.getProperty("lifeengine.deployment.env", "").trim().toLowerCase();
        if ("prod".equals(app)) {
            return false;
        }
        if ("local".equals(app) || "test".equals(app)) {
            return true;
        }
        return env.acceptsProfiles(Profiles.of("local", "test"));
    }
}
