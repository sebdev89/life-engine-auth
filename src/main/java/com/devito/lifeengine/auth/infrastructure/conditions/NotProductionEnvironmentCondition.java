package com.devito.lifeengine.auth.infrastructure.conditions;

import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.ConfigurationCondition;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.core.type.AnnotatedTypeMetadata;

/**
 * Matches when this process is not production: {@code lifeengine.deployment.env} is not {@code prod} and the
 * {@code prod} Spring profile is not active.
 */
public final class NotProductionEnvironmentCondition implements ConfigurationCondition {

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
        return !"prod".equals(app);
    }
}
