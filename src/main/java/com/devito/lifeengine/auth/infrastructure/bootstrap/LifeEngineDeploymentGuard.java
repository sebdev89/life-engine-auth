package com.devito.lifeengine.auth.infrastructure.bootstrap;

import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;

/** Shared guard: treat {@code prod} profile or {@code lifeengine.deployment.env=prod} as production. */
public final class LifeEngineDeploymentGuard {

    private LifeEngineDeploymentGuard() {}

    public static boolean isProduction(Environment environment) {
        if (environment.acceptsProfiles(Profiles.of("prod"))) {
            return true;
        }
        String app = environment.getProperty("lifeengine.deployment.env", "").trim().toLowerCase();
        return "prod".equals(app);
    }
}
