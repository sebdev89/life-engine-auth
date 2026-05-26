package com.devito.lifeengine;

import com.devito.lifeengine.boot.LifeengineApplicationEnvironmentPreparedListener;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Standalone Life Engine identity / RBAC / session / security control plane.
 *
 * <p>Phase-1 extraction of {@code modules/auth} from the life-engine modulith plus the auth-related
 * glue that lived in {@code apps/core-app} (SecurityConfig, JwtReactiveAuthenticationWebFilter,
 * boot validators, logging masking, request correlation filter, ApiErrorEnvelope). Package names
 * are unchanged; the only purpose of this class is to act as the deployable replacement for
 * {@code com.devito.lifeengine.LifeEngineApplication}.
 *
 * <p>Component scan is intentionally narrow ({@code com.devito.lifeengine}) — agent-runtime,
 * dev-agent, crypto, and all other modulith verticals are not on the classpath and never will be
 * for this service. CryptoBot and Dev Agent stay in the original repo until their own phases.
 *
 * <p>{@code @EnableR2dbcRepositories} is intentionally NOT declared here — the auth module already
 * provides it via {@code AuthSecurityBeansConfiguration} on the same base package; redeclaring it
 * triggers a {@code BeanDefinitionOverrideException}.
 */
@SpringBootApplication(scanBasePackages = {"com.devito.lifeengine"})
public class LifeEngineAuthApplication {

    public static void main(String[] args) {
        SpringApplication app = new SpringApplication(LifeEngineAuthApplication.class);
        app.addListeners(new LifeengineApplicationEnvironmentPreparedListener());
        app.run(args);
    }
}
