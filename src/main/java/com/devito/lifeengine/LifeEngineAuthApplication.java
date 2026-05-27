package com.devito.lifeengine;

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
 * for this service.
 *
 * <p>{@code @EnableR2dbcRepositories} is intentionally NOT declared here — the auth module already
 * provides it via {@code AuthSecurityBeansConfiguration} on the same base package; redeclaring it
 * triggers a {@code BeanDefinitionOverrideException}.
 *
 * <p>{@code com.devito.lifeengine.boot.LifeengineApplicationEnvironmentPreparedListener} is wired
 * once via {@code META-INF/spring/org.springframework.context.ApplicationListener} (Spring Boot 3.x
 * factory) — do NOT also call {@link SpringApplication#addListeners(org.springframework.context.ApplicationListener[])}
 * here or the listener will fire twice.
 */
@SpringBootApplication(scanBasePackages = {"com.devito.lifeengine"})
public class LifeEngineAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(LifeEngineAuthApplication.class, args);
    }
}
