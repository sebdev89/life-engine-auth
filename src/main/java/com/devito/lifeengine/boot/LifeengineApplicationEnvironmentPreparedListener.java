package com.devito.lifeengine.boot;

import java.util.Locale;
import java.util.Properties;
import java.util.Set;
import org.springframework.boot.context.event.ApplicationEnvironmentPreparedEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.PropertiesPropertySource;

/**
 * Resolves {@code lifeengine.deployment.env} before Spring loads {@code application.yml} and validates
 * environment-specific invariants (e.g. DB passwords for {@code dev} / {@code prod}).
 *
 * <p><b>Phase-1 extraction note (life-engine-auth):</b> the original modulith version forced callers to
 * export {@code LIFEENGINE_DEPLOYMENT_ENV} because the listener runs at
 * {@link ApplicationEnvironmentPreparedEvent} with {@link Ordered#HIGHEST_PRECEDENCE}, which fires
 * <i>before</i> {@code application.yml} resolves {@code ${APP_ENV:local}}. That made local IntelliJ
 * launches fail with "APP_ENV is required" even when {@code APP_ENV=local} was exported. This version
 * widens the resolution to mirror the YAML default chain:
 *
 * <ol>
 *   <li>{@code lifeengine.deployment.env} (env {@code LIFEENGINE_DEPLOYMENT_ENV} / JVM {@code -D…}).</li>
 *   <li>{@code APP_ENV} environment variable / system property.</li>
 *   <li>Active Spring profile fallback — only for the SAFE values {@code local} or {@code test}.
 *       {@code dev} / {@code prod} must always be set explicitly; profile-only activation never escalates
 *       a runtime into prod-equivalent mode.</li>
 *   <li>Conservative default {@code local} (matches the YAML {@code ${APP_ENV:local}} default).</li>
 * </ol>
 *
 * <p>Once a value is resolved, it is published as a high-priority {@link PropertiesPropertySource}
 * so the rest of the application (CorsConfig, SecurityConfig, SafeApiErrorWebExceptionHandler) sees
 * the same value via {@code environment.getProperty("lifeengine.deployment.env")} regardless of which
 * input variable the operator actually exported.
 *
 * <p>Production safety is unchanged: when the resolved value is {@code dev} or {@code prod}, both
 * {@code spring.datasource.password} and {@code spring.flyway.password} are still required to be
 * non-blank, and the {@link ProductionAuthSecurityStartupValidator} still runs.
 */
@Order(Ordered.HIGHEST_PRECEDENCE)
public class LifeengineApplicationEnvironmentPreparedListener
        implements ApplicationListener<ApplicationEnvironmentPreparedEvent>, Ordered {

    static final Set<String> ALLOWED = Set.of("local", "dev", "prod", "test");

    /** PropertySource name for the resolved value — also referenced by tests. */
    static final String RESOLVED_PROPERTY_SOURCE = "lifeengineDeploymentEnvResolved";

    @Override
    public void onApplicationEvent(ApplicationEnvironmentPreparedEvent event) {
        ConfigurableEnvironment environment = event.getEnvironment();
        if (isTestProfile(environment)) {
            ensureResolvedProperty(environment, "test");
            return;
        }
        String appEnv = resolveAppEnv(environment);
        if (!ALLOWED.contains(appEnv)) {
            throw new IllegalStateException(
                    "lifeengine.deployment.env must be one of local, dev, prod, test (was: '" + appEnv + "').");
        }
        ensureResolvedProperty(environment, appEnv);
        if ("dev".equals(appEnv) || "prod".equals(appEnv)) {
            String ds = environment.getProperty("spring.datasource.password", "");
            if (ds == null || ds.isBlank()) {
                throw new IllegalStateException(
                        "spring.datasource.password is required when APP_ENV is dev or prod (set SPRING_DATASOURCE_PASSWORD).");
            }
            String fly = environment.getProperty("spring.flyway.password", "");
            if (fly == null || fly.isBlank()) {
                throw new IllegalStateException(
                        "spring.flyway.password is required when APP_ENV is dev or prod (set SPRING_FLYWAY_PASSWORD).");
            }
        }
    }

    /**
     * Resolution chain mirroring the YAML default {@code ${APP_ENV:local}}. {@code dev} / {@code prod}
     * are never inferred from a Spring profile alone — they must come from an explicit env var or system
     * property to keep production-equivalent runtimes opt-in.
     */
    static String resolveAppEnv(ConfigurableEnvironment environment) {
        String direct = trimOrEmpty(environment.getProperty("lifeengine.deployment.env"));
        if (!direct.isEmpty()) {
            return direct.toLowerCase(Locale.ROOT);
        }
        String appEnv = trimOrEmpty(environment.getProperty("APP_ENV"));
        if (!appEnv.isEmpty()) {
            return appEnv.toLowerCase(Locale.ROOT);
        }
        if (environment.matchesProfiles("test")) {
            return "test";
        }
        if (environment.matchesProfiles("local")) {
            return "local";
        }
        return "local";
    }

    private static String trimOrEmpty(String s) {
        return s == null ? "" : s.trim();
    }

    /** Publishes the resolved value as a high-priority PropertySource (idempotent). */
    private static void ensureResolvedProperty(ConfigurableEnvironment environment, String appEnv) {
        if (environment.getPropertySources().contains(RESOLVED_PROPERTY_SOURCE)) {
            return;
        }
        Properties props = new Properties();
        props.setProperty("lifeengine.deployment.env", appEnv);
        environment.getPropertySources().addFirst(new PropertiesPropertySource(RESOLVED_PROPERTY_SOURCE, props));
    }

    /**
     * Test profile uses {@code application-test.yml} defaults; skip strict APP_ENV checks so {@code mvn test} works
     * without shell exports.
     */
    private static boolean isTestProfile(ConfigurableEnvironment environment) {
        if (environment.matchesProfiles("test")) {
            return true;
        }
        String raw = environment.getProperty("spring.profiles.active", "");
        if (raw == null || raw.isBlank()) {
            return false;
        }
        for (String p : raw.split(",")) {
            if ("test".equalsIgnoreCase(p.trim())) {
                return true;
            }
        }
        return false;
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }
}
