package com.devito.lifeengine.boot;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.context.event.ApplicationEnvironmentPreparedEvent;
import org.springframework.boot.DefaultBootstrapContext;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.mock.env.MockEnvironment;

/**
 * Behavioural contract for {@link LifeengineApplicationEnvironmentPreparedListener}: the listener has to
 * resolve {@code lifeengine.deployment.env} <i>before</i> {@code application.yml} loads, mirror the YAML
 * {@code ${APP_ENV:local}} default chain, and keep production-equivalent runtimes opt-in.
 */
class LifeengineApplicationEnvironmentPreparedListenerTest {

    private final LifeengineApplicationEnvironmentPreparedListener listener =
            new LifeengineApplicationEnvironmentPreparedListener();

    @Nested
    @DisplayName("resolveAppEnv() — input chain mirrors application.yml ${APP_ENV:local}")
    class ResolveAppEnv {

        @Test
        @DisplayName("direct lifeengine.deployment.env wins over APP_ENV")
        void directWinsOverAppEnv() {
            MockEnvironment env = new MockEnvironment()
                    .withProperty("lifeengine.deployment.env", "prod")
                    .withProperty("APP_ENV", "local");
            assertThat(LifeengineApplicationEnvironmentPreparedListener.resolveAppEnv(env)).isEqualTo("prod");
        }

        @Test
        @DisplayName("falls back to APP_ENV when lifeengine.deployment.env is blank")
        void fallsBackToAppEnv() {
            MockEnvironment env = new MockEnvironment().withProperty("APP_ENV", "Local");
            assertThat(LifeengineApplicationEnvironmentPreparedListener.resolveAppEnv(env)).isEqualTo("local");
        }

        @Test
        @DisplayName("falls back to active spring profile 'local'")
        void fallsBackToLocalProfile() {
            MockEnvironment env = new MockEnvironment();
            env.setActiveProfiles("local");
            assertThat(LifeengineApplicationEnvironmentPreparedListener.resolveAppEnv(env)).isEqualTo("local");
        }

        @Test
        @DisplayName("falls back to active spring profile 'test'")
        void fallsBackToTestProfile() {
            MockEnvironment env = new MockEnvironment();
            env.setActiveProfiles("test");
            assertThat(LifeengineApplicationEnvironmentPreparedListener.resolveAppEnv(env)).isEqualTo("test");
        }

        @Test
        @DisplayName("nothing set -> 'local' (matches YAML default)")
        void defaultsToLocalWhenNothingSet() {
            MockEnvironment env = new MockEnvironment();
            assertThat(LifeengineApplicationEnvironmentPreparedListener.resolveAppEnv(env)).isEqualTo("local");
        }

        @Test
        @DisplayName("profile 'prod' alone does NOT escalate runtime to prod (must be explicit)")
        void profileProdDoesNotEscalateToProd() {
            MockEnvironment env = new MockEnvironment();
            env.setActiveProfiles("prod");
            // Falls through to safe "local" default; the operator must explicitly set APP_ENV / LIFEENGINE_DEPLOYMENT_ENV
            // to enter prod-equivalent runtime.
            assertThat(LifeengineApplicationEnvironmentPreparedListener.resolveAppEnv(env)).isEqualTo("local");
        }
    }

    @Nested
    @DisplayName("onApplicationEvent() — wiring + validation")
    class FullListener {

        @Test
        @DisplayName("local: passes with no exports; resolved value is published as a property source")
        void localPassesWithNoExports() {
            MockEnvironment env = new MockEnvironment();
            listener.onApplicationEvent(eventFor(env));
            assertThat(env.getProperty("lifeengine.deployment.env")).isEqualTo("local");
            assertThat(env.getPropertySources()
                            .contains(LifeengineApplicationEnvironmentPreparedListener.RESOLVED_PROPERTY_SOURCE))
                    .isTrue();
        }

        @Test
        @DisplayName("APP_ENV=local alone passes and publishes lifeengine.deployment.env=local")
        void appEnvLocalAloneIsEnough() {
            MockEnvironment env = new MockEnvironment().withProperty("APP_ENV", "local");
            listener.onApplicationEvent(eventFor(env));
            assertThat(env.getProperty("lifeengine.deployment.env")).isEqualTo("local");
        }

        @Test
        @DisplayName("test profile short-circuits (no APP_ENV required)")
        void testProfileShortCircuits() {
            MockEnvironment env = new MockEnvironment();
            env.setActiveProfiles("test");
            listener.onApplicationEvent(eventFor(env));
            assertThat(env.getProperty("lifeengine.deployment.env")).isEqualTo("test");
        }

        @Test
        @DisplayName("APP_ENV=prod without DB password fails fast")
        void prodRequiresDatasourcePassword() {
            MockEnvironment env = new MockEnvironment().withProperty("APP_ENV", "prod");
            assertThatThrownBy(() -> listener.onApplicationEvent(eventFor(env)))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("spring.datasource.password");
        }

        @Test
        @DisplayName("APP_ENV=prod without flyway password fails fast")
        void prodRequiresFlywayPassword() {
            MockEnvironment env = new MockEnvironment()
                    .withProperty("APP_ENV", "prod")
                    .withProperty("spring.datasource.password", "set");
            assertThatThrownBy(() -> listener.onApplicationEvent(eventFor(env)))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("spring.flyway.password");
        }

        @Test
        @DisplayName("APP_ENV=prod with both passwords succeeds and publishes prod")
        void prodWithAllPasswordsSucceeds() {
            MockEnvironment env = new MockEnvironment()
                    .withProperty("APP_ENV", "prod")
                    .withProperty("spring.datasource.password", "ds")
                    .withProperty("spring.flyway.password", "fly");
            listener.onApplicationEvent(eventFor(env));
            assertThat(env.getProperty("lifeengine.deployment.env")).isEqualTo("prod");
        }

        @Test
        @DisplayName("garbage APP_ENV value is rejected")
        void invalidAppEnvIsRejected() {
            MockEnvironment env = new MockEnvironment().withProperty("APP_ENV", "qa");
            assertThatThrownBy(() -> listener.onApplicationEvent(eventFor(env)))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("must be one of local, dev, prod, test");
        }

        @Test
        @DisplayName("non-test path adds the resolved property source exactly once")
        void resolvedPropertySourceIsIdempotent() {
            MockEnvironment env = new MockEnvironment().withProperty("APP_ENV", "local");
            listener.onApplicationEvent(eventFor(env));
            listener.onApplicationEvent(eventFor(env));
            long count = env.getPropertySources().stream()
                    .filter(ps -> LifeengineApplicationEnvironmentPreparedListener.RESOLVED_PROPERTY_SOURCE
                            .equals(ps.getName()))
                    .count();
            assertThat(count).isEqualTo(1);
        }

        @Test
        @DisplayName("operator-supplied lifeengine.deployment.env survives without being overwritten")
        void operatorSuppliedValueSurvives() {
            MockEnvironment env = new MockEnvironment().withProperty("lifeengine.deployment.env", "dev")
                    .withProperty("spring.datasource.password", "ds")
                    .withProperty("spring.flyway.password", "fly");
            listener.onApplicationEvent(eventFor(env));
            assertThat(env.getProperty("lifeengine.deployment.env")).isEqualTo("dev");
        }
    }

    private static ApplicationEnvironmentPreparedEvent eventFor(ConfigurableEnvironment environment) {
        SpringApplication app = new SpringApplication();
        return new ApplicationEnvironmentPreparedEvent(
                new DefaultBootstrapContext(), app, new String[0], environment);
    }

    /** Silences unused import warnings in IDEs that strip {@link MapPropertySource} / {@link HashMap} / {@link Map}. */
    @SuppressWarnings("unused")
    private static void touchUnused() {
        new MapPropertySource("x", new HashMap<String, Object>());
        Map<String, Object> m = new HashMap<>();
        m.size();
    }
}
