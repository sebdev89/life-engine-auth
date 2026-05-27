package com.devito.lifeengine.config;

import java.util.Arrays;
import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

/**
 * WebFlux CORS.
 *
 * <p>Two strict modes only:
 *
 * <ul>
 *   <li><b>local</b> ({@code lifeengine.deployment.env=local} or Spring profile {@code local}): permissive
 *       localhost-only origin patterns so {@code mvn spring-boot:run} + a local BO (Angular 4200, Ionic 8100,
 *       arbitrary localhost / 127.0.0.1 ports) works without exporting an env var. Preserves local frontend
 *       development ergonomics.</li>
 *   <li><b>everything else</b> (dev, ci, test, prod, unset): explicit allow-list via
 *       {@code lifeengine.http.cors.allowed-origins} (comma separated). No wildcards. No localhost shortcut.
 *       Shared dev / test / prod-like environments must list their FE origins explicitly. An empty list
 *       blocks all cross-origin requests at the CORS layer — pair with
 *       {@code lifeengine.http.cors.prod-allow-empty=true} only as a documented opt-out.</li>
 * </ul>
 */
@Configuration
public class CorsConfig {

    private static final String PROP_ALLOWED_ORIGINS = "lifeengine.http.cors.allowed-origins";

    @Bean
    public CorsWebFilter corsWebFilter(Environment environment) {
        CorsConfiguration config = new CorsConfiguration();
        if (isLocalDevelopment(environment)) {
            /*
             * Local-only fallback: localhost / 127.0.0.1 with any port. Patterns work with
             * allowCredentials(true). Matches LOCAL_STACK.md. Never used outside the local profile.
             */
            config.setAllowedOriginPatterns(List.of("http://localhost:*", "http://127.0.0.1:*"));
        } else {
            config.setAllowedOrigins(parseAllowedOrigins(environment));
        }
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(
                List.of("Authorization", "Content-Type", "Accept", "Cache-Control", "X-Request-Id"));
        config.setExposedHeaders(List.of("Content-Type", "Cache-Control", "X-Request-Id"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return new CorsWebFilter(source);
    }

    /**
     * True only for genuine local development. {@code dev} / {@code ci} / {@code test} / {@code prod} all
     * fall into the explicit allow-list branch — they are shared or production-like and must declare their
     * own origins.
     */
    private static boolean isLocalDevelopment(Environment environment) {
        String env = deploymentEnv(environment);
        if ("local".equals(env)) {
            return true;
        }
        if (!env.isEmpty()) {
            return false;
        }
        return environment.acceptsProfiles(Profiles.of("local"));
    }

    /** Prefer {@code lifeengine.deployment.env}, then {@code APP_ENV}. */
    private static String deploymentEnv(Environment environment) {
        String le = environment.getProperty("lifeengine.deployment.env", "").trim().toLowerCase();
        if (!le.isEmpty()) {
            return le;
        }
        return environment.getProperty("APP_ENV", "").trim().toLowerCase();
    }

    private static List<String> parseAllowedOrigins(Environment environment) {
        String raw = environment.getProperty(PROP_ALLOWED_ORIGINS, "");
        if (raw.isBlank()) {
            return List.of();
        }
        return Arrays.stream(raw.split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList();
    }
}
