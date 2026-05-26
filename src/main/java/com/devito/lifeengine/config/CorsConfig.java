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
 * WebFlux CORS: permissive localhost patterns for {@code local}/{@code dev}/{@code test}; production uses an explicit
 * allow-list ({@code lifeengine.http.cors.allowed-origins}) — no wildcards.
 */
@Configuration
public class CorsConfig {

    private static final String PROP_ALLOWED_ORIGINS = "lifeengine.http.cors.allowed-origins";

    @Bean
    public CorsWebFilter corsWebFilter(Environment environment) {
        CorsConfiguration config = new CorsConfiguration();
        if (isProductionDeployment(environment)) {
            config.setAllowedOrigins(parseAllowedOrigins(environment));
        } else {
            /*
             * Local BO (4200), Ionic-style dev servers (8100), and arbitrary localhost / 127.0.0.1 ports — matches
             * {@code LOCAL_STACK.md}. Patterns work with {@code allowCredentials(true)}.
             */
            config.setAllowedOriginPatterns(List.of("http://localhost:*", "http://127.0.0.1:*"));
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

    private static boolean isProductionDeployment(Environment environment) {
        String env = deploymentEnv(environment);
        return "prod".equals(env) || environment.acceptsProfiles(Profiles.of("prod"));
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
