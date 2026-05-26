package com.devito.lifeengine.support.integration;

import org.springframework.test.context.DynamicPropertyRegistry;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * Single shared PostgreSQL (Testcontainers) for all modulith WebFlux IT classes in the same JVM. A static
 * {@link org.testcontainers.junit.jupiter.Container} on an abstract superclass is stopped when the first concrete
 * class completes, which breaks subsequent {@link org.springframework.boot.test.context.SpringBootTest} classes.
 */
public final class LifeEngineModulithPostgresItSupport {

    private static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>(DockerImageName.parse("pgvector/pgvector:pg16"))
                    .withDatabaseName("life_engine_modulith_it")
                    .withUsername("life")
                    .withPassword("life");

    static {
        POSTGRES.start();
    }

    private LifeEngineModulithPostgresItSupport() {}

    public static void registerDatasource(
            DynamicPropertyRegistry r, String jwtSecret, String bootstrapEmail, String bootstrapPassword) {
        r.add("lifeengine.deployment.env", () -> "test");
        String jdbc = POSTGRES.getJdbcUrl();
        String r2dbc = toR2dbcUrl(jdbc);
        r.add("spring.datasource.url", () -> jdbc);
        r.add("spring.datasource.username", POSTGRES::getUsername);
        r.add("spring.datasource.password", POSTGRES::getPassword);
        r.add("spring.r2dbc.url", () -> r2dbc);
        r.add("spring.r2dbc.username", POSTGRES::getUsername);
        r.add("spring.r2dbc.password", POSTGRES::getPassword);
        r.add("spring.flyway.url", () -> jdbc);
        r.add("spring.flyway.user", POSTGRES::getUsername);
        r.add("spring.flyway.password", POSTGRES::getPassword);
        r.add("spring.flyway.enabled", () -> "true");
        r.add("lifeengine.security.jwt.secret", () -> jwtSecret);
        r.add("lifeengine.security.bootstrap-admin-email", () -> bootstrapEmail);
        r.add("lifeengine.security.bootstrap-admin-password", () -> bootstrapPassword);
        r.add("lifeengine.security.password-reset.expose-token-for-testing", () -> "true");
        // Retrieval "enabled" lets PromptBackedMemoryAgentAdapter use the read-only empty-lexical fast path for
        // ANALYZE_ONLY without calling memory llm.complete; strict/require-index false keeps index preflight off.
        r.add("lifeengine.dev-agent.retrieval.enabled", () -> "true");
        r.add("lifeengine.dev-agent.execution.strict-real-mode", () -> "false");
        r.add("lifeengine.dev-agent.execution.require-index-ready", () -> "false");
    }

    private static String toR2dbcUrl(String jdbcUrl) {
        String base = jdbcUrl.replace("jdbc:postgresql://", "r2dbc:postgresql://");
        int q = base.indexOf('?');
        return q > 0 ? base.substring(0, q) : base;
    }
}
