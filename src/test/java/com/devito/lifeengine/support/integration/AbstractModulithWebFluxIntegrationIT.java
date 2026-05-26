package com.devito.lifeengine.support.integration;

import static org.assertj.core.api.Assertions.assertThat;

import com.devito.lifeengine.LifeEngineAuthApplication;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;
import java.util.Objects;
import org.junit.jupiter.api.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * Shared full-stack slice for Modulith WebFlux integration tests: Flyway + JDBC + R2DBC on
 * {@link LifeEngineModulithPostgresItSupport}, JWT secret, bootstrap admin, and stable dev-agent flags. Concrete suites
 * live per vertical under
 * {@code com.devito.lifeengine.<module>.integration} and add only module-specific scenarios.
 *
 * <p>Layout (under {@code apps/core-app/src/test/java}):
 *
 * <pre>
 * com.devito.lifeengine.support.integration/
 *   AbstractModulithWebFluxIntegrationIT.java
 *   LifeEngineModulithPostgresItSupport.java
 * com.devito.lifeengine.auth.integration/
 *   AuthModulithWebFluxContractIT.java
 * com.devito.lifeengine.devagent.integration/
 *   DevAgentModulithWebFluxContractIT.java
 * com.devito.lifeengine.agentruntime.integration/
 *   AgentRuntimeModulithWebFluxContractIT.java
 * com.devito.lifeengine.memoryrag.integration/
 *   MemoryRagModulithWebFluxContractIT.java
 * </pre>
 *
 * <p>Runs with Failsafe ({@code *IT.java}), Docker required — same discipline as {@code AuthCriticalFlowsIT}.
 *
 * <p>PostgreSQL is started once per JVM via {@link LifeEngineModulithPostgresItSupport} so multiple concrete IT
 * classes can each boot their own Spring context without stopping the database mid-suite.
 */
@Tag("integration")
@Tag("modulith-contract")
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = LifeEngineAuthApplication.class)
@AutoConfigureWebTestClient
@ActiveProfiles("test")
public abstract class AbstractModulithWebFluxIntegrationIT {

    protected static final String IT_JWT_SECRET =
            "0123456789012345678901234567890123456789012345678901234567890123";

    protected static final String BOOTSTRAP_EMAIL = "it-admin@life-engine.local";
    protected static final String BOOTSTRAP_PASSWORD = "ItBootstrap_Admin_Pass1!";

    @DynamicPropertySource
    static void registerModulithItDatasource(DynamicPropertyRegistry r) {
        LifeEngineModulithPostgresItSupport.registerDatasource(r, IT_JWT_SECRET, BOOTSTRAP_EMAIL, BOOTSTRAP_PASSWORD);
    }

    @Autowired protected WebTestClient webClient;
    @Autowired protected ObjectMapper objectMapper;

    protected String bearer(String accessToken) {
        return "Bearer " + accessToken;
    }

    protected JsonNode readJson(String json) {
        try {
            return objectMapper.readTree(json);
        } catch (Exception e) {
            throw new IllegalStateException("json parse: " + json, e);
        }
    }

    protected static String text(JsonNode n, String field) {
        if (n == null || n.isMissingNode()) {
            return null;
        }
        JsonNode c = n.get(field);
        if (c == null || c.isNull() || c.isMissingNode()) {
            return null;
        }
        return c.asText();
    }

    protected static String firstText(JsonNode n, String camel, String snake) {
        if (n.hasNonNull(camel)) {
            return n.get(camel).asText();
        }
        if (n.hasNonNull(snake)) {
            return n.get(snake).asText();
        }
        return "";
    }

    /**
     * Successful login against real {@code POST /api/auth/login}; fails the exchange if status is not 200.
     */
    protected Tokens login(String email, String password) {
        String json =
                webClient
                        .post()
                        .uri("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .bodyValue(Map.of("email", email, "password", password))
                        .exchange()
                        .expectStatus()
                        .isOk()
                        .expectBody(String.class)
                        .returnResult()
                        .getResponseBody();
        try {
            JsonNode n = objectMapper.readTree(Objects.requireNonNull(json, "login body"));
            String access = firstText(n, "accessToken", "access_token");
            String refresh = firstText(n, "refreshToken", "refresh_token");
            assertThat(access).as("login accessToken").isNotBlank();
            assertThat(refresh).as("login refreshToken").isNotBlank();
            return new Tokens(access, refresh);
        } catch (Exception e) {
            throw new IllegalStateException("login parse: " + json, e);
        }
    }

    public record Tokens(String accessToken, String refreshToken) {}
}
