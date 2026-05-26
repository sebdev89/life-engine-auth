package com.devito.lifeengine.auth.integration;

import static org.assertj.core.api.Assertions.assertThat;

import com.devito.lifeengine.support.integration.AbstractModulithWebFluxIntegrationIT;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

/**
 * Contract-focused auth HTTP tests (login + {@code /api/auth/me}, 401 paths, JSON shape). Heavier RBAC stories stay in
 * {@link AuthCriticalFlowsIT}.
 */
@Tag("auth")
class AuthModulithWebFluxContractIT extends AbstractModulithWebFluxIntegrationIT {

    @Test
    @DisplayName("POST /api/auth/login with bad password → 401 + ApiErrorEnvelope code=unauthorized")
    void loginInvalidCredentialsIsUnauthorized() {
        String body =
                webClient
                        .post()
                        .uri("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .bodyValue(
                                "{\"email\":\""
                                        + BOOTSTRAP_EMAIL
                                        + "\",\"password\":\"definitely-not-the-bootstrap-password\"}")
                        .exchange()
                        .expectStatus()
                        .isUnauthorized()
                        .expectBody(String.class)
                        .returnResult()
                        .getResponseBody();

        assertThat(text(readJson(body), "code")).isEqualTo("unauthorized");
    }

    @Test
    @DisplayName("POST /api/auth/login success → tokens + expiry fields (shape)")
    void loginSuccessResponseShape() {
        String body =
                webClient
                        .post()
                        .uri("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .bodyValue("{\"email\":\"" + BOOTSTRAP_EMAIL + "\",\"password\":\"" + BOOTSTRAP_PASSWORD + "\"}")
                        .exchange()
                        .expectStatus()
                        .isOk()
                        .expectHeader()
                        .contentTypeCompatibleWith(MediaType.APPLICATION_JSON)
                        .expectBody(String.class)
                        .returnResult()
                        .getResponseBody();

        JsonNode n = readJson(body);
        assertThat(firstText(n, "accessToken", "access_token")).isNotBlank();
        assertThat(firstText(n, "refreshToken", "refresh_token")).isNotBlank();
        assertThat(firstText(n, "tokenType", "token_type")).isNotBlank();
        assertThat(n.path("expiresInSeconds").isNumber() || n.path("expires_in_seconds").isNumber())
                .as("login should expose access TTL")
                .isTrue();
        assertThat(n.path("refreshExpiresInSeconds").isNumber() || n.path("refresh_expires_in_seconds").isNumber())
                .as("login should expose refresh TTL")
                .isTrue();
    }

    @Test
    @DisplayName("GET /api/auth/me without Authorization → 401 + ApiErrorEnvelope code=unauthorized")
    void meWithoutBearerIsUnauthorized() {
        String body =
                webClient
                        .get()
                        .uri("/api/auth/me")
                        .exchange()
                        .expectStatus()
                        .isUnauthorized()
                        .expectBody(String.class)
                        .returnResult()
                        .getResponseBody();

        assertThat(text(readJson(body), "code")).isEqualTo("unauthorized");
    }

    @Test
    @DisplayName("GET /api/platform/config without Authorization → 401 (not owned by life-engine-auth)")
    void platformConfigIsNotOwnedByAuth() {
        webClient.get().uri("/api/platform/config").exchange().expectStatus().isUnauthorized();
    }

    @Test
    @DisplayName("GET /api/platform/health without Authorization → 401 (not owned by life-engine-auth)")
    void platformHealthIsNotOwnedByAuth() {
        webClient.get().uri("/api/platform/health").exchange().expectStatus().isUnauthorized();
    }

    @Test
    @DisplayName("GET /api/auth/me with Bearer → MeResponse shape")
    void meWithBearerReturnsPrincipalEnvelope() {
        Tokens t = login(BOOTSTRAP_EMAIL, BOOTSTRAP_PASSWORD);
        String body =
                webClient
                        .get()
                        .uri("/api/auth/me")
                        .header(HttpHeaders.AUTHORIZATION, bearer(t.accessToken()))
                        .exchange()
                        .expectStatus()
                        .isOk()
                        .expectBody(String.class)
                        .returnResult()
                        .getResponseBody();

        JsonNode n = readJson(body);
        assertThat(text(n, "userId")).matches("[a-f0-9-]{8,}");
        assertThat(text(n, "email")).isEqualTo(BOOTSTRAP_EMAIL);
        assertThat(text(n, "primaryRole")).isNotBlank();
        assertThat(n.path("authorities").isArray()).isTrue();
        assertThat(n.path("authorities").size()).isGreaterThan(0);
    }
}
