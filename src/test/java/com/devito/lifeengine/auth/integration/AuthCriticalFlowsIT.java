package com.devito.lifeengine.auth.integration;

import static org.assertj.core.api.Assertions.assertThat;

import com.devito.lifeengine.LifeEngineAuthApplication;
import com.devito.lifeengine.auth.infrastructure.config.JwtSecurityProperties;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Full-stack auth flows against a real PostgreSQL (Testcontainers) with Flyway migrations applied.
 * Covers login/refresh/revoke/logout, RBAC, control plane, self-service {@code /api/auth/me} and {@code /api/auth/me/**},
 * password change/reset (with {@code lifeengine.security.password-reset.expose-token-for-testing=true}), admin
 * observability ({@code /api/auth/security/**}, {@code /api/security/**}), and USER vs ADMIN access rules — no mocked
 * security.
 *
 * <p><b>Docker required:</b> runs under Maven Failsafe ({@code *IT.java}) — {@code mvn test} does not execute this
 * class. Use {@code mvn verify} (or {@code -Pauth-it}). If Docker is missing or the daemon API is incompatible, the
 * build <b>fails</b> (no silent skip). See {@code TESTING.md}.
 *
 * <p>Tags: {@code @Tag("integration")}, {@code @Tag("spec")} (anchor; not {@code demo} — too large for a short tour
 * run; use {@code mvn ... -Dgroups=demo} for the three vertical {@code *SpecIT} classes only. See {@code TESTING.md}.)
 */
@Tag("integration")
@Tag("spec")
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = LifeEngineAuthApplication.class)
@AutoConfigureWebTestClient
@ActiveProfiles("test")
@Testcontainers
class AuthCriticalFlowsIT {

    private static final String IT_JWT_SECRET =
            "0123456789012345678901234567890123456789012345678901234567890123";

    private static final String BOOTSTRAP_EMAIL = "it-admin@life-engine.local";
    private static final String BOOTSTRAP_PASSWORD = "ItBootstrap_Admin_Pass1!";

    private static final UUID ROLE_USER = UUID.fromString("b1111111-1111-4111-8111-111111111102");
    private static final UUID ROLE_VIEWER = UUID.fromString("b1111111-1111-4111-8111-111111111106");
    private static final UUID NON_EXISTENT_ROLE = UUID.fromString("00000000-0000-0000-0000-000000000099");

    @Container
    private static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>(DockerImageName.parse("pgvector/pgvector:pg16"))
                    .withDatabaseName("life_engine_it")
                    .withUsername("life")
                    .withPassword("life");

    @DynamicPropertySource
    static void registerDatasourceProps(DynamicPropertyRegistry r) {
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
        r.add("lifeengine.security.jwt.secret", () -> IT_JWT_SECRET);
        r.add("lifeengine.security.bootstrap-admin-email", () -> BOOTSTRAP_EMAIL);
        r.add("lifeengine.security.bootstrap-admin-password", () -> BOOTSTRAP_PASSWORD);
        r.add("lifeengine.security.password-reset.expose-token-for-testing", () -> "true");
    }

    private static String toR2dbcUrl(String jdbcUrl) {
        String base = jdbcUrl.replace("jdbc:postgresql://", "r2dbc:postgresql://");
        int q = base.indexOf('?');
        return q > 0 ? base.substring(0, q) : base;
    }

    @Autowired private WebTestClient webClient;
    @Autowired private JwtSecurityProperties jwtSecurityProperties;
    @Autowired private PasswordEncoder passwordEncoder;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private DatabaseClient databaseClient;

    @Test
    @DisplayName("Flyway applied at least one migration (schema matches migrations)")
    void flywayMigrationsRan() {
        Long n =
                databaseClient
                        .sql("SELECT COUNT(*) FROM flyway_schema_history")
                        .map((row, meta) -> row.get(0, Long.class))
                        .one()
                        .block();
        assertThat(n).isNotNull().isPositive();
    }

    @Test
    @DisplayName("Login succeeds and returns bearer access + refresh tokens")
    void loginSuccess() {
        Tokens t = login(BOOTSTRAP_EMAIL, BOOTSTRAP_PASSWORD);
        assertThat(t.accessToken()).isNotBlank();
        assertThat(t.refreshToken()).isNotBlank();
        assertThat(jwtClaimText(t.accessToken(), "role")).isEqualTo("ADMIN");
        webClient
                .get()
                .uri("/api/auth/me")
                .header(HttpHeaders.AUTHORIZATION, bearer(t.accessToken()))
                .exchange()
                .expectStatus()
                .isOk()
                .expectBody()
                .jsonPath("$.email")
                .isEqualTo(BOOTSTRAP_EMAIL);
    }

    @Test
    @DisplayName("Login inserts user_sessions row for JWT sid (sync after refresh insert must not be UPDATE-only)")
    void loginPersistsUserSessionRowForJwtSid() {
        Tokens t = login(BOOTSTRAP_EMAIL, BOOTSTRAP_PASSWORD);
        UUID sid = jwtClaimUuid(t.accessToken(), "sid");
        Long count =
                databaseClient
                        .sql(
                                """
                                SELECT COUNT(*) FROM user_sessions
                                WHERE id = :sid AND revoked_at IS NULL
                                  AND (expires_at IS NULL OR expires_at > NOW())
                                """)
                        .bind("sid", sid)
                        .map((row, meta) -> row.get(0, Long.class))
                        .one()
                        .block();
        assertThat(count).isEqualTo(1L);
    }

    @Test
    @DisplayName("Fresh access token passes session gate on /api/auth/me (no session_inactive)")
    void loginThenMeIsAuthorized() {
        Tokens t = login(BOOTSTRAP_EMAIL, BOOTSTRAP_PASSWORD);
        webClient
                .get()
                .uri("/api/auth/me")
                .header(HttpHeaders.AUTHORIZATION, bearer(t.accessToken()))
                .exchange()
                .expectStatus()
                .isOk();
    }

    @Test
    @DisplayName("Login is rejected when user has no bo_user_role rows (RBAC incomplete)")
    void loginRejectedWithoutBoUserRole() {
        String email = "norolelink-" + UUID.randomUUID() + "@it.local";
        UUID id = UUID.randomUUID();
        databaseClient
                .sql(
                        """
                        INSERT INTO bo_user (id, email, password_hash, enabled, locked, failed_login_attempts, locked_until, created_at, password_changed_at)
                        VALUES (:id, :email, :ph, true, false, 0, NULL, NOW(), NOW())
                        """)
                .bind("id", id)
                .bind("email", email)
                .bind("ph", passwordEncoder.encode("SomePass1!Xx"))
                .then()
                .block();
        webClient
                .post()
                .uri("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("email", email, "password", "SomePass1!Xx"))
                .exchange()
                .expectStatus()
                .isUnauthorized();
    }

    @Test
    @DisplayName("JWT role claim follows bo_user_role primary (VIEWER)")
    void jwtPrimaryRoleFromRbacViewer() {
        String email = "viewer-claim-" + UUID.randomUUID() + "@it.local";
        Tokens t = registerAndLogin(email, "ViewerJwt_Pass1!", ROLE_VIEWER);
        assertThat(jwtClaimText(t.accessToken(), "role")).isEqualTo("VIEWER");
    }

    @Test
    @DisplayName("Login fails with invalid credentials")
    void loginFailsWithInvalidCredentials() {
        webClient
                .post()
                .uri("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"" + BOOTSTRAP_EMAIL + "\",\"password\":\"wrong-password\"}")
                .exchange()
                .expectStatus()
                .isUnauthorized();
    }

    @Test
    @DisplayName("Refresh rotates tokens when refresh token is valid")
    void refreshTokenSuccess() {
        Tokens first = login(BOOTSTRAP_EMAIL, BOOTSTRAP_PASSWORD);
        Tokens second =
                refresh(first.refreshToken())
                        .expectStatus()
                        .isOk()
                        .expectBody(Tokens.class)
                        .returnResult()
                        .getResponseBody();
        assertThat(second).isNotNull();
        assertThat(second.accessToken()).isNotBlank().isNotEqualTo(first.accessToken());
        assertThat(second.refreshToken()).isNotBlank().isNotEqualTo(first.refreshToken());
    }

    @Test
    @DisplayName("POST /api/auth/sessions/revoke-others revokes other sessions; current refresh still works")
    void revokeOtherSessionsInvalidatesOlderRefreshOnly() {
        Tokens older = login(BOOTSTRAP_EMAIL, BOOTSTRAP_PASSWORD);
        Tokens newer = login(BOOTSTRAP_EMAIL, BOOTSTRAP_PASSWORD);
        webClient
                .post()
                .uri("/api/auth/sessions/revoke-others")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("refreshToken", newer.refreshToken()))
                .exchange()
                .expectStatus()
                .is2xxSuccessful();
        refresh(older.refreshToken()).expectStatus().isUnauthorized();
        refresh(newer.refreshToken()).expectStatus().isOk();
    }

    @Test
    @DisplayName("POST /api/auth/revoke invalidates refresh; subsequent refresh fails")
    void revokeRefreshThenRefreshFails() {
        Tokens t = login(BOOTSTRAP_EMAIL, BOOTSTRAP_PASSWORD);
        webClient
                .post()
                .uri("/api/auth/revoke")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("refreshToken", t.refreshToken()))
                .exchange()
                .expectStatus()
                .is2xxSuccessful();
        refresh(t.refreshToken()).expectStatus().isUnauthorized();
    }

    @Test
    @DisplayName("Admin can assign and remove RBAC role for another user")
    void assignRoleAndRemoveRole() {
        Tokens admin = login(BOOTSTRAP_EMAIL, BOOTSTRAP_PASSWORD);
        UUID targetId = insertUserWithRole("rbac-" + UUID.randomUUID() + "@it.local", "RbacPass1!", ROLE_USER);

        webClient
                .post()
                .uri("/api/auth/users/{userId}/roles", targetId)
                .header(HttpHeaders.AUTHORIZATION, bearer(admin.accessToken()))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"roleId\":\"" + ROLE_VIEWER + "\"}")
                .exchange()
                .expectStatus()
                .is2xxSuccessful();

        webClient
                .delete()
                .uri("/api/auth/users/{userId}/roles/{roleId}", targetId, ROLE_VIEWER)
                .header(HttpHeaders.AUTHORIZATION, bearer(admin.accessToken()))
                .exchange()
                .expectStatus()
                .is2xxSuccessful();
    }

    @Test
    @DisplayName("Assign role with unknown role id returns 400")
    void assignRoleUnknownRoleIdReturnsBadRequest() {
        Tokens admin = login(BOOTSTRAP_EMAIL, BOOTSTRAP_PASSWORD);
        UUID targetId = insertUserWithRole("norole-" + UUID.randomUUID() + "@it.local", "NoRolePass1!", ROLE_USER);
        webClient
                .post()
                .uri("/api/auth/users/{userId}/roles", targetId)
                .header(HttpHeaders.AUTHORIZATION, bearer(admin.accessToken()))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"roleId\":\"" + NON_EXISTENT_ROLE + "\"}")
                .exchange()
                .expectStatus()
                .isBadRequest();
    }

    @Test
    @DisplayName("Locked user cannot login")
    void lockedUserCannotLogin() {
        String victimEmail = "lock-" + UUID.randomUUID() + "@it.local";
        Tokens admin = login(BOOTSTRAP_EMAIL, BOOTSTRAP_PASSWORD);
        UUID victimId = insertUserWithRole(victimEmail, "LockPass1!", ROLE_USER);

        webClient
                .post()
                .uri("/api/security/users/{id}/lock", victimId)
                .header(HttpHeaders.AUTHORIZATION, bearer(admin.accessToken()))
                .exchange()
                .expectStatus()
                .isNoContent();

        webClient
                .post()
                .uri("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"" + victimEmail + "\",\"password\":\"LockPass1!\"}")
                .exchange()
                .expectStatus()
                .isUnauthorized();

        webClient
                .post()
                .uri("/api/security/users/{id}/unlock", victimId)
                .header(HttpHeaders.AUTHORIZATION, bearer(admin.accessToken()))
                .exchange()
                .expectStatus()
                .isNoContent();
    }

    @Test
    @DisplayName("Malformed or non-JWT bearer is rejected for /api/auth/me")
    void invalidBearerRejected() {
        webClient
                .get()
                .uri("/api/auth/me")
                .header(HttpHeaders.AUTHORIZATION, "Bearer not-a-jwt")
                .exchange()
                .expectStatus()
                .isUnauthorized();
    }

    @Test
    @DisplayName("Expired access token is rejected for /api/auth/me")
    void expiredAccessTokenRejected() {
        Tokens t = login(BOOTSTRAP_EMAIL, BOOTSTRAP_PASSWORD);
        UUID userId = jwtClaimUuid(t.accessToken(), "sub");
        String expired = buildExpiredAccessToken(userId, BOOTSTRAP_EMAIL, "ADMIN");
        webClient
                .get()
                .uri("/api/auth/me")
                .header(HttpHeaders.AUTHORIZATION, bearer(expired))
                .exchange()
                .expectStatus()
                .isUnauthorized();
    }

    @Test
    @DisplayName("Admin can kill session; victim refresh then fails")
    void killSessionRevokesRefreshChain() {
        String email = "kill-" + UUID.randomUUID() + "@it.local";
        insertUserWithRole(email, "KillPass1!", ROLE_USER);
        Tokens victim = login(email, "KillPass1!");
        Tokens admin = login(BOOTSTRAP_EMAIL, BOOTSTRAP_PASSWORD);

        UUID sessionId = jwtClaimUuid(victim.accessToken(), "sid");
        assertThat(sessionId).isNotNull();

        webClient
                .post()
                .uri("/api/security/sessions/{id}/kill", sessionId)
                .header(HttpHeaders.AUTHORIZATION, bearer(admin.accessToken()))
                .exchange()
                .expectStatus()
                .isNoContent();

        refresh(victim.refreshToken()).expectStatus().isUnauthorized();
    }

    @Test
    @DisplayName("Admin can revoke a refresh token row via control plane")
    void controlPlaneRevokeToken() throws Exception {
        String email = "tok-" + UUID.randomUUID() + "@it.local";
        insertUserWithRole(email, "TokPass1!", ROLE_USER);
        Tokens victim = login(email, "TokPass1!");
        Tokens admin = login(BOOTSTRAP_EMAIL, BOOTSTRAP_PASSWORD);

        String json =
                webClient
                        .get()
                        .uri("/api/security/tokens")
                        .header(HttpHeaders.AUTHORIZATION, bearer(admin.accessToken()))
                        .exchange()
                        .expectStatus()
                        .isOk()
                        .expectBody(String.class)
                        .returnResult()
                        .getResponseBody();
        JsonNode arr = objectMapper.readTree(json);
        UUID tokenRowId = null;
        for (JsonNode n : arr) {
            if (email.equals(n.path("principalLabel").asText()) && !n.path("revoked").asBoolean()) {
                tokenRowId = UUID.fromString(n.get("id").asText());
                break;
            }
        }
        assertThat(tokenRowId).isNotNull();

        webClient
                .post()
                .uri("/api/security/tokens/{id}/revoke", tokenRowId)
                .header(HttpHeaders.AUTHORIZATION, bearer(admin.accessToken()))
                .exchange()
                .expectStatus()
                .isNoContent();

        refresh(victim.refreshToken()).expectStatus().isUnauthorized();
    }

    @Test
    @DisplayName("ADMIN can access /api/security/dashboard, /api/auth/timeline, /api/auth/metrics/overview (200)")
    void adminCanAccessSecurityDashboardAuthObservability() {
        Tokens admin = login(BOOTSTRAP_EMAIL, BOOTSTRAP_PASSWORD);
        String auth = bearer(admin.accessToken());
        webClient
                .get()
                .uri("/api/security/dashboard")
                .header(HttpHeaders.AUTHORIZATION, auth)
                .exchange()
                .expectStatus()
                .isOk();
        webClient
                .get()
                .uri("/api/auth/timeline?limit=5")
                .header(HttpHeaders.AUTHORIZATION, auth)
                .exchange()
                .expectStatus()
                .isOk();
        webClient
                .get()
                .uri("/api/auth/metrics/overview")
                .header(HttpHeaders.AUTHORIZATION, auth)
                .exchange()
                .expectStatus()
                .isOk();
    }

    @Test
    @DisplayName("ADMIN GET /api/security/users/{id}/security returns operator bundle (user + sessions + securityEvents)")
    void adminOperatorSecurityBundleEndpoint() {
        Tokens admin = login(BOOTSTRAP_EMAIL, BOOTSTRAP_PASSWORD);
        UUID adminBoUserId = jwtClaimUuid(admin.accessToken(), "sub");
        String auth = bearer(admin.accessToken());
        webClient
                .get()
                .uri(
                        "/api/security/users/{id}/security?sessionsLimit=200&eventsLimit=120",
                        adminBoUserId)
                .header(HttpHeaders.AUTHORIZATION, auth)
                .exchange()
                .expectStatus()
                .isOk()
                .expectBody()
                .jsonPath("$.user.email")
                .isEqualTo(BOOTSTRAP_EMAIL)
                .jsonPath("$.sessions")
                .exists()
                .jsonPath("$.securityEvents")
                .exists();
    }

    @Test
    @DisplayName("USER role can access self-service GET /api/auth/me/security, /sessions, /activity, /api/auth/session")
    void userCanAccessSelfServiceEndpoints() {
        String email = "selfsvc-" + UUID.randomUUID() + "@it.local";
        Tokens user = registerAndLogin(email, "SelfSvc_Pass1!", ROLE_USER);
        String auth = bearer(user.accessToken());
        webClient
                .get()
                .uri("/api/auth/me/security")
                .header(HttpHeaders.AUTHORIZATION, auth)
                .exchange()
                .expectStatus()
                .isOk()
                .expectBody()
                .jsonPath("$.email")
                .isEqualTo(email);
        webClient
                .get()
                .uri("/api/auth/me/sessions")
                .header(HttpHeaders.AUTHORIZATION, auth)
                .exchange()
                .expectStatus()
                .isOk();
        webClient
                .get()
                .uri("/api/auth/me/activity?limit=5")
                .header(HttpHeaders.AUTHORIZATION, auth)
                .exchange()
                .expectStatus()
                .isOk();
        webClient
                .get()
                .uri("/api/auth/session")
                .header(HttpHeaders.AUTHORIZATION, auth)
                .exchange()
                .expectStatus()
                .isOk()
                .expectBody()
                .jsonPath("$.sessionId")
                .exists();
    }

    @Test
    @DisplayName("POST /api/auth/me/password success; login with new password; old password rejected")
    void changePasswordHappyPath() {
        String email = "chgpw-" + UUID.randomUUID() + "@it.local";
        String oldPw = "OldUser_Pass1!";
        String newPw = "NewUser_Pass2!";
        Tokens before = registerAndLogin(email, oldPw, ROLE_USER);
        webClient
                .post()
                .uri("/api/auth/me/password")
                .header(HttpHeaders.AUTHORIZATION, bearer(before.accessToken()))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(
                        Map.of(
                                "currentPassword", oldPw,
                                "newPassword", newPw,
                                "revokeOtherSessions", false))
                .exchange()
                .expectStatus()
                .isNoContent();
        login(email, newPw);
        webClient
                .post()
                .uri("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"" + email + "\",\"password\":\"" + oldPw + "\"}")
                .exchange()
                .expectStatus()
                .isUnauthorized();
    }

    @Test
    @DisplayName("POST /api/auth/me/password with wrong current password returns 401")
    void changePasswordWrongCurrentRejected() {
        String email = "badcur-" + UUID.randomUUID() + "@it.local";
        Tokens t = registerAndLogin(email, "Good_Pass99!", ROLE_USER);
        webClient
                .post()
                .uri("/api/auth/me/password")
                .header(HttpHeaders.AUTHORIZATION, bearer(t.accessToken()))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(
                        "{\"currentPassword\":\"TotallyWrong1!\",\"newPassword\":\"OtherNew_Pass1!\",\"revokeOtherSessions\":false}")
                .exchange()
                .expectStatus()
                .isUnauthorized();
    }

    @Test
    @DisplayName("POST /api/auth/password/forgot+reset (exposed token); login with new password; old rejected")
    void passwordResetForgotAndComplete() throws Exception {
        String email = "pr-" + UUID.randomUUID() + "@it.local";
        String initialPw = "Initial_Pass99!";
        String newPw = "ResetOk_Pass88!";
        registerAndLogin(email, initialPw, ROLE_USER);
        String forgotBody =
                webClient
                        .post()
                        .uri("/api/auth/password/forgot")
                        .contentType(MediaType.APPLICATION_JSON)
                        .bodyValue("{\"email\":\"" + email + "\"}")
                        .exchange()
                        .expectStatus()
                        .isOk()
                        .expectBody(String.class)
                        .returnResult()
                        .getResponseBody();
        JsonNode root = objectMapper.readTree(forgotBody);
        String resetToken = root.path("resetToken").asText(null);
        assertThat(resetToken).isNotBlank();
        webClient
                .post()
                .uri("/api/auth/password/reset")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"token\":\"" + resetToken + "\",\"newPassword\":\"" + newPw + "\"}")
                .exchange()
                .expectStatus()
                .isNoContent();
        login(email, newPw);
        webClient
                .post()
                .uri("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"" + email + "\",\"password\":\"" + initialPw + "\"}")
                .exchange()
                .expectStatus()
                .isUnauthorized();
    }

    @Test
    @DisplayName("Malformed bearer rejected for self-service GET /api/auth/me/security")
    void malformedBearerRejectedForMeSecurity() {
        webClient
                .get()
                .uri("/api/auth/me/security")
                .header(HttpHeaders.AUTHORIZATION, "Bearer not-a-jwt")
                .exchange()
                .expectStatus()
                .isUnauthorized();
    }

    @Test
    @DisplayName("Expired access token rejected for self-service GET /api/auth/me/security")
    void expiredAccessTokenRejectedForMeSecurity() {
        Tokens t = login(BOOTSTRAP_EMAIL, BOOTSTRAP_PASSWORD);
        UUID userId = jwtClaimUuid(t.accessToken(), "sub");
        String expired = buildExpiredAccessToken(userId, BOOTSTRAP_EMAIL, "ADMIN");
        webClient
                .get()
                .uri("/api/auth/me/security")
                .header(HttpHeaders.AUTHORIZATION, bearer(expired))
                .exchange()
                .expectStatus()
                .isUnauthorized();
    }

    @Test
    @DisplayName("USER role cannot POST /api/auth/users/{id}/roles (403)")
    void userRoleCannotAssignRoles() {
        Tokens user = loginFreshUserWithRole(ROLE_USER);
        UUID targetUserId = UUID.randomUUID();
        webClient
                .post()
                .uri("/api/auth/users/{id}/roles", targetUserId)
                .header(HttpHeaders.AUTHORIZATION, bearer(user.accessToken()))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"roleId\":\"" + ROLE_VIEWER + "\"}")
                .exchange()
                .expectStatus()
                .isForbidden();
    }

    @Test
    @DisplayName("USER role cannot GET /api/security/tokens (403)")
    void userRoleCannotListSecurityTokens() {
        Tokens user = loginFreshUserWithRole(ROLE_USER);
        webClient
                .get()
                .uri("/api/security/tokens")
                .header(HttpHeaders.AUTHORIZATION, bearer(user.accessToken()))
                .exchange()
                .expectStatus()
                .isForbidden();
    }

    @Test
    @DisplayName("USER role cannot GET /api/auth/timeline (403)")
    void userRoleCannotGetAuthTimeline() throws Exception {
        Tokens user = loginFreshUserWithRole(ROLE_USER);
        String body =
                webClient
                        .get()
                        .uri("/api/auth/timeline")
                        .header(HttpHeaders.AUTHORIZATION, bearer(user.accessToken()))
                        .exchange()
                        .expectStatus()
                        .isForbidden()
                        .expectBody(String.class)
                        .returnResult()
                        .getResponseBody();

        assertThat(objectMapper.readTree(body).path("code").asText()).isEqualTo("forbidden");
    }

    @Test
    @DisplayName("USER role cannot GET /api/auth/metrics/overview (403)")
    void userRoleCannotGetAuthMetricsOverview() {
        Tokens user = loginFreshUserWithRole(ROLE_USER);
        webClient
                .get()
                .uri("/api/auth/metrics/overview")
                .header(HttpHeaders.AUTHORIZATION, bearer(user.accessToken()))
                .exchange()
                .expectStatus()
                .isForbidden();
    }

    @Test
    @DisplayName("USER role cannot GET /api/auth/security/events (admin security feed) (403)")
    void userRoleCannotGetAuthSecurityEvents() {
        Tokens user = loginFreshUserWithRole(ROLE_USER);
        webClient
                .get()
                .uri("/api/auth/security/events?limit=5")
                .header(HttpHeaders.AUTHORIZATION, bearer(user.accessToken()))
                .exchange()
                .expectStatus()
                .isForbidden();
    }

    @Test
    @DisplayName("USER role cannot GET /api/security/dashboard (403)")
    void userRoleCannotGetSecurityDashboard() {
        Tokens user = loginFreshUserWithRole(ROLE_USER);
        webClient
                .get()
                .uri("/api/security/dashboard")
                .header(HttpHeaders.AUTHORIZATION, bearer(user.accessToken()))
                .exchange()
                .expectStatus()
                .isForbidden();
    }

    @Test
    @DisplayName("USER role cannot POST /api/security/users (403)")
    void userRoleCannotCreateSecurityUser() {
        Tokens user = loginFreshUserWithRole(ROLE_USER);
        String email = "nope-" + UUID.randomUUID() + "@it.local";
        webClient
                .post()
                .uri("/api/security/users")
                .header(HttpHeaders.AUTHORIZATION, bearer(user.accessToken()))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(
                        "{\"email\":\""
                                + email
                                + "\",\"initialRoleCodes\":[\"USER\"],\"enabled\":false,\"invite\":true}")
                .exchange()
                .expectStatus()
                .isForbidden();
    }

    @Test
    @DisplayName("ADMIN POST /api/security/users invite-only creates disabled user without password; audited")
    void adminCreatesUserInviteOnly() throws Exception {
        Tokens admin = login(BOOTSTRAP_EMAIL, BOOTSTRAP_PASSWORD);
        String email = "inv-" + UUID.randomUUID() + "@it.local";
        String json =
                webClient
                        .post()
                        .uri("/api/security/users")
                        .header(HttpHeaders.AUTHORIZATION, bearer(admin.accessToken()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .bodyValue(
                                "{\"email\":\""
                                        + email
                                        + "\",\"initialRoleCodes\":[\"USER\"],\"enabled\":false,\"invite\":true}")
                        .exchange()
                        .expectStatus()
                        .isCreated()
                        .expectBody(String.class)
                        .returnResult()
                        .getResponseBody();
        JsonNode n = objectMapper.readTree(json);
        UUID newId = UUID.fromString(n.get("id").asText());
        assertThat(n.get("invitePending").asBoolean()).isTrue();
        assertThat(n.get("enabled").asBoolean()).isFalse();

        webClient
                .post()
                .uri("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"" + email + "\",\"password\":\"AnyPass1!DoesNotMatter\"}")
                .exchange()
                .expectStatus()
                .isUnauthorized();

        Long roleRows =
                databaseClient
                        .sql("SELECT COUNT(*) FROM bo_user_role WHERE bo_user_id = :id")
                        .bind("id", newId)
                        .map((row, meta) -> row.get(0, Long.class))
                        .one()
                        .block();
        assertThat(roleRows).isEqualTo(1L);

        String ev =
                databaseClient
                        .sql(
                                "SELECT event_type FROM security_audit_event WHERE user_id = :id AND event_type = 'ADMIN_USER_CREATED' ORDER BY id DESC LIMIT 1")
                        .bind("id", newId)
                        .map((row, meta) -> row.get(0, String.class))
                        .one()
                        .block();
        assertThat(ev).isEqualTo("ADMIN_USER_CREATED");
    }

    @Test
    @DisplayName("ADMIN POST /api/security/users with temporary password allows login when enabled")
    void adminCreatesUserWithTemporaryPassword() throws Exception {
        Tokens admin = login(BOOTSTRAP_EMAIL, BOOTSTRAP_PASSWORD);
        String email = "pwd-" + UUID.randomUUID() + "@it.local";
        String rawPass = "Zz9!create_user_IT";
        String json =
                webClient
                        .post()
                        .uri("/api/security/users")
                        .header(HttpHeaders.AUTHORIZATION, bearer(admin.accessToken()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .bodyValue(
                                "{\"email\":\""
                                        + email
                                        + "\",\"initialRoleCodes\":[\"USER\"],\"enabled\":true,\"invite\":false,\"temporaryPassword\":\""
                                        + rawPass
                                        + "\"}")
                        .exchange()
                        .expectStatus()
                        .isCreated()
                        .expectBody(String.class)
                        .returnResult()
                        .getResponseBody();
        JsonNode n = objectMapper.readTree(json);
        assertThat(n.get("invitePending").asBoolean()).isFalse();
        assertThat(n.get("enabled").asBoolean()).isTrue();
        login(email, rawPass);
    }

    @Test
    @DisplayName("POST /api/security/users duplicate email returns 409")
    void createSecurityUserDuplicateEmail() {
        Tokens admin = login(BOOTSTRAP_EMAIL, BOOTSTRAP_PASSWORD);
        String email = "dup-" + UUID.randomUUID() + "@it.local";
        String body =
                "{\"email\":\""
                        + email
                        + "\",\"initialRoleCodes\":[\"USER\"],\"enabled\":false,\"invite\":true}";
        webClient
                .post()
                .uri("/api/security/users")
                .header(HttpHeaders.AUTHORIZATION, bearer(admin.accessToken()))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .exchange()
                .expectStatus()
                .isCreated();
        webClient
                .post()
                .uri("/api/security/users")
                .header(HttpHeaders.AUTHORIZATION, bearer(admin.accessToken()))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .exchange()
                .expectStatus()
                .isEqualTo(HttpStatus.CONFLICT);
    }

    @Test
    @DisplayName("POST /api/security/users unknown role code returns 400")
    void createSecurityUserUnknownRole() {
        Tokens admin = login(BOOTSTRAP_EMAIL, BOOTSTRAP_PASSWORD);
        String email = "badrole-" + UUID.randomUUID() + "@it.local";
        webClient
                .post()
                .uri("/api/security/users")
                .header(HttpHeaders.AUTHORIZATION, bearer(admin.accessToken()))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(
                        "{\"email\":\""
                                + email
                                + "\",\"initialRoleCodes\":[\"NOT_A_REAL_ROLE_CODE\"],\"enabled\":false,\"invite\":true}")
                .exchange()
                .expectStatus()
                .isBadRequest();
    }

    @Test
    @DisplayName("USER role can GET /api/auth/me (self-service principal)")
    void userRoleCanGetApiAuthMe() {
        String email = "meep-" + UUID.randomUUID() + "@it.local";
        Tokens user = registerAndLogin(email, "MeEp_Pass1!", ROLE_USER);
        webClient
                .get()
                .uri("/api/auth/me")
                .header(HttpHeaders.AUTHORIZATION, bearer(user.accessToken()))
                .exchange()
                .expectStatus()
                .isOk()
                .expectBody()
                .jsonPath("$.email")
                .isEqualTo(email)
                .jsonPath("$.userId")
                .exists();
    }

    @Test
    @DisplayName("JWT signed with a different secret is rejected for /api/auth/me (401)")
    void wrongSigningKeyJwtRejectedForMe() {
        SecretKey wrongKey =
                Keys.hmacShaKeyFor("wrong-signing-key-32-bytes-minimum!!".getBytes(StandardCharsets.UTF_8));
        String tampered =
                Jwts.builder()
                        .subject(UUID.randomUUID().toString())
                        .claim("email", "x@it.local")
                        .claim("role", "USER")
                        .claim("authorities", java.util.List.of("ROLE_USER"))
                        .issuedAt(Date.from(Instant.now().minusSeconds(60)))
                        .expiration(Date.from(Instant.now().plusSeconds(600)))
                        .signWith(wrongKey)
                        .compact();
        webClient
                .get()
                .uri("/api/auth/me")
                .header(HttpHeaders.AUTHORIZATION, bearer(tampered))
                .exchange()
                .expectStatus()
                .isUnauthorized();
    }

    @Test
    @DisplayName("POST /api/auth/logout revokes refresh; access JWT still works until expiry; refresh fails")
    void logoutRevokesRefreshChainAccessJwtStillValid() {
        Tokens t = login(BOOTSTRAP_EMAIL, BOOTSTRAP_PASSWORD);
        webClient
                .post()
                .uri("/api/auth/logout")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("refreshToken", t.refreshToken()))
                .exchange()
                .expectStatus()
                .is2xxSuccessful();
        webClient
                .get()
                .uri("/api/auth/me")
                .header(HttpHeaders.AUTHORIZATION, bearer(t.accessToken()))
                .exchange()
                .expectStatus()
                .isOk()
                .expectBody()
                .jsonPath("$.email")
                .isEqualTo(BOOTSTRAP_EMAIL);
        refresh(t.refreshToken()).expectStatus().isUnauthorized();
    }

    /** Real login via /api/auth/login — JWT carries DB-backed authorities for USER role only. */
    private Tokens loginFreshUserWithRole(UUID primaryRoleId) {
        String email = "user-only-" + UUID.randomUUID() + "@it.local";
        return registerAndLogin(email, "UserOnlyPass1!", primaryRoleId);
    }

    private Tokens registerAndLogin(String email, String rawPassword, UUID primaryRoleId) {
        insertUserWithRole(email, rawPassword, primaryRoleId);
        return login(email, rawPassword);
    }

    private UUID jwtClaimUuid(String jwt, String claim) {
        try {
            String[] parts = jwt.split("\\.");
            byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
            JsonNode n = objectMapper.readTree(payload);
            return UUID.fromString(n.get(claim).asText());
        } catch (Exception e) {
            throw new IllegalStateException("failed to read JWT claim " + claim, e);
        }
    }

    private String jwtClaimText(String jwt, String claim) {
        try {
            String[] parts = jwt.split("\\.");
            byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
            JsonNode n = objectMapper.readTree(payload);
            JsonNode c = n.get(claim);
            if (c == null || c.isNull()) {
                return null;
            }
            return c.asText();
        } catch (Exception e) {
            throw new IllegalStateException("failed to read JWT claim " + claim, e);
        }
    }

    private String buildExpiredAccessToken(UUID userId, String email, String role) {
        SecretKey key = Keys.hmacShaKeyFor(jwtSecurityProperties.getSecret().getBytes(StandardCharsets.UTF_8));
        Instant past = Instant.now().minusSeconds(7200);
        return Jwts.builder()
                .subject(userId.toString())
                .claim("email", email)
                .claim("role", role)
                .claim("authorities", java.util.List.of("ROLE_ADMIN"))
                .issuedAt(Date.from(past.minusSeconds(120)))
                .expiration(Date.from(past))
                .signWith(key)
                .compact();
    }

    private UUID insertUserWithRole(String email, String rawPassword, UUID primaryRoleId) {
        UUID id = UUID.randomUUID();
        databaseClient
                .sql(
                        """
                        INSERT INTO bo_user (id, email, password_hash, enabled, locked, failed_login_attempts, locked_until, created_at, password_changed_at)
                        VALUES (:id, :email, :ph, true, false, 0, NULL, NOW(), NOW())
                        """)
                .bind("id", id)
                .bind("email", email)
                .bind("ph", passwordEncoder.encode(rawPassword))
                .then()
                .block();
        databaseClient
                .sql(
                        """
                        INSERT INTO bo_user_role (id, bo_user_id, role_id, assigned_at)
                        VALUES (:id, :uid, :rid, NOW())
                        """)
                .bind("id", UUID.randomUUID())
                .bind("uid", id)
                .bind("rid", primaryRoleId)
                .then()
                .block();
        return id;
    }

    private Tokens login(String email, String password) {
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
            JsonNode n = objectMapper.readTree(json);
            String access = firstText(n, "accessToken", "access_token");
            String refresh = firstText(n, "refreshToken", "refresh_token");
            assertThat(access).as("login accessToken").isNotBlank();
            assertThat(refresh).as("login refreshToken").isNotBlank();
            return new Tokens(access, refresh);
        } catch (Exception e) {
            throw new IllegalStateException("login response parse failed: " + json, e);
        }
    }

    private static String firstText(JsonNode n, String camel, String snake) {
        if (n.hasNonNull(camel)) {
            return n.get(camel).asText();
        }
        if (n.hasNonNull(snake)) {
            return n.get(snake).asText();
        }
        return "";
    }

    private WebTestClient.ResponseSpec refresh(String refreshToken) {
        return webClient
                .post()
                .uri("/api/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("refreshToken", refreshToken))
                .exchange();
    }

    private static String bearer(String accessToken) {
        return "Bearer " + accessToken;
    }

    /** JSON subset for login/refresh responses (extra fields from {@code LoginResponse} are ignored). */
    @JsonIgnoreProperties(ignoreUnknown = true)
    record Tokens(String accessToken, String refreshToken) {}
}
