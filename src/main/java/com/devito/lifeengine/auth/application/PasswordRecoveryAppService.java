package com.devito.lifeengine.auth.application;

import com.devito.lifeengine.auth.application.email.PasswordResetMailSender;
import com.devito.lifeengine.auth.application.email.ResendPasswordResetMailSender;
import com.devito.lifeengine.auth.infrastructure.config.PasswordRecoveryProperties;
import com.devito.lifeengine.auth.infrastructure.persistence.BoUserRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.BoUserRow;
import com.devito.lifeengine.auth.infrastructure.persistence.PasswordResetTokenRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.PasswordResetTokenRow;
import com.devito.lifeengine.auth.infrastructure.persistence.RefreshTokenRepository;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Locale;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

@Service
public class PasswordRecoveryAppService {

    private static final Logger log = LoggerFactory.getLogger(PasswordRecoveryAppService.class);
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int TOKEN_VALID_HOURS = 2;

    private final BoUserRepository users;
    private final PasswordResetTokenRepository resetTokens;
    private final RefreshTokenRepository refreshTokens;
    private final PasswordEncoder passwordEncoder;
    private final SecurityAuditService securityAudit;
    private final R2dbcEntityTemplate entityTemplate;
    private final PasswordRecoveryProperties recoveryProperties;
    private final PasswordResetMailSender passwordResetMailSender;

    public PasswordRecoveryAppService(
            BoUserRepository users,
            PasswordResetTokenRepository resetTokens,
            RefreshTokenRepository refreshTokens,
            PasswordEncoder passwordEncoder,
            SecurityAuditService securityAudit,
            R2dbcEntityTemplate entityTemplate,
            PasswordRecoveryProperties recoveryProperties,
            PasswordResetMailSender passwordResetMailSender) {
        this.users = users;
        this.resetTokens = resetTokens;
        this.refreshTokens = refreshTokens;
        this.passwordEncoder = passwordEncoder;
        this.securityAudit = securityAudit;
        this.entityTemplate = entityTemplate;
        this.recoveryProperties = recoveryProperties;
        this.passwordResetMailSender = passwordResetMailSender;
    }

    /**
     * Timing-padded. Emits plaintext reset token only when {@link
     * PasswordRecoveryProperties#isExposeTokenForTesting()} is true and a matching enabled user exists.
     */
    public Mono<String> requestReset(String email, AuditContext ctx) {
        String norm = email.trim().toLowerCase(Locale.ROOT);
        boolean expose = recoveryProperties.isExposeTokenForTesting();
        return Mono.delay(Duration.ofMillis(40L + SECURE_RANDOM.nextInt(120)))
                .then(
                        users.findByEmailIgnoreCase(norm)
                                .filter(BoUserRow::isEnabled)
                                .flatMap(
                                        u -> {
                                            PasswordResetTokenRow row = new PasswordResetTokenRow();
                                            row.setId(java.util.UUID.randomUUID());
                                            row.setBoUserId(u.getId());
                                            byte[] raw = new byte[32];
                                            SECURE_RANDOM.nextBytes(raw);
                                            String opaque =
                                                    Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
                                            row.setTokenHash(RefreshTokenHasher.sha256Hex(opaque));
                                            row.setExpiresAt(
                                                    Instant.now().plus(TOKEN_VALID_HOURS, ChronoUnit.HOURS));
                                            row.setCreatedAt(Instant.now());
                                            row.setRequestIp(ctx != null ? ctx.ip() : null);
                                            String resetLink = buildResetLink(opaque);
                                            return entityTemplate
                                                    .insert(row)
                                                    .then(
                                                            securityAudit.record(
                                                                    SecurityAuditEventType.PASSWORD_RESET_REQUESTED,
                                                                    SecurityAuditService.OUTCOME_SUCCESS,
                                                                    u.getId(),
                                                                    norm,
                                                                    ctx,
                                                                    "expires_hours=" + TOKEN_VALID_HOURS))
                                                    .then(sendPasswordResetEmail(norm, resetLink))
                                                    .then(
                                                            Mono.defer(
                                                                    () ->
                                                                            expose
                                                                                    ? Mono.just(opaque)
                                                                                    : Mono.empty()));
                                        })
                                .switchIfEmpty(Mono.empty()));
    }

    private String buildResetLink(String opaque) {
        String base = recoveryProperties.getResetLinkBaseUrl().trim().replaceAll("/+$", "");
        return UriComponentsBuilder.fromUriString(base)
                .path("/auth/reset-password")
                .queryParam("token", opaque)
                .build(true)
                .toUriString();
    }

    /**
     * Sends reset mail when Resend is configured. Failures are logged without token/URL and do not fail the HTTP flow
     * (token remains valid).
     */
    private Mono<Void> sendPasswordResetEmail(String toEmail, String resetLink) {
        return passwordResetMailSender
                .sendPasswordResetEmail(toEmail, resetLink)
                .doOnError(
                        e ->
                                log.warn(
                                        "password_reset_email_dispatch_failed to={} type={}",
                                        ResendPasswordResetMailSender.maskEmail(toEmail),
                                        e.getClass().getSimpleName()))
                .onErrorResume(e -> Mono.empty());
    }

    public Mono<Void> completeReset(String rawToken, String newPassword, AuditContext ctx) {
        if (rawToken == null || rawToken.isBlank()) {
            return Mono.error(new ResponseStatusException(HttpStatus.BAD_REQUEST, "token required"));
        }
        String hash = RefreshTokenHasher.sha256Hex(rawToken.trim());
        return resetTokens
                .findActiveByTokenHash(hash)
                .switchIfEmpty(
                        Mono.defer(
                                () ->
                                        Mono.error(
                                                new ResponseStatusException(
                                                        HttpStatus.UNAUTHORIZED, "invalid_or_expired_token"))))
                .flatMap(
                        token ->
                                users.findById(token.getBoUserId())
                                        .switchIfEmpty(
                                                Mono.error(
                                                        new ResponseStatusException(
                                                                HttpStatus.UNAUTHORIZED, "invalid_or_expired_token")))
                                        .flatMap(
                                                u -> {
                                                    PasswordPolicy.validate(newPassword, u.getEmail());
                                                    u.setPasswordHash(passwordEncoder.encode(newPassword));
                                                    u.setPasswordChangedAt(Instant.now());
                                                    u.setFailedLoginAttempts(0);
                                                    u.setLockedUntil(null);
                                                    token.setUsedAt(Instant.now());
                                                    return refreshTokens
                                                            .findByBoUserId(u.getId())
                                                            .filter(r -> !r.isRevoked())
                                                            .concatMap(
                                                                    r -> {
                                                                        r.setRevoked(true);
                                                                        return refreshTokens.save(r);
                                                                    })
                                                            .then(users.save(u))
                                                            .then(resetTokens.save(token))
                                                            .then(
                                                                    securityAudit.record(
                                                                            SecurityAuditEventType
                                                                                    .PASSWORD_RESET_COMPLETED,
                                                                            SecurityAuditService.OUTCOME_SUCCESS,
                                                                            u.getId(),
                                                                            u.getEmail(),
                                                                            ctx,
                                                                            null));
                                                }));
    }
}
