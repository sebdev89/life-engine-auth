package com.devito.lifeengine.auth.application;

import com.devito.lifeengine.auth.api.AuthDtos;
import com.devito.lifeengine.auth.infrastructure.config.DevPasswordResetProperties;
import com.devito.lifeengine.auth.infrastructure.persistence.BoUserRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.RefreshTokenRepository;
import java.time.Instant;
import java.util.Locale;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

/** Non-production: set password by email + revoke all refresh rows (deterministic E2E recovery). */
@Service
public class LocalDevPasswordResetAppService {

    private static final Logger log = LoggerFactory.getLogger(LocalDevPasswordResetAppService.class);

    public static final String HEADER_DEV_RESET_KEY = "X-Life-Engine-Dev-Password-Reset-Key";

    private final DevPasswordResetProperties props;
    private final BoUserRepository users;
    private final RefreshTokenRepository refreshTokens;
    private final PasswordEncoder passwordEncoder;
    private final SecurityAuditService securityAudit;

    public LocalDevPasswordResetAppService(
            DevPasswordResetProperties props,
            BoUserRepository users,
            RefreshTokenRepository refreshTokens,
            PasswordEncoder passwordEncoder,
            SecurityAuditService securityAudit) {
        this.props = props;
        this.users = users;
        this.refreshTokens = refreshTokens;
        this.passwordEncoder = passwordEncoder;
        this.securityAudit = securityAudit;
    }

    public Mono<AuthDtos.DevPasswordResetResponse> resetIfAuthorized(
            String presentedApiKey, String email, String newPassword, AuditContext ctx) {
        if (!props.isEnabled()) {
            return Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND, "dev_password_reset_disabled"));
        }
        String expected = props.getApiKey() == null ? "" : props.getApiKey().trim();
        if (!StringUtils.hasText(expected)) {
            return Mono.error(new ResponseStatusException(HttpStatus.FORBIDDEN, "dev_password_reset_api_key_unset"));
        }
        if (!expected.equals(trimToEmpty(presentedApiKey))) {
            log.warn("dev_password_reset rejected: bad_api_key ip={}", ctx.ip());
            return Mono.error(new ResponseStatusException(HttpStatus.FORBIDDEN, "bad_api_key"));
        }
        String em = email == null ? "" : email.trim().toLowerCase(Locale.ROOT);
        if (em.isEmpty()) {
            return Mono.just(new AuthDtos.DevPasswordResetResponse(false, "email_required"));
        }
        if (newPassword == null || newPassword.isBlank()) {
            return Mono.just(new AuthDtos.DevPasswordResetResponse(false, "new_password_required"));
        }
        if (newPassword.length() > PasswordPolicy.MAX_LENGTH) {
            return Mono.just(new AuthDtos.DevPasswordResetResponse(false, "password_too_long"));
        }
        if (!props.isRelaxPasswordPolicy()) {
            try {
                PasswordPolicy.validate(newPassword, em);
            } catch (Exception e) {
                return Mono.just(new AuthDtos.DevPasswordResetResponse(false, "policy: " + e.getMessage()));
            }
        }
        return users.findByEmailIgnoreCase(em)
                .flatMap(
                        u ->
                                refreshTokens
                                        .revokeAllActiveForBoUser(u.getId())
                                        .then(
                                                Mono.defer(
                                                        () -> {
                                                            u.setPasswordHash(passwordEncoder.encode(newPassword));
                                                            u.setPasswordChangedAt(Instant.now());
                                                            u.setFailedLoginAttempts(0);
                                                            u.setLockedUntil(null);
                                                            u.setLocked(false);
                                                            u.setEnabled(true);
                                                            return users.save(u);
                                                        }))
                                        .flatMap(
                                                saved ->
                                                        securityAudit
                                                                .record(
                                                                        SecurityAuditEventType
                                                                                .DEV_PASSWORD_RESET_APPLIED,
                                                                        SecurityAuditService.OUTCOME_SUCCESS,
                                                                        saved.getId(),
                                                                        saved.getEmail(),
                                                                        ctx,
                                                                        "dev_reset")
                                                                .thenReturn(
                                                                        new AuthDtos.DevPasswordResetResponse(
                                                                                true,
                                                                                "password_updated_sessions_revoked"))))
                .switchIfEmpty(Mono.just(new AuthDtos.DevPasswordResetResponse(false, "user_not_found")));
    }

    private static String trimToEmpty(String s) {
        return s == null ? "" : s.trim();
    }
}
