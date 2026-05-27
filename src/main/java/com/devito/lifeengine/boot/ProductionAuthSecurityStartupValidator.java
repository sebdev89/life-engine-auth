package com.devito.lifeengine.boot;

import com.devito.lifeengine.auth.infrastructure.config.AdminSeedProperties;
import com.devito.lifeengine.auth.infrastructure.config.DevPasswordResetProperties;
import com.devito.lifeengine.auth.infrastructure.config.GuestAuthProperties;
import com.devito.lifeengine.auth.infrastructure.config.JwtSecurityProperties;
import com.devito.lifeengine.auth.infrastructure.config.LocalDevOperatorSeedProperties;
import com.devito.lifeengine.auth.infrastructure.config.LocalDevPasswordRotationSeedProperties;
import com.devito.lifeengine.auth.infrastructure.config.LocalDevRegistrationProperties;
import com.devito.lifeengine.auth.infrastructure.config.PasswordRecoveryProperties;
import jakarta.annotation.PostConstruct;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Fails fast when production-equivalent runtime ({@code lifeengine.deployment.env=prod} or Spring {@code prod}
 * profile) would violate the rules in {@code docs/security/auth-security-prod-runbook.md}.
 *
 * <p>Invariants enforced in prod:
 * <ul>
 *   <li>{@code JWT_SECRET} present and {@code >= 32} UTF-8 bytes (HS256 minimum).</li>
 *   <li>CORS allow-list ({@code lifeengine.http.cors.allowed-origins}) is non-empty unless explicitly
 *       opted out via {@code lifeengine.http.cors.prod-allow-empty=true} (intentional and audited).</li>
 *   <li>Local dev registration ({@code lifeengine.security.local-dev-registration.enabled}) is off.</li>
 *   <li>Local dev operator seed ({@code lifeengine.security.local-dev-operator-seed.enabled}) is off.</li>
 *   <li>Local dev password-rotation seed
 *       ({@code lifeengine.security.local-dev-password-rotation-seed.enabled}) is off.</li>
 *   <li>Admin seed ({@code lifeengine.security.admin-seed.enabled}) is off unless explicitly allowed
 *       for first-bootstrap via {@code lifeengine.security.admin-seed.allow-in-prod=true}.</li>
 *   <li>Dev password reset ({@code lifeengine.security.dev-password-reset.enabled}) is off.</li>
 *   <li>Password reset token exposure ({@code lifeengine.security.password-reset.expose-token-for-testing})
 *       is off.</li>
 *   <li>Guest login ({@code lifeengine.security.guest.enabled}) is off.</li>
 * </ul>
 *
 * <p>Local/dev/test contexts are unaffected — these are all opt-out checks gated on {@link #isProductionRuntime()}.
 */
@Component
@Profile("!test")
public class ProductionAuthSecurityStartupValidator {

    /** Minimum HS256 secret length in bytes. Matches the HS256 RFC 7518 SHOULD requirement. */
    static final int MIN_JWT_SECRET_BYTES = 32;

    private final Environment environment;
    private final JwtSecurityProperties jwtSecurity;
    private final PasswordRecoveryProperties passwordRecovery;
    private final GuestAuthProperties guestAuth;
    private final DevPasswordResetProperties devPasswordReset;
    private final AdminSeedProperties adminSeed;
    private final LocalDevOperatorSeedProperties localDevOperatorSeed;
    private final LocalDevPasswordRotationSeedProperties localDevPasswordRotationSeed;
    private final LocalDevRegistrationProperties localDevRegistration;

    public ProductionAuthSecurityStartupValidator(
            Environment environment,
            JwtSecurityProperties jwtSecurity,
            PasswordRecoveryProperties passwordRecovery,
            GuestAuthProperties guestAuth,
            DevPasswordResetProperties devPasswordReset,
            AdminSeedProperties adminSeed,
            LocalDevOperatorSeedProperties localDevOperatorSeed,
            LocalDevPasswordRotationSeedProperties localDevPasswordRotationSeed,
            LocalDevRegistrationProperties localDevRegistration) {
        this.environment = environment;
        this.jwtSecurity = jwtSecurity;
        this.passwordRecovery = passwordRecovery;
        this.guestAuth = guestAuth;
        this.devPasswordReset = devPasswordReset;
        this.adminSeed = adminSeed;
        this.localDevOperatorSeed = localDevOperatorSeed;
        this.localDevPasswordRotationSeed = localDevPasswordRotationSeed;
        this.localDevRegistration = localDevRegistration;
    }

    @PostConstruct
    void validateProductionInvariants() {
        if (!isProductionRuntime()) {
            return;
        }
        if (environment.acceptsProfiles(Profiles.of("ci"))) {
            throw new IllegalStateException(
                    "Spring profile 'ci' must not be active in production (see docs/security/auth-security-prod-runbook.md).");
        }

        validateJwtSecret();
        validateCorsAllowList();

        if (localDevRegistration.isEnabled()) {
            throw new IllegalStateException(
                    "lifeengine.security.local-dev-registration.enabled must be false in production "
                            + "(POST /api/auth/dev/register is non-prod tooling).");
        }
        if (localDevOperatorSeed.isEnabled()) {
            throw new IllegalStateException(
                    "lifeengine.security.local-dev-operator-seed.enabled must be false in production "
                            + "(deterministic e2e operator must never be seeded in prod).");
        }
        if (localDevPasswordRotationSeed.isEnabled()) {
            throw new IllegalStateException(
                    "lifeengine.security.local-dev-password-rotation-seed.enabled must be false in production "
                            + "(destructive password-change e2e operator must never be seeded in prod).");
        }
        if (adminSeed.isEnabled() && !isAdminSeedExplicitlyAllowedInProd()) {
            throw new IllegalStateException(
                    "lifeengine.security.admin-seed.enabled must be false in production unless "
                            + "lifeengine.security.admin-seed.allow-in-prod=true is set for a one-time bootstrap "
                            + "(see docs/security/auth-security-prod-runbook.md).");
        }
        if (devPasswordReset.isEnabled()) {
            throw new IllegalStateException(
                    "lifeengine.security.dev-password-reset.enabled must be false in production "
                            + "(POST /api/dev-auth/reset-password must never be exposed).");
        }
        if (passwordRecovery.isExposeTokenForTesting()) {
            throw new IllegalStateException(
                    "lifeengine.security.password-reset.expose-token-for-testing must be false in production "
                            + "(env PASSWORD_RESET_DEBUG_TOKEN / runbook).");
        }
        if (guestAuth.isEnabled()) {
            throw new IllegalStateException(
                    "lifeengine.security.guest.enabled must be false in production unless explicitly risk-accepted "
                            + "(env GUEST_AUTH_ENABLED / runbook).");
        }

        if (StringUtils.hasText(passwordRecovery.getResendApiKey())
                && !StringUtils.hasText(passwordRecovery.getFromAddress())) {
            throw new IllegalStateException(
                    "RESEND_API_KEY is set but RESEND_FROM / lifeengine.security.password-reset.from-address is blank "
                            + "(Resend requires a from address).");
        }
    }

    private void validateJwtSecret() {
        String secret = jwtSecurity.getSecret();
        if (!StringUtils.hasText(secret)) {
            throw new IllegalStateException(
                    "lifeengine.security.jwt.secret (env JWT_SECRET) is required in production.");
        }
        int bytes = secret.getBytes(StandardCharsets.UTF_8).length;
        if (bytes < MIN_JWT_SECRET_BYTES) {
            throw new IllegalStateException(
                    "lifeengine.security.jwt.secret must be at least "
                            + MIN_JWT_SECRET_BYTES
                            + " UTF-8 bytes in production (HS256 minimum); got "
                            + bytes
                            + " bytes.");
        }
    }

    private void validateCorsAllowList() {
        String raw = environment.getProperty("lifeengine.http.cors.allowed-origins", "").trim();
        if (raw.isEmpty() && !isCorsEmptyAllowed()) {
            throw new IllegalStateException(
                    "lifeengine.http.cors.allowed-origins is required in production. "
                            + "Set LIFEENGINE_HTTP_CORS_ALLOWED_ORIGINS to a comma-separated allow-list, "
                            + "or set lifeengine.http.cors.prod-allow-empty=true to explicitly opt out "
                            + "(documented in docs/security/auth-security-prod-runbook.md).");
        }
    }

    private boolean isCorsEmptyAllowed() {
        return Boolean.parseBoolean(environment.getProperty("lifeengine.http.cors.prod-allow-empty", "false"));
    }

    private boolean isAdminSeedExplicitlyAllowedInProd() {
        return Boolean.parseBoolean(environment.getProperty("lifeengine.security.admin-seed.allow-in-prod", "false"));
    }

    private boolean isProductionRuntime() {
        if (environment.acceptsProfiles(Profiles.of("prod"))) {
            return true;
        }
        String appEnv = environment.getProperty("lifeengine.deployment.env", "").trim().toLowerCase(Locale.ROOT);
        return "prod".equals(appEnv);
    }
}
