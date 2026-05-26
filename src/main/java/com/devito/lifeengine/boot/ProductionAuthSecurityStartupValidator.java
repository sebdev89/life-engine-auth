package com.devito.lifeengine.boot;

import com.devito.lifeengine.auth.infrastructure.config.DevPasswordResetProperties;
import com.devito.lifeengine.auth.infrastructure.config.GuestAuthProperties;
import com.devito.lifeengine.auth.infrastructure.config.PasswordRecoveryProperties;
import jakarta.annotation.PostConstruct;
import java.util.Locale;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Fails fast when production-equivalent runtime ({@code lifeengine.deployment.env=prod} or Spring {@code prod}
 * profile) would violate the rules in {@code docs/security/auth-security-prod-runbook.md}.
 */
@Component
@Profile("!test")
public class ProductionAuthSecurityStartupValidator {

    private final Environment environment;
    private final PasswordRecoveryProperties passwordRecovery;
    private final GuestAuthProperties guestAuth;
    private final DevPasswordResetProperties devPasswordReset;

    // Phase-1 extraction note (life-engine-auth):
    // AgentRuntimeProperties lived in modules/agent-runtime and the original validator also enforced
    // `grpc-insecure-local-enabled=false` and `internal-secret` presence for prod. Those invariants belong
    // to the agent-runtime/dev-agent transport (gRPC), not to identity. They are deliberately not
    // re-validated here; agent-runtime will keep enforcing them when extracted next.
    public ProductionAuthSecurityStartupValidator(
            Environment environment,
            PasswordRecoveryProperties passwordRecovery,
            GuestAuthProperties guestAuth,
            DevPasswordResetProperties devPasswordReset) {
        this.environment = environment;
        this.passwordRecovery = passwordRecovery;
        this.guestAuth = guestAuth;
        this.devPasswordReset = devPasswordReset;
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
        if (passwordRecovery.isExposeTokenForTesting()) {
            throw new IllegalStateException(
                    "lifeengine.security.password-reset.expose-token-for-testing must be false in production "
                            + "(env PASSWORD_RESET_DEBUG_TOKEN / runbook).");
        }
        if (devPasswordReset.isEnabled()) {
            throw new IllegalStateException(
                    "lifeengine.security.dev-password-reset.enabled must be false in production "
                            + "(POST /api/dev-auth/reset-password must never be exposed).");
        }
        if (StringUtils.hasText(passwordRecovery.getResendApiKey())
                && !StringUtils.hasText(passwordRecovery.getFromAddress())) {
            throw new IllegalStateException(
                    "RESEND_API_KEY is set but RESEND_FROM / lifeengine.security.password-reset.from-address is blank "
                            + "(Resend requires a from address).");
        }
        if (guestAuth.isEnabled()) {
            throw new IllegalStateException(
                    "lifeengine.security.guest.enabled must be false in production unless explicitly risk-accepted "
                            + "(env GUEST_AUTH_ENABLED / runbook).");
        }
        // Phase-1 extraction note (life-engine-auth):
        // Original checks for `lifeengine.agents.grpc-insecure-local-enabled=false` and
        // `lifeengine.agents.internal-secret` not blank lived here because identity + agent-runtime
        // shared one JVM. They will move to life-engine-runtime when extracted.
    }

    private boolean isProductionRuntime() {
        if (environment.acceptsProfiles(Profiles.of("prod"))) {
            return true;
        }
        String appEnv = environment.getProperty("lifeengine.deployment.env", "").trim().toLowerCase(Locale.ROOT);
        return "prod".equals(appEnv);
    }
}
