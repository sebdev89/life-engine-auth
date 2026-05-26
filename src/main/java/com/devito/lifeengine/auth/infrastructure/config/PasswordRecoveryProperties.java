package com.devito.lifeengine.auth.infrastructure.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.StringUtils;

/**
 * Password recovery: token persistence, optional {@code resetToken} in JSON for local tests only, and optional Resend
 * email delivery. Never enable {@code exposeTokenForTesting} in production.
 */
@ConfigurationProperties(prefix = "lifeengine.security.password-reset")
public class PasswordRecoveryProperties {

    /** When true, {@code POST /api/auth/password/forgot} may include {@code resetToken} in JSON (local/CI only). */
    private boolean exposeTokenForTesting = false;

    /**
     * Resend API key ({@code RESEND_API_KEY}). When blank together with {@link #fromAddress}, outbound email is
     * skipped (NoOp sender).
     */
    private String resendApiKey = "";

    /**
     * {@code From} header for Resend, e.g. {@code Life Engine <noreply@yourdomain.com>} (must match a verified domain
     * or Resend onboarding address for trials).
     */
    private String fromAddress = "";

    /**
     * Public BO base URL used to build reset links ({@code …/auth/reset-password?token=…}). No trailing slash required.
     */
    private String resetLinkBaseUrl = "http://localhost:4200";

    public boolean isExposeTokenForTesting() {
        return exposeTokenForTesting;
    }

    public void setExposeTokenForTesting(boolean exposeTokenForTesting) {
        this.exposeTokenForTesting = exposeTokenForTesting;
    }

    public String getResendApiKey() {
        return resendApiKey;
    }

    public void setResendApiKey(String resendApiKey) {
        this.resendApiKey = resendApiKey == null ? "" : resendApiKey;
    }

    public String getFromAddress() {
        return fromAddress;
    }

    public void setFromAddress(String fromAddress) {
        this.fromAddress = fromAddress == null ? "" : fromAddress;
    }

    public String getResetLinkBaseUrl() {
        return resetLinkBaseUrl;
    }

    public void setResetLinkBaseUrl(String resetLinkBaseUrl) {
        this.resetLinkBaseUrl =
                resetLinkBaseUrl == null || resetLinkBaseUrl.isBlank()
                        ? "http://localhost:4200"
                        : resetLinkBaseUrl;
    }

    /** True when Resend API + from are both set so password-reset emails can be sent. */
    public boolean isResendEmailDeliveryConfigured() {
        return StringUtils.hasText(resendApiKey) && StringUtils.hasText(fromAddress);
    }
}
