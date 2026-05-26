package com.devito.lifeengine.auth.application.email;

import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.HtmlUtils;
import reactor.core.publisher.Mono;

/**
 * Sends password-reset mail via <a href="https://resend.com/docs/api-reference/emails/send-email">Resend HTTP API</a>.
 * Never logs {@code resetUrl}, response bodies, or API errors containing echoed content.
 */
public final class ResendPasswordResetMailSender implements PasswordResetMailSender {

    private static final Logger log = LoggerFactory.getLogger(ResendPasswordResetMailSender.class);

    private final WebClient http;
    private final String fromAddress;

    public ResendPasswordResetMailSender(WebClient resendApiClient, String fromAddress) {
        this.http = resendApiClient;
        this.fromAddress = fromAddress;
    }

    @Override
    public Mono<Void> sendPasswordResetEmail(String toEmail, String resetUrl) {
        String html = buildHtml(resetUrl);
        Map<String, Object> body =
                Map.of(
                        "from",
                        fromAddress,
                        "to",
                        List.of(toEmail),
                        "subject",
                        "Reset your Life Engine password",
                        "html",
                        html);
        return http.post()
                .uri("/emails")
                .bodyValue(body)
                .retrieve()
                .toBodilessEntity()
                .doOnSuccess(
                        r ->
                                log.debug(
                                        "password_reset_email_sent provider=resend status={} to={}",
                                        r.getStatusCode().value(),
                                        maskEmail(toEmail)))
                .then();
    }

    private static String buildHtml(String resetUrl) {
        String href = HtmlUtils.htmlEscape(resetUrl);
        return "<p>You requested a password reset for your Life Engine account.</p>"
                + "<p><a href=\""
                + href
                + "\">Choose a new password</a></p>"
                + "<p>If you did not request this, you can ignore this message.</p>";
    }

    public static String maskEmail(String email) {
        if (email == null || email.isBlank()) {
            return "(blank)";
        }
        int at = email.indexOf('@');
        if (at <= 0) {
            return "***";
        }
        String local = email.substring(0, at);
        String domain = email.substring(at);
        String prefix = local.length() <= 1 ? "*" : local.charAt(0) + "***";
        return prefix + domain;
    }
}
