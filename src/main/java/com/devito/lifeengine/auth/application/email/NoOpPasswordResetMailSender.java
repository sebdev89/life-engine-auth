package com.devito.lifeengine.auth.application.email;

import reactor.core.publisher.Mono;

/** Used when Resend is not configured (no API key / no from). Forgot-reset still persists token for dev-only JSON exposure. */
public final class NoOpPasswordResetMailSender implements PasswordResetMailSender {

    @Override
    public Mono<Void> sendPasswordResetEmail(String toEmail, String resetUrl) {
        return Mono.empty();
    }
}
