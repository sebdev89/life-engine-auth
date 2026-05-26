package com.devito.lifeengine.auth.application.email;

import reactor.core.publisher.Mono;

/** Outbound password-reset email (e.g. Resend). Implementations must not log reset URLs or raw tokens. */
public interface PasswordResetMailSender {

    Mono<Void> sendPasswordResetEmail(String toEmail, String resetUrl);
}
