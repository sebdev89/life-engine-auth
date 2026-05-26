package com.devito.lifeengine.auth.infrastructure.config;

import com.devito.lifeengine.auth.application.email.NoOpPasswordResetMailSender;
import com.devito.lifeengine.auth.application.email.PasswordResetMailSender;
import com.devito.lifeengine.auth.application.email.ResendPasswordResetMailSender;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class PasswordRecoveryMailConfiguration {

    @Bean
    PasswordResetMailSender passwordResetMailSender(PasswordRecoveryProperties props) {
        if (!props.isResendEmailDeliveryConfigured()) {
            return new NoOpPasswordResetMailSender();
        }
        WebClient client =
                WebClient.builder()
                        .baseUrl("https://api.resend.com")
                        .defaultHeader(HttpHeaders.AUTHORIZATION, "Bearer " + props.getResendApiKey().trim())
                        .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                        .build();
        return new ResendPasswordResetMailSender(client, props.getFromAddress().trim());
    }
}
