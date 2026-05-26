package com.devito.lifeengine.auth.infrastructure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class GoogleLoginOAuthClientConfiguration {

    @Bean(name = "googleLoginOAuthTokenWebClient")
    WebClient googleLoginOAuthTokenWebClient(WebClient.Builder builder) {
        return builder.baseUrl("https://oauth2.googleapis.com").build();
    }

    @Bean(name = "googleLoginOAuthApisWebClient")
    WebClient googleLoginOAuthApisWebClient(WebClient.Builder builder) {
        return builder.baseUrl("https://www.googleapis.com").build();
    }
}
