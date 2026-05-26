package com.devito.lifeengine.auth.infrastructure.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.r2dbc.repository.config.EnableR2dbcRepositories;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableConfigurationProperties({
    JwtSecurityProperties.class,
    GoogleLoginOAuthProperties.class,
    LoginSecurityProperties.class,
    GuestAuthProperties.class,
    PasswordRecoveryProperties.class,
    AdminSeedProperties.class,
    LocalDevOperatorSeedProperties.class,
    LocalDevPasswordRotationSeedProperties.class,
    LocalDevRegistrationProperties.class,
    DevPasswordResetProperties.class
})
@EnableR2dbcRepositories(basePackages = "com.devito.lifeengine.auth.infrastructure.persistence")
public class AuthSecurityBeansConfiguration {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
