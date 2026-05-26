package com.devito.lifeengine.auth.application;

import com.devito.lifeengine.auth.infrastructure.persistence.RefreshTokenRepository;
import java.time.Duration;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class AuthActiveSessionsGaugeUpdater {

    private final RefreshTokenRepository refreshTokens;
    private final AuthMetricsRecorder metrics;

    public AuthActiveSessionsGaugeUpdater(RefreshTokenRepository refreshTokens, AuthMetricsRecorder metrics) {
        this.refreshTokens = refreshTokens;
        this.metrics = metrics;
    }

    @Scheduled(fixedDelayString = "${lifeengine.observability.auth-sessions-gauge-ms:30000}")
    public void refreshGauge() {
        Long c = refreshTokens.countActiveDistinctSessions().block(Duration.ofSeconds(8));
        if (c != null) {
            metrics.setActiveSessionsGauge(c);
        }
    }
}
