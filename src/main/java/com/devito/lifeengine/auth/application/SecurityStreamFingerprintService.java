package com.devito.lifeengine.auth.application;

import com.devito.lifeengine.auth.api.SecurityStreamEventDto;
import com.devito.lifeengine.auth.application.SecurityRiskComputation.SecurityRiskSummary;
import com.devito.lifeengine.auth.infrastructure.persistence.RefreshTokenRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.SecurityAuditRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Detects DB changes for sessions/tokens/audit without instrumenting every write path: compares a compact
 * fingerprint on an adaptive schedule and emits which logical surfaces changed.
 */
@Service
public class SecurityStreamFingerprintService {

    private final SecurityAuditRepository audit;
    private final RefreshTokenRepository refreshTokens;
    private final SecurityRiskSignalsService riskSignals;
    private final SecurityStreamActivityTracker activity;
    private final AtomicReference<Fingerprint> last = new AtomicReference<>();
    private final AtomicReference<SecurityRiskSummary> lastRiskSummary = new AtomicReference<>();

    public SecurityStreamFingerprintService(
            SecurityAuditRepository audit,
            RefreshTokenRepository refreshTokens,
            SecurityRiskSignalsService riskSignals,
            SecurityStreamActivityTracker activity) {
        this.audit = audit;
        this.refreshTokens = refreshTokens;
        this.riskSignals = riskSignals;
        this.activity = activity;
    }

    public Flux<SecurityStreamEventDto> watchChanges() {
        return Mono.defer(() -> Mono.delay(activity.nextPollDelay()).thenReturn(0L))
                .repeat()
                .concatMap(
                        tick ->
                                capture()
                                        .flatMapMany(
                                                fp -> {
                                                    Fingerprint prev = last.get();
                                                    if (prev == null) {
                                                        last.set(fp);
                                                        return Flux.empty();
                                                    }
                                                    if (prev.equals(fp)) {
                                                        return Flux.empty();
                                                    }
                                                    activity.touch();
                                                    last.set(fp);
                                                    List<String> surfaces = diffSurfaces(prev, fp);
                                                    if (surfaces.isEmpty()) {
                                                        return Flux.empty();
                                                    }
                                                    SecurityRiskSummary prevRisk = lastRiskSummary.get();
                                                    return riskSignals
                                                            .compute()
                                                            .flatMapMany(
                                                                    comp -> {
                                                                        SecurityRiskSummary cur =
                                                                                comp.summary();
                                                                        lastRiskSummary.set(cur);
                                                                        var snapshot =
                                                                                new SecurityStreamEventDto(
                                                                                        1,
                                                                                        "snapshot",
                                                                                        surfaces,
                                                                                        null,
                                                                                        null,
                                                                                        null,
                                                                                        Instant.now(),
                                                                                        null,
                                                                                        null);
                                                                        if (prevRisk != null
                                                                                && !prevRisk.equals(cur)) {
                                                                            return Flux.just(
                                                                                    snapshot,
                                                                                    riskChanged(cur));
                                                                        }
                                                                        return Flux.just(snapshot);
                                                                    });
                                                }));
    }

    private static SecurityStreamEventDto riskChanged(SecurityRiskSummary s) {
        return new SecurityStreamEventDto(
                1,
                "risk_changed",
                List.of("risk", "users", "sessions"),
                null,
                null,
                Map.of(
                        "suspiciousSessions",
                        s.suspiciousSessions(),
                        "unusualSessions",
                        s.unusualSessions(),
                        "safeSessions",
                        s.safeSessions()),
                Instant.now(),
                null,
                null);
    }

    private Mono<Fingerprint> capture() {
        return Mono.zip(
                        audit.findMaxId(),
                        refreshTokens.countActiveDistinctSessions(),
                        refreshTokens.countActiveRefreshRows())
                .map(t -> new Fingerprint(t.getT1(), t.getT2(), t.getT3()));
    }

    private static List<String> diffSurfaces(Fingerprint prev, Fingerprint next) {
        Set<String> out = new LinkedHashSet<>();
        if (!Objects.equals(prev.maxAuditId(), next.maxAuditId())) {
            out.add("audit");
            out.add("risk");
        }
        if (!Objects.equals(prev.activeDistinctSessions(), next.activeDistinctSessions())
                || !Objects.equals(prev.activeRefreshRows(), next.activeRefreshRows())) {
            out.add("sessions");
            out.add("tokens");
            out.add("users");
            out.add("risk");
        }
        return new ArrayList<>(out);
    }

    private record Fingerprint(Long maxAuditId, Long activeDistinctSessions, Long activeRefreshRows) {}
}
