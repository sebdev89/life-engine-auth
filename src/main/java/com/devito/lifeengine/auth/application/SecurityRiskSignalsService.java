package com.devito.lifeengine.auth.application;

import com.devito.lifeengine.auth.application.SecurityRiskExplanationFormatter.RiskNarrative;
import com.devito.lifeengine.auth.application.SecurityRiskComputation.SecurityRiskSummary;
import com.devito.lifeengine.auth.application.SecurityRiskComputation.SessionRiskView;
import com.devito.lifeengine.auth.application.SecurityRiskComputation.UserRiskView;
import com.devito.lifeengine.auth.infrastructure.persistence.RefreshTokenRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.RefreshTokenRow;
import com.devito.lifeengine.auth.infrastructure.persistence.SecurityAuditRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.SecurityAuditRow;
import com.devito.lifeengine.auth.infrastructure.persistence.BoUserRepository;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * Heuristic risk scoring using {@link RefreshTokenRow#getSessionId()} as the stable operator session (one
 * login/OAuth); rotation rows share the same {@code session_id}. Known IP/UA history uses one fingerprint
 * per prior session (first token row in each chain), not every rotated row.
 *
 * <p>Signals: never-seen IP / UA for that BO user before this session started, multiple concurrent active
 * sessions, and repeated failed password attempts (24h) by email. Levels combine into SAFE / UNUSUAL /
 * SUSPICIOUS.
 */
@Service
public class SecurityRiskSignalsService {

    private static final int AUDIT_LOOKBACK_DAYS = 90;
    private static final int FAILURE_WINDOW_HOURS = 24;
    private static final int FAILURES_UNUSUAL = 3;
    private static final int FAILURES_SUSPICIOUS = 5;
    private static final int SESSIONS_UNUSUAL = 2;
    private static final int SESSIONS_SUSPICIOUS = 3;

    private final RefreshTokenRepository refreshTokens;
    private final SecurityAuditRepository audit;
    private final BoUserRepository users;

    public SecurityRiskSignalsService(
            RefreshTokenRepository refreshTokens, SecurityAuditRepository audit, BoUserRepository users) {
        this.refreshTokens = refreshTokens;
        this.audit = audit;
        this.users = users;
    }

    public Mono<SecurityRiskComputation> compute() {
        return refreshTokens
                .findActiveSessionsLatestPerSession()
                .collectList()
                .flatMap(this::computeForActiveSessions);
    }

    /** Public so {@link SecurityControlPlaneAppService} can score the same session list without a second DB pass. */
    public Mono<SecurityRiskComputation> computeForActiveSessions(List<RefreshTokenRow> activeSessions) {
        if (activeSessions.isEmpty()) {
            return Mono.just(
                    new SecurityRiskComputation(
                            Map.of(),
                            Map.of(),
                            Map.of(),
                            Map.of(),
                            new SecurityRiskSummary(0, 0, 0)));
        }
        List<UUID> userIds =
                activeSessions.stream()
                        .map(RefreshTokenRow::getBoUserId)
                        .filter(Objects::nonNull)
                        .distinct()
                        .toList();
        Instant auditSince = Instant.now().minus(AUDIT_LOOKBACK_DAYS, ChronoUnit.DAYS);
        Instant failuresSince = Instant.now().minus(FAILURE_WINDOW_HOURS, ChronoUnit.HOURS);

        Mono<Map<UUID, List<RefreshTokenRow>>> historyMono =
                userIds.isEmpty()
                        ? Mono.just(Map.of())
                        : refreshTokens
                                .findByBoUserIdIn(userIds)
                                .collectMultimap(RefreshTokenRow::getBoUserId)
                                .map(
                                        m -> {
                                            Map<UUID, List<RefreshTokenRow>> out = new HashMap<>();
                                            m.forEach((k, v) -> out.put(k, new ArrayList<>(v)));
                                            return out;
                                        });

        Mono<Map<UUID, List<SecurityAuditRow>>> auditMono =
                userIds.isEmpty()
                        ? Mono.just(Map.of())
                        : audit.findByUserIdInAndCreatedAtAfter(userIds, auditSince)
                                .filter(a -> a.getUserId() != null)
                                .collectMultimap(SecurityAuditRow::getUserId)
                                .map(
                                        m -> {
                                            Map<UUID, List<SecurityAuditRow>> out = new HashMap<>();
                                            m.forEach((k, v) -> out.put(k, new ArrayList<>(v)));
                                            return out;
                                        });

        Mono<Map<String, Long>> failuresByEmailMono =
                audit.findLoginFailuresSince(failuresSince)
                        .collectList()
                        .map(
                                rows -> {
                                    Map<String, Long> counts = new HashMap<>();
                                    for (SecurityAuditRow r : rows) {
                                        if (r.getEmail() == null || r.getEmail().isBlank()) {
                                            continue;
                                        }
                                        String key = r.getEmail().trim().toLowerCase(Locale.ROOT);
                                        counts.merge(key, 1L, Long::sum);
                                    }
                                    return counts;
                                });

        Mono<Map<UUID, String>> emailByUserIdMono =
                userIds.isEmpty()
                        ? Mono.just(Map.of())
                        : reactor.core.publisher.Flux.fromIterable(userIds)
                                .concatMap(
                                        id ->
                                                users.findById(id)
                                                        .map(
                                                                u ->
                                                                        Map.entry(
                                                                                id,
                                                                                u.getEmail()
                                                                                        .trim()
                                                                                        .toLowerCase(
                                                                                                Locale
                                                                                                        .ROOT))))
                                .collectMap(Map.Entry::getKey, Map.Entry::getValue);

        return Mono.zip(historyMono, auditMono, failuresByEmailMono, emailByUserIdMono)
                .map(
                        t -> {
                            Map<UUID, List<RefreshTokenRow>> historyByUser = t.getT1();
                            Map<UUID, List<SecurityAuditRow>> auditByUser = t.getT2();
                            Map<String, Long> failuresByEmailRaw = t.getT3();
                            Map<UUID, String> emailByUserId = t.getT4();

                            Map<String, Integer> failuresByEmailInt = new HashMap<>();
                            failuresByEmailRaw.forEach(
                                    (k, v) ->
                                            failuresByEmailInt.put(
                                                    k,
                                                    v == null
                                                            ? 0
                                                            : Math.toIntExact(Math.min(v, Integer.MAX_VALUE))));

                            List<RefreshTokenRow> allTokensForSessionStarts = new ArrayList<>(activeSessions);
                            for (List<RefreshTokenRow> list : historyByUser.values()) {
                                allTokensForSessionStarts.addAll(list);
                            }
                            Map<UUID, Instant> sessionStartedAt =
                                    earliestCreatedAtPerSession(allTokensForSessionStarts);

                            Map<UUID, Long> activeCountByUser =
                                    activeSessions.stream()
                                            .map(RefreshTokenRow::getBoUserId)
                                            .filter(Objects::nonNull)
                                            .collect(
                                                    Collectors.groupingBy(
                                                            java.util.function.Function.identity(),
                                                            Collectors.counting()));

                            Map<UUID, SessionRiskView> sessionRisks = new HashMap<>();
                            for (RefreshTokenRow s : activeSessions) {
                                UUID sid = s.getSessionId();
                                if (sid == null) {
                                    continue;
                                }
                                if (s.getBoUserId() == null) {
                                    RiskNarrative g = SecurityRiskExplanationFormatter.forGuestSession();
                                    sessionRisks.put(
                                            sid,
                                            new SessionRiskView(
                                                    SecurityRiskLevel.SAFE,
                                                    List.of(),
                                                    g.summary(),
                                                    g.explanation()));
                                    continue;
                                }
                                UUID uid = s.getBoUserId();
                                List<RefreshTokenRow> hist =
                                        historyByUser.getOrDefault(uid, List.of());
                                List<SecurityAuditRow> aud =
                                        auditByUser.getOrDefault(uid, List.of());

                                Instant currentSessionStart =
                                        sessionStartedAt.getOrDefault(sid, s.getCreatedAt());

                                Set<String> knownIps = new HashSet<>();
                                Set<String> knownUas = new HashSet<>();
                                Map<UUID, RefreshTokenRow> firstRowPerOtherSession =
                                        firstRowPerSession(hist);
                                for (Map.Entry<UUID, RefreshTokenRow> e :
                                        firstRowPerOtherSession.entrySet()) {
                                    if (e.getKey().equals(sid)) {
                                        continue;
                                    }
                                    Instant otherStart =
                                            sessionStartedAt.getOrDefault(
                                                    e.getKey(), e.getValue().getCreatedAt());
                                    if (currentSessionStart != null
                                            && otherStart.isBefore(currentSessionStart)) {
                                        addIp(knownIps, e.getValue().getClientIp());
                                        addUa(knownUas, e.getValue().getClientUserAgent());
                                    }
                                }
                                for (SecurityAuditRow a : aud) {
                                    if (a.getCreatedAt() != null
                                            && currentSessionStart != null
                                            && a.getCreatedAt().isBefore(currentSessionStart)) {
                                        addIp(knownIps, a.getIp());
                                        addUa(knownUas, a.getUserAgent());
                                    }
                                }

                                String curIp = normalizeIp(s.getClientIp());
                                String curUa = normalizeUa(s.getClientUserAgent());

                                List<String> signals = new ArrayList<>();
                                if (curIp != null && !knownIps.contains(curIp)) {
                                    signals.add(SecurityRiskLevel.SIGNAL_NEW_IP);
                                }
                                if (curUa != null && !knownUas.contains(curUa)) {
                                    signals.add(SecurityRiskLevel.SIGNAL_NEW_USER_AGENT);
                                }
                                long act = activeCountByUser.getOrDefault(uid, 0L);
                                if (act >= SESSIONS_UNUSUAL) {
                                    signals.add(SecurityRiskLevel.SIGNAL_MULTIPLE_SESSIONS);
                                }

                                String email = emailByUserId.get(uid);
                                int failures =
                                        email == null
                                                ? 0
                                                : failuresByEmailInt.getOrDefault(email, 0);
                                if (failures >= FAILURES_UNUSUAL) {
                                    signals.add(SecurityRiskLevel.SIGNAL_FAILED_LOGINS);
                                }

                                String level =
                                        classifySession(
                                                signals,
                                                act,
                                                failures);
                                RiskNarrative sessionNar =
                                        SecurityRiskExplanationFormatter.forSession(
                                                level, List.copyOf(signals), act, failures);
                                sessionRisks.put(
                                        sid,
                                        new SessionRiskView(
                                                level,
                                                List.copyOf(signals),
                                                sessionNar.summary(),
                                                sessionNar.explanation()));
                            }

                            Map<UUID, UserRiskView> userRisks = new HashMap<>();
                            for (UUID uid : userIds) {
                                String email = emailByUserId.get(uid);
                                int failures =
                                        email == null
                                                ? 0
                                                : failuresByEmailInt.getOrDefault(email, 0);
                                int active = activeCountByUser.getOrDefault(uid, 0L).intValue();

                                String worst = SecurityRiskLevel.SAFE;
                                List<String> agg = new ArrayList<>();
                                for (RefreshTokenRow s : activeSessions) {
                                    if (uid.equals(s.getBoUserId()) && s.getSessionId() != null) {
                                        SessionRiskView v = sessionRisks.get(s.getSessionId());
                                        if (v != null) {
                                            worst = maxLevel(worst, v.riskLevel());
                                            for (String sig : v.signals()) {
                                                if (!agg.contains(sig)) {
                                                    agg.add(sig);
                                                }
                                            }
                                        }
                                    }
                                }
                                if (failures >= FAILURES_SUSPICIOUS) {
                                    worst = SecurityRiskLevel.SUSPICIOUS;
                                    if (!agg.contains(SecurityRiskLevel.SIGNAL_FAILED_LOGINS)) {
                                        agg.add(SecurityRiskLevel.SIGNAL_FAILED_LOGINS);
                                    }
                                } else if (failures >= FAILURES_UNUSUAL
                                        && SecurityRiskLevel.SAFE.equals(worst)) {
                                    worst = SecurityRiskLevel.UNUSUAL;
                                }

                                RiskNarrative userNar =
                                        SecurityRiskExplanationFormatter.forUser(
                                                worst, List.copyOf(agg), active, failures);
                                userRisks.put(
                                        uid,
                                        new UserRiskView(
                                                worst,
                                                List.copyOf(agg),
                                                active,
                                                failures,
                                                userNar.summary(),
                                                userNar.explanation()));
                            }

                            int susp =
                                    (int)
                                            sessionRisks.values().stream()
                                                    .filter(
                                                            v ->
                                                                    SecurityRiskLevel.SUSPICIOUS.equals(
                                                                            v.riskLevel()))
                                                    .count();
                            int unusual =
                                    (int)
                                            sessionRisks.values().stream()
                                                    .filter(
                                                            v ->
                                                                    SecurityRiskLevel.UNUSUAL.equals(
                                                                            v.riskLevel()))
                                                    .count();
                            int safe =
                                    (int)
                                            sessionRisks.values().stream()
                                                    .filter(
                                                            v ->
                                                                    SecurityRiskLevel.SAFE.equals(
                                                                            v.riskLevel()))
                                                    .count();
                            return new SecurityRiskComputation(
                                    Map.copyOf(sessionRisks),
                                    Map.copyOf(userRisks),
                                    Map.copyOf(failuresByEmailInt),
                                    Map.copyOf(sessionStartedAt),
                                    new SecurityRiskSummary(susp, unusual, safe));
                        });
    }

    private static String classifySession(List<String> signals, long activeSessions, int failures) {
        boolean newIp = signals.contains(SecurityRiskLevel.SIGNAL_NEW_IP);
        boolean newUa = signals.contains(SecurityRiskLevel.SIGNAL_NEW_USER_AGENT);
        boolean multi = activeSessions >= SESSIONS_UNUSUAL;
        boolean manyFails = failures >= FAILURES_UNUSUAL;

        if (failures >= FAILURES_SUSPICIOUS
                || activeSessions >= SESSIONS_SUSPICIOUS
                || (newIp && newUa)
                || (newIp && multi)
                || (newUa && multi)) {
            return SecurityRiskLevel.SUSPICIOUS;
        }
        if (newIp || newUa || multi || manyFails) {
            return SecurityRiskLevel.UNUSUAL;
        }
        return SecurityRiskLevel.SAFE;
    }

    private static String maxLevel(String a, String b) {
        int sa = score(a);
        int sb = score(b);
        return sa >= sb ? a : b;
    }

    private static int score(String level) {
        if (SecurityRiskLevel.SUSPICIOUS.equals(level)) {
            return 2;
        }
        if (SecurityRiskLevel.UNUSUAL.equals(level)) {
            return 1;
        }
        return 0;
    }

    private static void addIp(Set<String> set, String ip) {
        String n = normalizeIp(ip);
        if (n != null) {
            set.add(n);
        }
    }

    private static void addUa(Set<String> set, String ua) {
        String n = normalizeUa(ua);
        if (n != null) {
            set.add(n);
        }
    }

    private static String normalizeIp(String ip) {
        if (ip == null || ip.isBlank() || "—".equals(ip.trim())) {
            return null;
        }
        return ip.trim();
    }

    private static String normalizeUa(String ua) {
        if (ua == null || ua.isBlank() || "—".equals(ua.trim())) {
            return null;
        }
        return ua.trim();
    }

    /** Earliest {@code created_at} per {@code session_id} (login boundary for the chain). */
    static Map<UUID, Instant> earliestCreatedAtPerSession(List<RefreshTokenRow> rows) {
        Map<UUID, Instant> m = new HashMap<>();
        for (RefreshTokenRow r : rows) {
            if (r.getSessionId() == null || r.getCreatedAt() == null) {
                continue;
            }
            m.merge(
                    r.getSessionId(),
                    r.getCreatedAt(),
                    (a, b) -> a.isBefore(b) ? a : b);
        }
        return m;
    }

    /** One row per session — the first token issued in the rotation chain (for stable IP/UA history). */
    static Map<UUID, RefreshTokenRow> firstRowPerSession(List<RefreshTokenRow> rows) {
        Map<UUID, RefreshTokenRow> m = new HashMap<>();
        for (RefreshTokenRow r : rows) {
            if (r.getSessionId() == null || r.getCreatedAt() == null) {
                continue;
            }
            m.merge(
                    r.getSessionId(),
                    r,
                    (a, b) -> a.getCreatedAt().isBefore(b.getCreatedAt()) ? a : b);
        }
        return m;
    }
}
