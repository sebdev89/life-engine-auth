package com.devito.lifeengine.auth.application;

import java.time.Duration;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicLong;
import org.springframework.stereotype.Component;

/**
 * Drives adaptive fingerprint polling: recent security-related activity keeps polls in a 2–3s band; after a quiet
 * period, polling backs off to 8–10s. Activity is {@link #touch()}ed from push/domain notifications and when the
 * fingerprint itself detects drift (covers paths that bypass the notifier).
 */
@Component
public class SecurityStreamActivityTracker {

    private static final Duration ACTIVE_MIN = Duration.ofSeconds(2);
    private static final Duration ACTIVE_MAX = Duration.ofSeconds(3);
    private static final Duration IDLE_MIN = Duration.ofSeconds(8);
    private static final Duration IDLE_MAX = Duration.ofSeconds(10);
    /** No {@link #touch()} for this long ⇒ treat as idle (longer poll spacing). */
    private static final Duration IDLE_AFTER = Duration.ofSeconds(45);

    private final AtomicLong lastTouchEpochMs = new AtomicLong(System.currentTimeMillis());

    public void touch() {
        lastTouchEpochMs.set(System.currentTimeMillis());
    }

    /** Delay before the next fingerprint capture; recomputed on every poll. */
    public Duration nextPollDelay() {
        long quietMs = System.currentTimeMillis() - lastTouchEpochMs.get();
        if (quietMs >= IDLE_AFTER.toMillis()) {
            return jitterBetween(IDLE_MIN, IDLE_MAX);
        }
        return jitterBetween(ACTIVE_MIN, ACTIVE_MAX);
    }

    private static Duration jitterBetween(Duration min, Duration max) {
        long a = min.toSeconds();
        long b = max.toSeconds();
        long span = b - a + 1;
        long pick = a + ThreadLocalRandom.current().nextLong(span);
        return Duration.ofSeconds(pick);
    }
}
