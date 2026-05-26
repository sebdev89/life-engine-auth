package com.devito.lifeengine.auth.events;

import java.time.Instant;

public record UserRegisteredEvent(
        String userId,
        String email,
        Instant occurredAt
) {}