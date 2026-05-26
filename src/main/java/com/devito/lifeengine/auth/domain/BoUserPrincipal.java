package com.devito.lifeengine.auth.domain;

import java.util.List;
import java.util.UUID;

/**
 * Principal stored in {@link org.springframework.security.core.Authentication} after JWT validation.
 *
 * @param primaryRole application role code (e.g. ADMIN) for display / legacy clients.
 * @param authorities effective permission codes (union of RBAC); used as Spring authorities.
 * @param sessionId optional {@code refresh_token.session_id} (claim {@code sid}).
 */
public record BoUserPrincipal(
        UUID userId, String email, String primaryRole, List<String> authorities, UUID sessionId) {}
