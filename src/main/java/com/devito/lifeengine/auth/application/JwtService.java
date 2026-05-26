package com.devito.lifeengine.auth.application;

import com.devito.lifeengine.auth.domain.BoUserPrincipal;
import com.devito.lifeengine.auth.infrastructure.config.JwtSecurityProperties;
import com.devito.lifeengine.platform.PlatformRoles;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;
import javax.crypto.SecretKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

    private static final Logger log = LoggerFactory.getLogger(JwtService.class);

    /**
     * Result of parsing {@code Authorization} or a raw JWT. {@link #failureReason()} is only present when {@link
     * #principal()} is empty — safe strings for logs (no token contents).
     */
    public record AuthorizationParseOutcome(Optional<BoUserPrincipal> principal, Optional<String> failureReason) {

        public static AuthorizationParseOutcome ok(BoUserPrincipal p) {
            return new AuthorizationParseOutcome(Optional.of(p), Optional.empty());
        }

        public static AuthorizationParseOutcome failed(String reason) {
            return new AuthorizationParseOutcome(Optional.empty(), Optional.of(reason));
        }
    }

    private final JwtSecurityProperties props;
    private final SecretKey key;

    public JwtService(JwtSecurityProperties props, Environment environment) {
        String raw = props.getSecret();
        String secret = raw == null ? "" : raw;
        String appEnv = environment.getProperty("lifeengine.deployment.env", "").trim().toLowerCase();
        boolean strictJwt =
                environment.acceptsProfiles(Profiles.of("prod")) || "prod".equals(appEnv);
        if (strictJwt && secret.isBlank()) {
            throw new IllegalStateException(
                    "JWT_SECRET is required (lifeengine.security.jwt.secret) when APP_ENV is prod or Spring profile 'prod' is active.");
        }
        byte[] bytes = secret.getBytes(StandardCharsets.UTF_8);
        if (bytes.length < 32) {
            throw new IllegalStateException(
                    "lifeengine.security.jwt.secret must be at least 32 UTF-8 bytes for HS256 (activeProfiles="
                            + String.join(",", environment.getActiveProfiles())
                            + ")");
        }
        this.props = props;
        this.key = Keys.hmacShaKeyFor(bytes);
    }

    public String createAccessToken(UUID userId, String email, String appRole) {
        return createAccessToken(userId, email, appRole, List.of(), null);
    }

    public String createAccessToken(UUID userId, String email, String appRole, UUID sessionId) {
        return createAccessToken(userId, email, appRole, List.of(), sessionId);
    }

    /**
     * @param primaryRole application role code stored in {@code role} claim.
     * @param authorities permission codes (Spring authority strings) stored in {@code authorities} claim.
     */
    public String createAccessToken(
            UUID userId, String email, String primaryRole, List<String> authorities, UUID sessionId) {
        Instant now = Instant.now();
        Instant exp = now.plusSeconds(props.getAccessTokenValidityMinutes() * 60L);
        List<String> auths = authorities == null || authorities.isEmpty() ? legacyAuthorities(primaryRole) : authorities;
        var b =
                Jwts.builder()
                        .id(UUID.randomUUID().toString())
                        .subject(userId.toString())
                        .claim("email", email)
                        .claim("role", primaryRole)
                        .claim("authorities", auths)
                        .issuedAt(Date.from(now))
                        .expiration(Date.from(exp));
        if (sessionId != null) {
            b.claim("sid", sessionId.toString());
        }
        return b.signWith(key).compact();
    }

    private static List<String> legacyAuthorities(String primaryRole) {
        String r = primaryRole == null ? "USER" : primaryRole.trim().toUpperCase(Locale.ROOT);
        return List.of(PlatformRoles.toAuthority(r));
    }

    /** Parses a raw JWT string (no {@code Bearer} prefix). */
    public Optional<BoUserPrincipal> parseToken(String rawToken) {
        return parseTokenOutcome(rawToken).principal();
    }

    /**
     * Same as {@link #parseToken(String)} but returns a stable {@code failureReason} when parsing fails (safe for WARN
     * logs).
     */
    @SuppressWarnings("unchecked")
    public AuthorizationParseOutcome parseTokenOutcome(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            return AuthorizationParseOutcome.failed("empty_token");
        }
        try {
            Claims claims =
                    Jwts.parser().verifyWith(key).build().parseSignedClaims(rawToken.trim()).getPayload();
            String sub = claims.getSubject();
            String email = claims.get("email", String.class);
            String role = claims.get("role", String.class);
            if (sub == null || email == null || role == null) {
                jwtParseDiag("missing_required_claims", sub, claims.get("sid", String.class), role, null, 0);
                return AuthorizationParseOutcome.failed("missing_required_claims");
            }
            UUID sessionId = null;
            String sid = claims.get("sid", String.class);
            if (sid != null && !sid.isBlank()) {
                try {
                    sessionId = UUID.fromString(sid.trim());
                } catch (IllegalArgumentException ignored) {
                    jwtParseDiag("sid_not_uuid", sub, sid, role, claims.getId(), 0);
                    return AuthorizationParseOutcome.failed("sid_not_uuid");
                }
            }
            List<String> authorities = new ArrayList<>();
            Object rawAuths = claims.get("authorities");
            if (rawAuths instanceof List<?> list) {
                for (Object o : list) {
                    if (o != null) {
                        authorities.add(o.toString());
                    }
                }
            }
            if (authorities.isEmpty()) {
                authorities.add(PlatformRoles.toAuthority(role));
            }
            UUID userId;
            try {
                userId = UUID.fromString(sub);
            } catch (IllegalArgumentException ignored) {
                jwtParseDiag("sub_not_uuid", sub, sid, role, claims.getId(), authorities.size());
                return AuthorizationParseOutcome.failed("sub_not_uuid");
            }
            jwtParseDiag("ok", userId.toString(), sessionId != null ? sessionId.toString() : null, role, claims.getId(), authorities.size());
            return AuthorizationParseOutcome.ok(new BoUserPrincipal(userId, email, role, List.copyOf(authorities), sessionId));
        } catch (ExpiredJwtException e) {
            jwtParseDiag("expired", e.getClaims() != null ? e.getClaims().getSubject() : null, null, null, null, 0);
            return AuthorizationParseOutcome.failed("expired");
        } catch (SignatureException e) {
            jwtParseDiag("bad_signature", null, null, null, null, 0);
            return AuthorizationParseOutcome.failed("bad_signature");
        } catch (MalformedJwtException e) {
            jwtParseDiag("malformed", null, null, null, null, 0);
            return AuthorizationParseOutcome.failed("malformed");
        } catch (JwtException e) {
            jwtParseDiag("jwt_invalid_" + e.getClass().getSimpleName(), null, null, null, null, 0);
            return AuthorizationParseOutcome.failed("jwt_invalid_" + e.getClass().getSimpleName());
        } catch (Exception e) {
            jwtParseDiag("unexpected_" + e.getClass().getSimpleName(), null, null, null, null, 0);
            return AuthorizationParseOutcome.failed("unexpected_" + e.getClass().getSimpleName());
        }
    }

    /** Temporary local-dev correlation: enable {@code logging.level.com.devito.lifeengine.auth.application.JwtService=DEBUG}. */
    private static void jwtParseDiag(
            String outcome,
            String sub,
            String sid,
            String role,
            String jti,
            int authorityCount) {
        if (!log.isDebugEnabled()) {
            return;
        }
        log.debug(
                "jwt_parse_diag outcome={} sub={} sid={} role={} jti={} authorityCount={}",
                outcome,
                sub,
                sid,
                role,
                jti,
                authorityCount);
    }

    public Optional<BoUserPrincipal> parseAuthorizationHeader(String authorizationHeader) {
        return parseAuthorizationHeaderOutcome(authorizationHeader).principal();
    }

    /**
     * Parses {@code Authorization: Bearer &lt;jwt&gt;}. Failure reasons are safe log labels (never include the token).
     */
    public AuthorizationParseOutcome parseAuthorizationHeaderOutcome(String authorizationHeader) {
        if (authorizationHeader == null || authorizationHeader.isBlank()) {
            return AuthorizationParseOutcome.failed("no_authorization_header");
        }
        if (!authorizationHeader.regionMatches(true, 0, "Bearer ", 0, 7)) {
            if (log.isDebugEnabled()) {
                log.debug(
                        "jwt_parse_diag outcome=no_bearer_prefix headerPresent={}",
                        true);
            }
            return AuthorizationParseOutcome.failed("not_bearer_scheme");
        }
        return parseTokenOutcome(authorizationHeader.substring(7).trim());
    }

    /** Access token {@code exp} claim (requires valid signed JWT). */
    public Optional<Instant> readAccessTokenExpiration(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return Optional.empty();
        }
        String raw = authorizationHeader.substring(7).trim();
        if (raw.isBlank()) {
            return Optional.empty();
        }
        try {
            Claims claims = Jwts.parser().verifyWith(key).build().parseSignedClaims(raw).getPayload();
            Date exp = claims.getExpiration();
            return exp == null ? Optional.empty() : Optional.of(exp.toInstant());
        } catch (Exception ignored) {
            return Optional.empty();
        }
    }
}
