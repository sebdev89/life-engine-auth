package com.devito.lifeengine.auth.application;

import com.devito.lifeengine.auth.api.AuthDtos;
import com.devito.lifeengine.auth.infrastructure.config.GoogleLoginOAuthProperties;
import com.devito.lifeengine.auth.infrastructure.bootstrap.SecurityDevSeedSupport;
import com.devito.lifeengine.auth.infrastructure.persistence.BoUserIdentityProviderRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.BoUserIdentityProviderRow;
import com.devito.lifeengine.auth.infrastructure.persistence.BoUserRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.BoUserRow;
import com.devito.lifeengine.auth.oauth.GoogleLoginOAuthClient;
import com.devito.lifeengine.auth.oauth.GoogleOAuthCallbackResult;
import com.devito.lifeengine.auth.oauth.GoogleOAuthIntent;
import com.devito.lifeengine.auth.oauth.GoogleUserInfo;
import com.devito.lifeengine.auth.oauth.PendingGoogleOAuthState;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

/**
 * Google OAuth for BO: anonymous login and authenticated account linking (same callback URI; intent is bound to
 * server-side state).
 */
@Service
public class GoogleOAuthLoginAppService {

    private final GoogleLoginOAuthClient googleOAuth;
    private final GoogleLoginOAuthProperties googleProps;
    private final BoUserRepository users;
    private final BoUserIdentityProviderRepository identityLinks;
    private final R2dbcEntityTemplate entityTemplate;
    private final AuthAppService authAppService;
    private final SecurityAuditService securityAudit;
    private final SecurityStreamNotifier streamNotifier;
    private final SecurityDevSeedSupport seedSupport;

    public GoogleOAuthLoginAppService(
            GoogleLoginOAuthClient googleOAuth,
            GoogleLoginOAuthProperties googleProps,
            BoUserRepository users,
            BoUserIdentityProviderRepository identityLinks,
            R2dbcEntityTemplate entityTemplate,
            AuthAppService authAppService,
            SecurityAuditService securityAudit,
            SecurityStreamNotifier streamNotifier,
            SecurityDevSeedSupport seedSupport) {
        this.googleOAuth = googleOAuth;
        this.googleProps = googleProps;
        this.users = users;
        this.identityLinks = identityLinks;
        this.entityTemplate = entityTemplate;
        this.authAppService = authAppService;
        this.securityAudit = securityAudit;
        this.streamNotifier = streamNotifier;
        this.seedSupport = seedSupport;
    }

    public Mono<GoogleOAuthCallbackResult> handleCallback(
            String code, String state, String oauthError, AuditContext ctx) {
        if (oauthError != null && !oauthError.isBlank()) {
            return auditLoginFailure(null, null, ctx, "oauth_error=" + truncate(oauthError, 200))
                    .then(Mono.error(badRequest("OAuth error: " + oauthError)));
        }
        if (code == null || code.isBlank()) {
            return auditLoginFailure(null, null, ctx, "missing_code")
                    .then(Mono.error(badRequest("Missing authorization code")));
        }
        Optional<PendingGoogleOAuthState> pendingOpt = googleOAuth.validateAndConsumeState(state);
        if (pendingOpt.isEmpty()) {
            return auditLoginFailure(null, null, ctx, "invalid_state")
                    .then(Mono.error(badRequest("Invalid or expired state")));
        }
        PendingGoogleOAuthState pending = pendingOpt.get();
        if (pending.intent() == GoogleOAuthIntent.LINK_GOOGLE) {
            return handleLinkCallback(code, pending, ctx);
        }
        return handleLoginCallback(code, ctx);
    }

    private Mono<GoogleOAuthCallbackResult> handleLoginCallback(String code, AuditContext ctx) {
        return googleOAuth
                .exchangeAuthorizationCode(code)
                .flatMap(googleOAuth::resolveUserInfo)
                .flatMap(ui -> requireVerifiedMono(ui).flatMap(v -> resolveUserAndSessionLogin(v, ctx)))
                .map(this::loginOutcome)
                .onErrorResume(ex -> auditLoginFailureFromThrowable(ex, ctx).then(Mono.error(ex)));
    }

    private GoogleOAuthCallbackResult loginOutcome(AuthDtos.LoginResponse login) {
        String raw = googleProps.getLoginSuccessRedirectUri();
        if (raw != null && !raw.trim().isBlank()) {
            try {
                return new GoogleOAuthCallbackResult.LoginBrowserRedirect(
                        buildLoginBrowserRedirect(URI.create(raw.trim()), login));
            } catch (RuntimeException ex) {
                // Misconfiguration: still return JSON so operators can diagnose from /callback.
                return new GoogleOAuthCallbackResult.LoginTokens(login);
            }
        }
        return new GoogleOAuthCallbackResult.LoginTokens(login);
    }

    /**
     * Sends tokens in the URL <em>fragment</em> so they are not sent to the BO origin as a Referer on subsequent
     * navigations (only the SPA reads {@code location.hash}).
     */
    private static URI buildLoginBrowserRedirect(URI boEntry, AuthDtos.LoginResponse login) {
        validateBrowserRedirect(boEntry);
        String base = boEntry.toString();
        String frag =
                "access_token="
                        + enc(login.accessToken())
                        + "&token_type="
                        + enc(login.tokenType())
                        + "&expires_in="
                        + login.expiresInSeconds()
                        + "&refresh_token="
                        + enc(login.refreshToken())
                        + "&refresh_expires_in="
                        + login.refreshExpiresInSeconds();
        return URI.create(base + "#" + frag);
    }

    private static String enc(String s) {
        return URLEncoder.encode(s == null ? "" : s, StandardCharsets.UTF_8);
    }

    private Mono<GoogleOAuthCallbackResult> handleLinkCallback(
            String code, PendingGoogleOAuthState pending, AuditContext ctx) {
        UUID targetUserId = pending.linkTargetUserId();
        if (targetUserId == null) {
            return auditLinkFailure(null, ctx, "missing_link_user")
                    .then(Mono.error(badRequest("Invalid link state")));
        }
        return googleOAuth
                .exchangeAuthorizationCode(code)
                .flatMap(googleOAuth::resolveUserInfo)
                .flatMap(ui -> requireVerifiedMono(ui).flatMap(v -> completeAccountLink(v, targetUserId, ctx)))
                .onErrorResume(ex -> auditLinkFailure(targetUserId, ctx, throwableDetail(ex)).then(Mono.error(ex)));
    }

    private Mono<GoogleOAuthCallbackResult> completeAccountLink(
            GoogleUserInfo v, UUID targetUserId, AuditContext ctx) {
        String sub = v.sub().trim();
        String googleEmail = v.email().trim().toLowerCase(Locale.ROOT);
        return users.findById(targetUserId)
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND, "user not found")))
                .flatMap(
                        u -> {
                            if (!u.isEnabled()) {
                                return Mono.error(
                                        new ResponseStatusException(HttpStatus.FORBIDDEN, "account_disabled"));
                            }
                            String boEmail = u.getEmail().trim().toLowerCase(Locale.ROOT);
                            if (!googleEmail.equals(boEmail)) {
                                return Mono.error(
                                        new ResponseStatusException(
                                                HttpStatus.FORBIDDEN, "google_email_mismatch_bo_account"));
                            }
                            return identityLinks
                                    .findByProviderAndProviderSubject(
                                            BoUserIdentityProviderRow.PROVIDER_GOOGLE, sub)
                                    .flatMap(
                                            existing ->
                                                    existing.getBoUserId().equals(targetUserId)
                                                            ? Mono.<Void>empty()
                                                            : Mono.error(
                                                                    new ResponseStatusException(
                                                                            HttpStatus.CONFLICT,
                                                                            "google_sub_already_linked_elsewhere")))
                                    .switchIfEmpty(Mono.empty())
                                    .then(upsertGoogleLink(targetUserId, sub, googleEmail))
                                    .then(
                                            securityAudit.record(
                                                    SecurityAuditEventType.GOOGLE_ACCOUNT_LINKED,
                                                    SecurityAuditService.OUTCOME_SUCCESS,
                                                    targetUserId,
                                                    boEmail,
                                                    ctx,
                                                    "provider=google sub=" + truncate(sub, 40)))
                                    .then(
                                            Mono.fromRunnable(
                                                    () ->
                                                            streamNotifier.notifyDomain(
                                                                    "google_account_linked",
                                                                    List.of("users", "audit"),
                                                                    targetUserId,
                                                                    targetUserId,
                                                                    Map.of("provider", "google"))))
                                    .then(Mono.fromCallable(this::buildLinkOutcome));
                        });
    }

    private GoogleOAuthCallbackResult buildLinkOutcome() {
        String raw = googleProps.getLinkSuccessRedirectUri();
        if (raw != null && !raw.trim().isBlank()) {
            URI loc = URI.create(raw.trim());
            validateBrowserRedirect(loc);
            return new GoogleOAuthCallbackResult.LinkedRedirect(loc);
        }
        return new GoogleOAuthCallbackResult.LinkedJson(
                new AuthDtos.GoogleAccountLinkedResponse(true, BoUserIdentityProviderRow.PROVIDER_GOOGLE));
    }

    private static void validateBrowserRedirect(URI loc) {
        String scheme = loc.getScheme();
        if (!"https".equalsIgnoreCase(scheme) && !"http".equalsIgnoreCase(scheme)) {
            throw new IllegalStateException("link_success_redirect_uri must use http or https");
        }
        if (loc.getHost() == null || loc.getHost().isBlank()) {
            throw new IllegalStateException("link_success_redirect_uri must have a host");
        }
    }

    private Mono<AuthDtos.LoginResponse> resolveUserAndSessionLogin(GoogleUserInfo v, AuditContext ctx) {
        String sub = v.sub().trim();
        String email = v.email().trim().toLowerCase(Locale.ROOT);

        return identityLinks
                .findByProviderAndProviderSubject(BoUserIdentityProviderRow.PROVIDER_GOOGLE, sub)
                .flatMap(link -> users.findById(link.getBoUserId()))
                .filter(BoUserRow::isEnabled)
                .flatMap(
                        u -> {
                            if (!u.getEmail().trim().equalsIgnoreCase(email)) {
                                return auditLoginFailure(
                                                u.getId(),
                                                email,
                                                ctx,
                                                "google_email_changed_sub_mismatch_bo_email")
                                        .then(
                                                Mono.error(
                                                        new ResponseStatusException(
                                                                HttpStatus.FORBIDDEN, "google_email_mismatch")));
                            }
                            return upsertGoogleLink(u.getId(), sub, email)
                                    .then(authAppService.issueSessionAfterOAuth(u, ctx));
                        })
                .switchIfEmpty(
                        Mono.defer(
                                () ->
                                        users.findByEmailIgnoreCase(email)
                                                .filter(BoUserRow::isEnabled)
                                                .flatMap(
                                                        u ->
                                                                identityLinks
                                                                        .findByProviderAndProviderSubject(
                                                                                BoUserIdentityProviderRow.PROVIDER_GOOGLE,
                                                                                sub)
                                                                        .flatMap(
                                                                                row ->
                                                                                        row.getBoUserId()
                                                                                                        .equals(
                                                                                                                u.getId())
                                                                                                ? Mono.<Void>empty()
                                                                                                : Mono.error(
                                                                                                        new ResponseStatusException(
                                                                                                                HttpStatus.CONFLICT,
                                                                                                                "google_sub_conflict")))
                                                                        .switchIfEmpty(Mono.empty())
                                                                        .then(upsertGoogleLink(u.getId(), sub, email))
                                                                        .then(
                                                                                authAppService.issueSessionAfterOAuth(
                                                                                        u, ctx)))
                                                .switchIfEmpty(
                                                        Mono.defer(() -> createGoogleOnlyUser(sub, email, ctx)))));
    }

    private Mono<GoogleUserInfo> requireVerifiedMono(GoogleUserInfo ui) {
        try {
            return Mono.just(requireVerifiedGoogleProfile(ui));
        } catch (ResponseStatusException e) {
            return Mono.error(e);
        }
    }

    private static GoogleUserInfo requireVerifiedGoogleProfile(GoogleUserInfo ui) {
        if (ui.sub() == null || ui.sub().isBlank()) {
            throw badRequest("Google userinfo missing sub");
        }
        if (ui.email() == null || ui.email().isBlank()) {
            throw badRequest("Google userinfo missing email");
        }
        if (!Boolean.TRUE.equals(ui.emailVerified())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Google email is not verified; cannot proceed");
        }
        return ui;
    }

    private Mono<Void> upsertGoogleLink(UUID boUserId, String sub, String email) {
        return identityLinks
                .findByBoUserIdAndProvider(boUserId, BoUserIdentityProviderRow.PROVIDER_GOOGLE)
                .flatMap(
                        row -> {
                            row.setProviderSubject(sub);
                            row.setLinkedEmail(email);
                            return identityLinks.save(row);
                        })
                .switchIfEmpty(
                        Mono.defer(
                                () -> {
                                    BoUserIdentityProviderRow row = new BoUserIdentityProviderRow();
                                    row.setId(UUID.randomUUID());
                                    row.setBoUserId(boUserId);
                                    row.setProvider(BoUserIdentityProviderRow.PROVIDER_GOOGLE);
                                    row.setProviderSubject(sub);
                                    row.setLinkedEmail(email);
                                    row.setCreatedAt(Instant.now());
                                    return entityTemplate.insert(row);
                                }))
                .then();
    }

    private Mono<AuthDtos.LoginResponse> createGoogleOnlyUser(String sub, String email, AuditContext ctx) {
        BoUserRow u = new BoUserRow();
        u.setId(UUID.randomUUID());
        u.setEmail(email);
        u.setPasswordHash(null);
        u.setEnabled(true);
        u.setCreatedAt(Instant.now());
        return entityTemplate
                .insert(u)
                .flatMap(
                        saved ->
                                seedSupport
                                        .ensureRoleLinks(saved.getId(), List.of("USER"))
                                        .then(upsertGoogleLink(saved.getId(), sub, email))
                                        .then(authAppService.issueSessionAfterOAuth(saved, ctx)));
    }

    private static ResponseStatusException badRequest(String msg) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, msg);
    }

    private Mono<Void> auditLoginFailure(UUID userId, String emailNorm, AuditContext ctx, String detail) {
        return securityAudit.record(
                SecurityAuditEventType.GOOGLE_LOGIN_FAILURE,
                SecurityAuditService.OUTCOME_FAILURE,
                userId,
                emailNorm,
                ctx,
                detail);
    }

    private Mono<Void> auditLoginFailureFromThrowable(Throwable ex, AuditContext ctx) {
        return auditLoginFailure(null, null, ctx, throwableDetail(ex));
    }

    private Mono<Void> auditLinkFailure(UUID userId, AuditContext ctx, String detail) {
        return securityAudit.record(
                SecurityAuditEventType.GOOGLE_LINK_FAILURE,
                SecurityAuditService.OUTCOME_FAILURE,
                userId,
                null,
                ctx,
                detail);
    }

    private static String throwableDetail(Throwable ex) {
        if (ex instanceof ResponseStatusException r) {
            String reason = r.getReason();
            return r.getStatusCode().value() + ":" + (reason != null ? reason : "");
        }
        return truncate(ex.getMessage() != null ? ex.getMessage() : ex.getClass().getSimpleName(), 400);
    }

    private static String truncate(String s, int max) {
        if (s == null) {
            return "";
        }
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }
}
