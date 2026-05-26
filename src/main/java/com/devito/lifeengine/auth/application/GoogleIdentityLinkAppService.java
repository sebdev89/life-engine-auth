package com.devito.lifeengine.auth.application;

import com.devito.lifeengine.auth.api.AuthDtos;
import com.devito.lifeengine.auth.domain.BoUserPrincipal;
import com.devito.lifeengine.auth.infrastructure.config.GoogleLoginOAuthProperties;
import com.devito.lifeengine.auth.infrastructure.persistence.BoUserIdentityProviderRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.BoUserIdentityProviderRow;
import com.devito.lifeengine.auth.infrastructure.persistence.BoUserRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.BoUserRow;
import com.devito.lifeengine.auth.oauth.GoogleLoginOAuthClient;
import com.devito.lifeengine.auth.oauth.GoogleOAuthIntent;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

@Service
public class GoogleIdentityLinkAppService {

    private final GoogleLoginOAuthClient googleOAuth;
    private final GoogleLoginOAuthProperties props;
    private final BoUserRepository users;
    private final BoUserIdentityProviderRepository identityLinks;
    private final SecurityAuditService securityAudit;
    private final SecurityStreamNotifier streamNotifier;

    public GoogleIdentityLinkAppService(
            GoogleLoginOAuthClient googleOAuth,
            GoogleLoginOAuthProperties props,
            BoUserRepository users,
            BoUserIdentityProviderRepository identityLinks,
            SecurityAuditService securityAudit,
            SecurityStreamNotifier streamNotifier) {
        this.googleOAuth = googleOAuth;
        this.props = props;
        this.users = users;
        this.identityLinks = identityLinks;
        this.securityAudit = securityAudit;
        this.streamNotifier = streamNotifier;
    }

    public Mono<AuthDtos.GoogleLinkStartResponse> startGoogleLink(BoUserPrincipal principal) {
        if (!props.isConfigured()) {
            return Mono.error(new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "google_oauth_not_configured"));
        }
        if ("GUEST".equalsIgnoreCase(principal.primaryRole())) {
            return Mono.error(new ResponseStatusException(HttpStatus.FORBIDDEN, "guest_cannot_link_google"));
        }
        return identityLinks
                .countByBoUserIdAndProvider(principal.userId(), BoUserIdentityProviderRow.PROVIDER_GOOGLE)
                .flatMap(
                        c -> {
                            if (c != null && c > 0) {
                                return Mono.error(
                                        new ResponseStatusException(HttpStatus.CONFLICT, "google_already_linked"));
                            }
                            String url =
                                    googleOAuth.createAuthorizationUrl(
                                            GoogleOAuthIntent.LINK_GOOGLE, principal.userId());
                            return Mono.just(new AuthDtos.GoogleLinkStartResponse(url));
                        });
    }

    public Mono<Void> unlinkGoogle(BoUserPrincipal principal, AuditContext ctx) {
        if ("GUEST".equalsIgnoreCase(principal.primaryRole())) {
            return Mono.error(new ResponseStatusException(HttpStatus.FORBIDDEN, "guest_cannot_unlink_google"));
        }
        UUID uid = principal.userId();
        return users
                .findById(uid)
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND)))
                .flatMap(
                        u -> {
                            boolean password =
                                    u.getPasswordHash() != null && !u.getPasswordHash().isBlank();
                            if (!password) {
                                return Mono.error(
                                        new ResponseStatusException(
                                                HttpStatus.CONFLICT,
                                                "cannot_unlink_google_without_local_password"));
                            }
                            return identityLinks
                                    .countByBoUserIdAndProvider(uid, BoUserIdentityProviderRow.PROVIDER_GOOGLE)
                                    .flatMap(
                                            c -> {
                                                if (c == null || c == 0) {
                                                    return Mono.error(
                                                            new ResponseStatusException(
                                                                    HttpStatus.NOT_FOUND, "google_not_linked"));
                                                }
                                                return identityLinks
                                                        .deleteByBoUserIdAndProvider(
                                                                uid, BoUserIdentityProviderRow.PROVIDER_GOOGLE)
                                                        .then(
                                                                securityAudit.record(
                                                                        SecurityAuditEventType.GOOGLE_ACCOUNT_UNLINKED,
                                                                        SecurityAuditService.OUTCOME_SUCCESS,
                                                                        uid,
                                                                        principal.email().trim().toLowerCase(Locale.ROOT),
                                                                        ctx,
                                                                        "provider=google"))
                                                        .then(
                                                                Mono.fromRunnable(
                                                                        () ->
                                                                                streamNotifier.notifyDomain(
                                                                                        "google_account_unlinked",
                                                                                        List.of("users", "audit"),
                                                                                        uid,
                                                                                        uid,
                                                                                        java.util.Map.of(
                                                                                                "provider", "google"))))
                                                        .then();
                                            });
                        });
    }
}
