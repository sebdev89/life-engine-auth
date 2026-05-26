package com.devito.lifeengine.auth.oauth;

import com.devito.lifeengine.auth.infrastructure.config.GoogleLoginOAuthProperties;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

/**
 * Google OAuth 2.0 authorization-code flow for BO login (separate redirect URI and state from mailbox
 * OAuth in the email-agent module).
 */
@Service
public class GoogleLoginOAuthClient {

    private static final Logger log = LoggerFactory.getLogger(GoogleLoginOAuthClient.class);
    private static final String AUTH_BASE = "https://accounts.google.com/o/oauth2/v2/auth";
    private static final String TOKEN_PATH = "/token";

    private final GoogleLoginOAuthProperties props;
    private final WebClient tokenWebClient;
    private final WebClient apisWebClient;
    private final ConcurrentHashMap<String, PendingGoogleOAuthState> pendingStates = new ConcurrentHashMap<>();

    public GoogleLoginOAuthClient(
            GoogleLoginOAuthProperties props,
            @Qualifier("googleLoginOAuthTokenWebClient") WebClient tokenWebClient,
            @Qualifier("googleLoginOAuthApisWebClient") WebClient apisWebClient) {
        this.props = props;
        this.tokenWebClient = tokenWebClient;
        this.apisWebClient = apisWebClient;
    }

    public boolean isConfigured() {
        return props.isConfigured();
    }

    public String createAuthorizationUrl() {
        return createAuthorizationUrl(GoogleOAuthIntent.LOGIN, null);
    }

    /**
     * @param linkTargetUserId required when {@code intent} is {@link GoogleOAuthIntent#LINK_GOOGLE}; must be the
     *     authenticated BO user id that initiated linking (stored server-side, never from the OAuth callback).
     */
    public String createAuthorizationUrl(GoogleOAuthIntent intent, UUID linkTargetUserId) {
        if (!props.isConfigured()) {
            throw new IllegalStateException("Google login OAuth is not configured (client-id / secret / redirect-uri)");
        }
        if (intent == GoogleOAuthIntent.LINK_GOOGLE && linkTargetUserId == null) {
            throw new IllegalArgumentException("linkTargetUserId required for LINK_GOOGLE");
        }
        String state = UUID.randomUUID().toString();
        long exp = System.currentTimeMillis() + 10 * 60_000L;
        pendingStates.put(
                state,
                new PendingGoogleOAuthState(
                        exp, intent, intent == GoogleOAuthIntent.LINK_GOOGLE ? linkTargetUserId : null));
        log.info("auth-google-oauth: issued state={} intent={}", state, intent);

        String scope = URLEncoder.encode(props.getScopes().trim(), StandardCharsets.UTF_8);
        String redirect = URLEncoder.encode(props.getRedirectUri(), StandardCharsets.UTF_8);
        return AUTH_BASE
                + "?client_id="
                + URLEncoder.encode(props.getClientId(), StandardCharsets.UTF_8)
                + "&redirect_uri="
                + redirect
                + "&response_type=code&scope="
                + scope
                + "&access_type=offline&prompt=select_account&state="
                + URLEncoder.encode(state, StandardCharsets.UTF_8);
    }

    public Optional<PendingGoogleOAuthState> validateAndConsumeState(String state) {
        if (state == null || state.isBlank()) {
            log.warn("auth-google-oauth: callback missing state");
            return Optional.empty();
        }
        PendingGoogleOAuthState pending = pendingStates.remove(state);
        if (pending == null) {
            log.warn("auth-google-oauth: state not found or already consumed");
            return Optional.empty();
        }
        if (pending.expired()) {
            log.warn("auth-google-oauth: state expired");
            return Optional.empty();
        }
        return Optional.of(pending);
    }

    public Mono<GoogleTokenResponse> exchangeAuthorizationCode(String code) {
        if (!props.isConfigured()) {
            return Mono.error(new IllegalStateException("OAuth not configured"));
        }
        log.info("auth-google-oauth: exchanging authorization code");

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("code", code);
        form.add("client_id", props.getClientId());
        form.add("client_secret", props.getClientSecret());
        form.add("redirect_uri", props.getRedirectUri());
        form.add("grant_type", "authorization_code");

        return tokenWebClient
                .post()
                .uri(TOKEN_PATH)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData(form))
                .exchangeToMono(
                        resp -> {
                            if (resp.statusCode().is2xxSuccessful()) {
                                return resp.bodyToMono(GoogleTokenResponse.class);
                            }
                            return resp.bodyToMono(String.class)
                                    .defaultIfEmpty("")
                                    .flatMap(
                                            body -> {
                                                log.error(
                                                        "auth-google-oauth: token HTTP {} body={}",
                                                        resp.statusCode().value(),
                                                        truncate(body, 800));
                                                return Mono.error(
                                                        new IllegalStateException(
                                                                "Google token "
                                                                        + resp.statusCode().value()
                                                                        + ": "
                                                                        + truncate(body, 400)));
                                            });
                        })
                .onErrorMap(
                        WebClientResponseException.class,
                        ex -> {
                            String body = ex.getResponseBodyAsString(StandardCharsets.UTF_8);
                            log.error(
                                    "auth-google-oauth: token WebClientResponseException status={} body={}",
                                    ex.getStatusCode().value(),
                                    truncate(body, 800));
                            return new IllegalStateException(
                                    "Google token "
                                            + ex.getStatusCode().value()
                                            + ": "
                                            + truncate(body, 400));
                        });
    }

    public Mono<GoogleUserInfo> fetchUserInfo(String accessToken) {
        if (accessToken == null || accessToken.isBlank()) {
            return Mono.error(new IllegalStateException("Missing access_token for userinfo"));
        }
        return apisWebClient
                .get()
                .uri("/oauth2/v3/userinfo")
                .headers(h -> h.setBearerAuth(accessToken))
                .retrieve()
                .bodyToMono(GoogleUserInfo.class)
                .doOnNext(
                        ui ->
                                log.info(
                                        "auth-google-oauth: userinfo sub present={} email present={}",
                                        ui.sub() != null && !ui.sub().isBlank(),
                                        ui.email() != null && !ui.email().isBlank()))
                .onErrorMap(
                        WebClientResponseException.class,
                        ex -> {
                            String body = ex.getResponseBodyAsString(StandardCharsets.UTF_8);
                            log.error(
                                    "auth-google-oauth: userinfo HTTP {} body={}",
                                    ex.getStatusCode().value(),
                                    truncate(body, 600));
                            return new IllegalStateException(
                                    "Google userinfo " + ex.getStatusCode().value() + ": " + truncate(body, 300));
                        });
    }

    /** Resolves userinfo; if email is missing, returns empty. */
    public Mono<GoogleUserInfo> resolveUserInfo(GoogleTokenResponse tr) {
        if (tr.accessToken() == null || tr.accessToken().isBlank()) {
            return Mono.error(new IllegalStateException("Google did not return access_token"));
        }
        return fetchUserInfo(tr.accessToken());
    }

    private static String truncate(String s, int max) {
        if (s == null) {
            return "";
        }
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }
}
