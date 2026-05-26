package com.devito.lifeengine.auth.api;

import com.devito.lifeengine.auth.application.AuditContext;
import com.devito.lifeengine.auth.application.GoogleOAuthLoginAppService;
import com.devito.lifeengine.auth.infrastructure.config.GoogleLoginOAuthProperties;
import com.devito.lifeengine.auth.oauth.GoogleLoginOAuthClient;
import com.devito.lifeengine.auth.oauth.GoogleOAuthCallbackResult;
import java.net.URI;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/auth/google")
public class GoogleAuthController {

    private final GoogleLoginOAuthProperties props;
    private final GoogleLoginOAuthClient oauthClient;
    private final GoogleOAuthLoginAppService oauthLogin;

    public GoogleAuthController(
            GoogleLoginOAuthProperties props,
            GoogleLoginOAuthClient oauthClient,
            GoogleOAuthLoginAppService oauthLogin) {
        this.props = props;
        this.oauthClient = oauthClient;
        this.oauthLogin = oauthLogin;
    }

    @GetMapping("/status")
    public Mono<AuthDtos.GoogleOAuthStatusResponse> status() {
        boolean id = props.getClientId() != null && !props.getClientId().isBlank();
        boolean secret = props.getClientSecret() != null && !props.getClientSecret().isBlank();
        boolean redir = props.getRedirectUri() != null && !props.getRedirectUri().isBlank();
        boolean linkRedir =
                props.getLinkSuccessRedirectUri() != null && !props.getLinkSuccessRedirectUri().isBlank();
        boolean loginRedir =
                props.getLoginSuccessRedirectUri() != null && !props.getLoginSuccessRedirectUri().isBlank();
        return Mono.just(
                new AuthDtos.GoogleOAuthStatusResponse(
                        props.isConfigured(), id, secret, redir, linkRedir, loginRedir));
    }

    @GetMapping("/authorize")
    public Mono<Void> authorize(ServerWebExchange exchange) {
        if (!props.isConfigured()) {
            exchange.getResponse().setStatusCode(HttpStatus.SERVICE_UNAVAILABLE);
            return exchange.getResponse().setComplete();
        }
        String url = oauthClient.createAuthorizationUrl();
        exchange.getResponse().setStatusCode(HttpStatus.FOUND);
        exchange.getResponse().getHeaders().setLocation(URI.create(url));
        return exchange.getResponse().setComplete();
    }

    /**
     * Google redirects here with {@code code} and {@code state}. For login intent: same JSON as {@code POST
     * /api/auth/login}. For account-link intent: 302 to configured BO URL or JSON {@link
     * AuthDtos.GoogleAccountLinkedResponse}.
     */
    @GetMapping("/callback")
    public Mono<ResponseEntity<Object>> callback(
            @RequestParam(name = "code", required = false) String code,
            @RequestParam(name = "state", required = false) String state,
            @RequestParam(name = "error", required = false) String error,
            ServerWebExchange exchange) {
        return oauthLogin
                .handleCallback(code, state, error, AuditContext.from(exchange))
                .map(GoogleAuthController::toResponse);
    }

    private static ResponseEntity<Object> toResponse(GoogleOAuthCallbackResult r) {
        return switch (r) {
            case GoogleOAuthCallbackResult.LoginTokens lt ->
                    ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(lt.response());
            case GoogleOAuthCallbackResult.LoginBrowserRedirect lr ->
                    ResponseEntity.status(HttpStatus.FOUND).location(lr.location()).build();
            case GoogleOAuthCallbackResult.LinkedRedirect lr ->
                    ResponseEntity.status(HttpStatus.FOUND).location(lr.location()).build();
            case GoogleOAuthCallbackResult.LinkedJson lj ->
                    ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(lj.body());
        };
    }
}
