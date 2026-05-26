package com.devito.lifeengine.auth.infrastructure.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "lifeengine.security.google-login")
public class GoogleLoginOAuthProperties {

    private String clientId = "";
    private String clientSecret = "";
    /** Must match a redirect URI registered for the OAuth client in Google Cloud Console. */
    private String redirectUri = "http://localhost:8080/api/auth/google/callback";

    /** Space-separated scopes (openid email profile is enough for sub + email). */
    private String scopes = "openid email profile";

    /**
     * After successful Google <em>account linking</em>, redirect the browser here (BO URL). Empty = return JSON
     * {@link com.devito.lifeengine.auth.api.AuthDtos.GoogleAccountLinkedResponse} from the callback instead.
     */
    private String linkSuccessRedirectUri = "";

    /**
     * After successful Google <em>login</em> (anonymous OAuth), redirect the browser here with tokens in the URL
     * fragment ({@code access_token}, {@code refresh_token}, …) so the SPA can persist the session. Empty = return
     * JSON {@link com.devito.lifeengine.auth.api.AuthDtos.LoginResponse} from {@code /api/auth/google/callback}
     * (API clients / curl only).
     */
    private String loginSuccessRedirectUri = "";

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getScopes() {
        return scopes;
    }

    public void setScopes(String scopes) {
        this.scopes = scopes;
    }

    public boolean isConfigured() {
        return clientId != null
                && !clientId.isBlank()
                && clientSecret != null
                && !clientSecret.isBlank()
                && redirectUri != null
                && !redirectUri.isBlank();
    }

    public String getLinkSuccessRedirectUri() {
        return linkSuccessRedirectUri;
    }

    public void setLinkSuccessRedirectUri(String linkSuccessRedirectUri) {
        this.linkSuccessRedirectUri = linkSuccessRedirectUri;
    }

    public String getLoginSuccessRedirectUri() {
        return loginSuccessRedirectUri;
    }

    public void setLoginSuccessRedirectUri(String loginSuccessRedirectUri) {
        this.loginSuccessRedirectUri = loginSuccessRedirectUri;
    }
}
