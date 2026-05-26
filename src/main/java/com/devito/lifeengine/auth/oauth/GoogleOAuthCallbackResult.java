package com.devito.lifeengine.auth.oauth;

import com.devito.lifeengine.auth.api.AuthDtos;
import java.net.URI;

/** Outcome of {@code GET /api/auth/google/callback} after code exchange. */
public sealed interface GoogleOAuthCallbackResult
        permits GoogleOAuthCallbackResult.LoginTokens,
                GoogleOAuthCallbackResult.LoginBrowserRedirect,
                GoogleOAuthCallbackResult.LinkedRedirect,
                GoogleOAuthCallbackResult.LinkedJson {

    record LoginTokens(AuthDtos.LoginResponse response) implements GoogleOAuthCallbackResult {}

    /** Browser follows redirect; tokens are in the URL fragment for the SPA (not sent to the BO server). */
    record LoginBrowserRedirect(URI location) implements GoogleOAuthCallbackResult {}

    record LinkedRedirect(URI location) implements GoogleOAuthCallbackResult {}

    record LinkedJson(AuthDtos.GoogleAccountLinkedResponse body) implements GoogleOAuthCallbackResult {}
}
