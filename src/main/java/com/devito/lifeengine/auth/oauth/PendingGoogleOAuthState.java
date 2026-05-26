package com.devito.lifeengine.auth.oauth;

import java.util.UUID;

/** Server-side CSRF state for Google OAuth (login or link). */
public record PendingGoogleOAuthState(long expiresAtMillis, GoogleOAuthIntent intent, UUID linkTargetUserId) {

    public boolean expired() {
        return expiresAtMillis < System.currentTimeMillis();
    }
}
