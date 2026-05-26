package com.devito.lifeengine.auth.oauth;

/** Authorization-code flow entry: anonymous login vs authenticated account linking. */
public enum GoogleOAuthIntent {
    LOGIN,
    LINK_GOOGLE
}
