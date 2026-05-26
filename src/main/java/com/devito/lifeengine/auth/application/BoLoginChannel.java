package com.devito.lifeengine.auth.application;

/** How a BO refresh-backed session was established (audit + observability). */
public enum BoLoginChannel {
    PASSWORD,
    OAUTH_GOOGLE
}
