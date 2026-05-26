package com.devito.lifeengine.logging;

import java.util.regex.Pattern;

final class SensitiveMessageMasker {

    private static final Pattern BEARER = Pattern.compile("(?i)Bearer\\s+\\S+");
    private static final Pattern REFRESH_JSON = Pattern.compile("\"refreshToken\"\\s*:\\s*\"[^\"]*\"");
    private static final Pattern PASSWORD_JSON = Pattern.compile("\"password\"\\s*:\\s*\"[^\"]*\"");
    private static final Pattern ACCESS_JSON = Pattern.compile("\"accessToken\"\\s*:\\s*\"[^\"]*\"");
    private static final Pattern CLIENT_SECRET_JSON = Pattern.compile("\"client_secret\"\\s*:\\s*\"[^\"]*\"");
    private static final Pattern AGENT_SECRET_HDR = Pattern.compile("(?i)(x-agent-secret)\\s*[:=]\\s*\\S+");

    private SensitiveMessageMasker() {}

    static String mask(String message) {
        if (message == null || message.isEmpty()) {
            return message;
        }
        String m = BEARER.matcher(message).replaceAll("Bearer ***");
        m = REFRESH_JSON.matcher(m).replaceAll("\"refreshToken\":\"***\"");
        m = PASSWORD_JSON.matcher(m).replaceAll("\"password\":\"***\"");
        m = ACCESS_JSON.matcher(m).replaceAll("\"accessToken\":\"***\"");
        m = CLIENT_SECRET_JSON.matcher(m).replaceAll("\"client_secret\":\"***\"");
        m = AGENT_SECRET_HDR.matcher(m).replaceAll("$1:***");
        return m;
    }
}
