package com.devito.lifeengine.auth.application;

import java.util.Locale;
import java.util.regex.Pattern;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

/** Production-oriented password rules for BO self-service and recovery. */
public final class PasswordPolicy {

    public static final int MIN_LENGTH = 12;
    public static final int MAX_LENGTH = 128;

    private static final Pattern UPPER = Pattern.compile("[A-Z]");
    private static final Pattern LOWER = Pattern.compile("[a-z]");
    private static final Pattern DIGIT = Pattern.compile("[0-9]");
    private static final Pattern SPECIAL = Pattern.compile("[!@#$%^&*()_+\\-=\\[\\]{}|;:,.<>?/\\\\~`\"']");

    private PasswordPolicy() {}

    public static void validate(String raw, String emailHint) {
        if (raw == null || raw.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "password_required");
        }
        if (raw.length() < MIN_LENGTH || raw.length() > MAX_LENGTH) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "password_length_invalid");
        }
        if (!UPPER.matcher(raw).find()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "password_requires_uppercase");
        }
        if (!LOWER.matcher(raw).find()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "password_requires_lowercase");
        }
        if (!DIGIT.matcher(raw).find()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "password_requires_digit");
        }
        if (!SPECIAL.matcher(raw).find()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "password_requires_special");
        }
        if (emailHint != null && !emailHint.isBlank()) {
            String local = emailHint.trim().toLowerCase(Locale.ROOT);
            int at = local.indexOf('@');
            String prefix = at > 0 ? local.substring(0, at) : local;
            if (prefix.length() >= 3 && raw.toLowerCase(Locale.ROOT).contains(prefix)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "password_must_not_contain_email_local_part");
            }
        }
        String lower = raw.toLowerCase(Locale.ROOT);
        if (lower.contains("password") || lower.contains("lifeengine") || lower.contains("life-engine")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "password_too_common");
        }
    }
}
