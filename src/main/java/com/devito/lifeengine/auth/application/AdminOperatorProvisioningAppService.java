package com.devito.lifeengine.auth.application;

import com.devito.lifeengine.auth.api.SecurityControlPlaneDtos;
import com.devito.lifeengine.auth.domain.BoUserPrincipal;
import com.devito.lifeengine.auth.infrastructure.persistence.AuthRoleRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.AuthRoleRow;
import com.devito.lifeengine.auth.infrastructure.persistence.BoUserRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.BoUserRoleRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.BoUserRoleRow;
import com.devito.lifeengine.auth.infrastructure.persistence.BoUserRow;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Production admin provisioning for BO operators — {@code POST /api/security/users}. Persists {@code bo_user} +
 * {@code bo_user_role} from {@code auth_role} catalog; never uses dev-register, seeds, or OAuth.
 */
@Service
public class AdminOperatorProvisioningAppService {

    private static final Pattern EMAIL_PATTERN =
            Pattern.compile("^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,63}$");
    private static final Pattern ROLE_CODE = Pattern.compile("^[A-Z][A-Z0-9_]{0,31}$");
    private static final int MAX_INITIAL_ROLES = 16;

    private final BoUserRepository users;
    private final BoUserRoleRepository userRoles;
    private final AuthRoleRepository roles;
    private final R2dbcEntityTemplate entityTemplate;
    private final PasswordEncoder passwordEncoder;
    private final SecurityAuditService securityAudit;
    private final SecurityStreamNotifier streamNotifier;

    public AdminOperatorProvisioningAppService(
            BoUserRepository users,
            BoUserRoleRepository userRoles,
            AuthRoleRepository roles,
            R2dbcEntityTemplate entityTemplate,
            PasswordEncoder passwordEncoder,
            SecurityAuditService securityAudit,
            SecurityStreamNotifier streamNotifier) {
        this.users = users;
        this.userRoles = userRoles;
        this.roles = roles;
        this.entityTemplate = entityTemplate;
        this.passwordEncoder = passwordEncoder;
        this.securityAudit = securityAudit;
        this.streamNotifier = streamNotifier;
    }

    public Mono<SecurityControlPlaneDtos.CreatedOperatorResponse> createOperator(
            SecurityControlPlaneDtos.CreateAdminOperatorRequest req,
            BoUserPrincipal actor,
            AuditContext ctx) {
        if (req == null) {
            return Mono.error(new ResponseStatusException(HttpStatus.BAD_REQUEST, "body_required"));
        }
        String email = normalizeEmail(req.email());
        if (email == null) {
            return Mono.error(new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_email"));
        }
        List<String> roleCodes = normalizeRoleCodes(req.initialRoleCodes());
        if (roleCodes.isEmpty()) {
            return Mono.error(new ResponseStatusException(HttpStatus.BAD_REQUEST, "initial_role_codes_required"));
        }
        if (roleCodes.size() > MAX_INITIAL_ROLES) {
            return Mono.error(new ResponseStatusException(HttpStatus.BAD_REQUEST, "too_many_initial_roles"));
        }
        for (String code : roleCodes) {
            if (!ROLE_CODE.matcher(code).matches()) {
                return Mono.error(new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_role_code:" + code));
            }
        }

        String temp = req.temporaryPassword() == null ? null : req.temporaryPassword().trim();
        boolean hasPassword = temp != null && !temp.isEmpty();
        boolean invite = Boolean.TRUE.equals(req.invite());

        if (!hasPassword && !invite) {
            return Mono.error(
                    new ResponseStatusException(
                            HttpStatus.BAD_REQUEST, "password_or_invite_required"));
        }
        if (hasPassword && invite) {
            invite = false;
        }

        if (hasPassword) {
            try {
                PasswordPolicy.validate(temp, email);
            } catch (ResponseStatusException e) {
                return Mono.error(e);
            }
        }

        final boolean invitePending = !hasPassword;
        final boolean effectiveInviteFlag = invitePending;
        /*
         * Without password material the account cannot authenticate with password — keep disabled until a future
         * invite/set-password flow (ignore client enabled=true for this branch).
         */
        boolean enabled = invitePending ? false : Boolean.TRUE.equals(req.enabled());

        return users
                .findByEmailIgnoreCase(email)
                .flatMap(
                        existing ->
                                Mono.<SecurityControlPlaneDtos.CreatedOperatorResponse>error(
                                        new ResponseStatusException(HttpStatus.CONFLICT, "email_already_exists")))
                .switchIfEmpty(
                        Mono.defer(
                                () -> {
                                    UUID userId = UUID.randomUUID();
                                    Instant now = Instant.now();
                                    BoUserRow row = new BoUserRow();
                                    row.setId(userId);
                                    row.setEmail(email);
                                    if (hasPassword) {
                                        row.setPasswordHash(passwordEncoder.encode(temp));
                                        row.setPasswordChangedAt(now);
                                    } else {
                                        row.setPasswordHash(null);
                                        row.setPasswordChangedAt(null);
                                    }
                                    row.setEnabled(enabled);
                                    row.setLocked(false);
                                    row.setFailedLoginAttempts(0);
                                    row.setLockedUntil(null);
                                    row.setCreatedAt(now);
                                    return entityTemplate
                                            .insert(row)
                                            .flatMap(
                                                    saved ->
                                                            resolveRoleRows(roleCodes)
                                                                    .flatMap(
                                                                            roleRows ->
                                                                                    insertUserRoles(
                                                                                                    saved.getId(),
                                                                                                    roleRows)
                                                                                            .then(
                                                                                                    securityAudit
                                                                                                            .record(
                                                                                                                    SecurityAuditEventType
                                                                                                                            .ADMIN_USER_CREATED,
                                                                                                                    SecurityAuditService
                                                                                                                            .OUTCOME_SUCCESS,
                                                                                                                    saved
                                                                                                                            .getId(),
                                                                                                                    saved
                                                                                                                            .getEmail(),
                                                                                                                    ctx,
                                                                                                                    provisioningDetail(
                                                                                                                            actor,
                                                                                                                            roleCodes,
                                                                                                                            hasPassword,
                                                                                                                            effectiveInviteFlag,
                                                                                                                            enabled)))
                                                                                            .then(
                                                                                                    Mono.fromRunnable(
                                                                                                            () ->
                                                                                                                    streamNotifier
                                                                                                                            .notifyDomain(
                                                                                                                                    "user_created",
                                                                                                                                    List.of(
                                                                                                                                            "users",
                                                                                                                                            "audit",
                                                                                                                                            "risk"),
                                                                                                                                    saved.getId(),
                                                                                                                                    saved.getId(),
                                                                                                                                    Map.of())))
                                                                                            .then(
                                                                                                    Mono.just(
                                                                                                            new SecurityControlPlaneDtos.CreatedOperatorResponse(
                                                                                                                    saved.getId(),
                                                                                                                    saved.getEmail(),
                                                                                                                    saved.isEnabled(),
                                                                                                                    invitePending,
                                                                                                                    roleCodes)))))
                                            .onErrorResume(
                                                    DuplicateKeyException.class,
                                                    e ->
                                                            Mono.error(
                                                                    new ResponseStatusException(
                                                                            HttpStatus.CONFLICT,
                                                                            "email_already_exists",
                                                                            e)));
                                }));
    }

    private static String provisioningDetail(
            BoUserPrincipal actor,
            List<String> roleCodes,
            boolean passwordSet,
            boolean inviteRequested,
            boolean enabled) {
        return "actorId="
                + actor.userId()
                + " actorEmail="
                + actor.email().trim().toLowerCase(Locale.ROOT)
                + " roles="
                + String.join(",", roleCodes)
                + " passwordSet="
                + passwordSet
                + " inviteRequested="
                + inviteRequested
                + " enabled="
                + enabled;
    }

    private static String normalizeEmail(String raw) {
        if (raw == null) {
            return null;
        }
        String t = raw.trim().toLowerCase(Locale.ROOT);
        if (t.isEmpty() || !EMAIL_PATTERN.matcher(t).matches()) {
            return null;
        }
        return t;
    }

    private static List<String> normalizeRoleCodes(List<String> raw) {
        if (raw == null || raw.isEmpty()) {
            return List.of();
        }
        Set<String> out = new LinkedHashSet<>();
        for (String s : raw) {
            if (s == null) {
                continue;
            }
            String u = s.trim().toUpperCase(Locale.ROOT);
            if (!u.isEmpty()) {
                out.add(u);
            }
        }
        return new ArrayList<>(out);
    }

    private Mono<List<AuthRoleRow>> resolveRoleRows(List<String> codes) {
        return Flux.fromIterable(codes)
                .concatMap(
                        code ->
                                roles.findByCode(code)
                                        .switchIfEmpty(
                                                Mono.error(
                                                        new ResponseStatusException(
                                                                HttpStatus.BAD_REQUEST, "unknown_role:" + code))))
                .collectList();
    }

    private Mono<Void> insertUserRoles(UUID userId, List<AuthRoleRow> roleRows) {
        return Flux.fromIterable(roleRows)
                .concatMap(
                        authRole -> {
                            BoUserRoleRow ur = new BoUserRoleRow();
                            ur.setBoUserId(userId);
                            ur.setRoleId(authRole.getId());
                            ur.setAssignedAt(Instant.now());
                            return userRoles.save(ur);
                        })
                .then();
    }
}
