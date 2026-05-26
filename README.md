# life-engine-auth

Standalone identity / RBAC / session / security control plane extracted from the
`life-engine` Spring Boot modulith. This is the Phase 1 deliverable of the
migration plan — the existing `life-engine` modulith is **not** modified.

## What's inside

| Source folder                                  | Origin                                              |
|------------------------------------------------|-----------------------------------------------------|
| `src/main/java/com/devito/lifeengine/auth/**`  | `life-engine/modules/auth/**` (verbatim)           |
| `…/config/SecurityConfig.java`                  | `life-engine/apps/core-app/.../config/`             |
| `…/config/ApiErrorHttpSupport.java`             | `life-engine/apps/core-app/.../config/`             |
| `…/config/SafeApiErrorWebExceptionHandler.java` | `life-engine/apps/core-app/.../config/` (patched)   |
| `…/config/LifeengineSecurityStartupLogger.java` | `life-engine/apps/core-app/.../config/`             |
| `…/config/CorsConfig.java`                      | `life-engine/apps/core-app/.../config/`             |
| `…/config/JacksonConfig.java`                   | `life-engine/apps/core-app/.../config/`             |
| `…/security/JwtReactiveAuthenticationWebFilter.java` | `life-engine/apps/core-app/.../security/`       |
| `…/boot/LifeengineApplicationEnvironmentPreparedListener.java` | core-app `boot/`                          |
| `…/boot/ProductionAuthSecurityStartupValidator.java` | core-app `boot/` (patched)                     |
| `…/logging/SensitiveMessage{Converter,Masker}.java` | core-app `logging/`                             |
| `…/platform/api/ApiErrorEnvelope.java`          | core-app `platform/api/`                            |
| `…/platform/web/RequestCorrelationWebFilter.java` | core-app `platform/web/`                          |
| `…/platform/PlatformRoles.java`                 | `modules/shared-kernel/platform/` (vendored)        |
| `…/platform/observability/{RequestCorrelationKeys,TracePropagationUtil,GrpcCorrelationThreadLocals}.java` | shared-kernel `platform/observability/` |
| `…/shared/events/UserRegisteredEvent.java`      | shared-kernel `shared/events/` (vendored)           |
| `src/main/resources/db/migration/V32..V54`      | core-app Flyway, auth-only (V40..V46 left behind)   |
| Tests under `src/test/java/.../auth/**` and `support/**` | core-app `src/test/java/...`                |

## Required minimal surgery

Only two source files were patched during the extraction. Both retain a
`Phase-1 extraction note (life-engine-auth):` comment so the change is traceable:

- `boot/ProductionAuthSecurityStartupValidator.java` — dropped the
  `io.lifeengine.agentruntime.infrastructure.config.AgentRuntimeProperties`
  dependency and the two gRPC-only production invariants (`grpc-insecure-local-enabled`,
  `internal-secret`). Identity has no gRPC clients; these checks belong to
  `life-engine-runtime` when it is extracted.
- `config/SafeApiErrorWebExceptionHandler.java` — dropped
  `com.devito.lifeengine.devagent.application.exception.DevAgentBusinessException`
  and the `io.grpc.Status / StatusRuntimeException → HTTP` mapper. Controllers can
  still ship stable codes via `ResponseStatusException("STABLE_CODE: human message")`
  (the existing `errorCodeOverride` regex picks them up unchanged).
- `LifeEngineAuthApplication` does NOT declare `@EnableR2dbcRepositories` —
  the auth module already provides it via `AuthSecurityBeansConfiguration`
  on the same base package. Redeclaring it triggers a
  `BeanDefinitionOverrideException` (caught + fixed during the first boot
  smoke test).

In tests, four `import`/`classes = LifeEngineApplication.class` references were
updated to point to `LifeEngineAuthApplication.class`. No assertion or behavior
changes.

## Building and running

### Quick path

```bash
cp .env.template .env.local   # already shipped pre-populated for local dev
bash scripts/run-local.sh
```

`scripts/run-local.sh` sources `.env.local` (via `scripts/load-env-local.sh`,
mirroring the modulith convention) and then runs `mvn spring-boot:run`. The
service listens on `:8081` by default (`LIFE_ENGINE_AUTH_PORT`). The modulith
keeps `:8080`; both can run side-by-side.

### Why both `APP_ENV` and `LIFEENGINE_DEPLOYMENT_ENV` are exported

The same `LifeengineApplicationEnvironmentPreparedListener` that ships in the
modulith fires at `ApplicationEnvironmentPreparedEvent` with
`@Order(HIGHEST_PRECEDENCE)`. That runs **before** Spring loads
`application.yml`, so the `${APP_ENV:local}` default inside the YAML is not yet
visible. The listener queries `lifeengine.deployment.env`, which only the
relaxed-binding rule `LIFEENGINE_DEPLOYMENT_ENV` (env var) or
`-Dlifeengine.deployment.env=local` (JVM arg) reaches. Exporting `APP_ENV` alone
will fail with `APP_ENV is required (binds lifeengine.deployment.env)`.
`.env.local` / `.env.template` therefore set both variables.

### IntelliJ IDEA

A shared run configuration is checked in at
`.run/LifeEngineAuthApplication.run.xml`. IntelliJ auto-detects it (Run →
Edit Configurations → LifeEngineAuthApplication) and supplies the same
environment variables as `.env.local`. No EnvFile plugin required.

If you prefer the EnvFile plugin, point it at `.env.local` and remove the
inline `<envs>` block from the run config.

### Manual / production

```bash
APP_ENV=prod \
LIFEENGINE_DEPLOYMENT_ENV=prod \
JWT_SECRET=$(openssl rand -hex 32) \
SPRING_DATASOURCE_PASSWORD=… SPRING_R2DBC_PASSWORD=… SPRING_FLYWAY_PASSWORD=… \
AUTH_BOOTSTRAP_USER=… AUTH_BOOTSTRAP_PASSWORD=… \
mvn -DskipTests package && java -jar target/life-engine-auth-0.0.1-SNAPSHOT.jar
```

## API contract

Identical to the modulith. All endpoints under `/api/auth/**`, `/api/security/**`,
`/api/dev-auth/reset-password`, `/api/email/oauth/google/**`, plus actuator
`/actuator/health|prometheus|metrics`. Path-matchers for non-auth routes
(`/api/dev-agent/**`, `/api/crypto/**`, `/api/workflow/**`, etc.) remain in
`SecurityConfig` so the auth-side guard logic is byte-identical to the original,
even though no controllers respond to those routes from this service.

## Database

### Ownership

`life-engine-auth` owns its **own** PostgreSQL database `life_engine_auth`,
schema `public`. No other service writes to this database. Canonical decision
matrix:

| Service | Database | Schema | Notes |
|---|---|---|---|
| `life-engine-auth` | `life_engine_auth` | `public` | Owned exclusively by this service. |
| `life-engine-runtime` | `life_engine_runtime` | `public` | Reserved; runtime currently in-memory. |
| `life-engine` (modulith) | `life_engine` | `public` | Legacy shared DB; auth no longer points here by default. |
| Vertical modules (future) | TBD per vertical | TBD | Each vertical decides its own DB/schema later. |

Multi-schema isolation inside one database is **not** used for auth/runtime;
the separation is at the database level. See
[`life-engine/docs/operations/11-database-ownership.md`](../life-engine/docs/operations/11-database-ownership.md)
for the workspace-wide matrix.

### Bootstrap the auth database (one-time, local)

The `docker-compose.yml` in `life-engine/` creates `life_engine` via
`POSTGRES_DB`, not `life_engine_auth`. On a fresh local checkout (or after
switching from the shared DB), create the auth-owned database once:

```bash
PGPASSWORD=life createdb -h localhost -p 5433 -U life life_engine_auth
```

The next `mvn spring-boot:run` will let Flyway apply `V32..V39` and `V47..V54`
into the empty `life_engine_auth` history table. The `local` profile pins
`SPRING_DATASOURCE_URL` / `SPRING_R2DBC_URL` / `SPRING_FLYWAY_URL` to
`localhost:5433/life_engine_auth`.

### Migrations

Flyway runs the auth-only migrations `V32..V39` and `V47..V54`. The historical
gap (`V40..V46`) is owned by email/OCR/media-studio/workflow in the modulith
and is intentionally not part of identity. Against the dedicated
`life_engine_auth` DB the gap is invisible — the Flyway history table contains
exactly the auth scripts that shipped on the classpath.

### Falling back to the shared `life_engine` DB (legacy / debugging)

If you temporarily repoint at the modulith's shared database (by exporting
`SPRING_DATASOURCE_URL=jdbc:postgresql://localhost:5433/life_engine` plus the
R2DBC and Flyway equivalents), Flyway will log:

```
o.f.core.internal.command.DbMigrate : Current version of schema "public": 83
o.f.core.internal.command.DbMigrate : Schema "public" has a version (83) that is newer than the latest available migration (54) !
o.f.core.internal.command.DbMigrate : Schema "public" is up to date. No migration necessary.
```

That warning is **expected** against the shared DB: the modulith's history
table carries scripts up to `V83` while this service's classpath stops at
`V54`. The `local` profile keeps
`spring.flyway.ignore-migration-patterns: ["*:missing", "*:future"]` as a
defensive safety net so that scenario boots cleanly without auth-owned scripts
being re-applied. Against the dedicated `life_engine_auth` DB the patterns are
a no-op.

## What's intentionally left behind

- `modules/auth/` is not deleted from `life-engine/`; both services coexist.
- All other modules (`dev-agent`, `crypto`, `crypto-bot`, `agent-runtime`,
  `agent-workflow-engine`, `interaction-platform`, `control-plane`,
  `email-agent`, `social-agent`, `land-radar`, `media-studio`, `ocr`, `memory`,
  `memory-rag`, `shared-kernel`, `finance`, `bogabot`) remain in `life-engine/`.
- gRPC client config (`lifeengine.agents.*`) — agents-python integration.
- Dev Agent / Workflow / Crypto-bot / Land-radar / RAG application properties.
- Kafka event bus + Resilience4j circuit breakers (Dev Agent only).
