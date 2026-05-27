# Life Engine Auth

[![Backend CI](https://github.com/sebdev89/life-engine-auth/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/sebdev89/life-engine-auth/actions/workflows/ci.yml)

Standalone authentication and authorization service for the **Life Engine** platform.

This repository owns identity. Runtime, agents, workflow, RAG, crypto, and any
other vertical consume identity from this service via signed JWTs — they never
own users, passwords, sessions, or RBAC rows.

## Purpose

`life-engine-auth` is the system of record for who can call Life Engine and
what they are allowed to do. It is a Spring Boot / WebFlux service backed by
a dedicated PostgreSQL database (`life_engine_auth`) and migrated with Flyway.

It is intentionally narrow: it does not orchestrate workflows, run agents,
make LLM calls, sign crypto transactions, or call out to any vertical. Other
services consume the JWTs it issues; they do not write back into its tables.

## Responsibilities

- Local login (email + password) with lockout on repeated failures
- Short-lived JWT access tokens (HS256)
- Refresh token lifecycle: issue, rotate, revoke
- Logout and admin-driven session invalidation (`/api/auth/logout`, kill-session)
- RBAC (`ADMIN`, `USER`, `VIEWER`, …) with role assignment endpoints
- Password change and password reset flow (Resend HTTP for email delivery)
- Optional Google OAuth login (login + identity linking)
- Self-service `/api/auth/me/**` endpoints (profile, sessions, activity)
- Admin security control plane (`/api/security/**`) for sessions, tokens,
  user lockouts, and an operator security bundle
- Security audit events persisted to PostgreSQL
- PostgreSQL persistence via R2DBC + JDBC (for Flyway)

## Boundary — what this service does NOT do

`life-engine-auth` is deliberately **not**:

- a workflow engine (no orchestration, no DAGs, no schedulers)
- an agent runtime (no agents-python integration, no gRPC clients to model
  serving, no Ollama / vLLM call-outs)
- a RAG / memory store (no vector DB, no embeddings)
- a crypto service (no key custody, no signing of external transactions —
  the only "crypto" here is JWT HMAC and BCrypt via Spring Security)
- the Life Engine modulith (the legacy `life-engine` repo still hosts those
  verticals; this service is an extraction of the auth surface only)

Runtime and vertical services downstream of identity:

- receive a JWT from a logged-in user (or service principal in the future)
- validate the JWT using the same secret / JWKS contract
- read the `sub`, `email`, `role`, `authorities`, and `sid` claims
- never read or write `bo_user`, `bo_user_role`, `refresh_token`,
  `user_sessions`, or `security_audit_event` in this DB

## Tech stack

- Java 21 (Temurin)
- Spring Boot 3.4.x
- Spring WebFlux + Reactor (the service is fully reactive)
- Spring Security (reactive) + BCrypt password hashing
- jjwt 0.12.x for HS256 access tokens
- PostgreSQL 16 (dedicated `life_engine_auth` database)
- R2DBC at runtime; JDBC + Flyway 11.x for migrations
- Micrometer + Prometheus actuator
- Maven 3.9
- Testcontainers (Postgres) for integration tests
- GitHub Actions for CI

## Local development

### Prerequisites

- JDK 21 (Temurin recommended)
- Maven 3.9+
- A PostgreSQL 16 instance on `localhost:5433` with user `life` / password `life`
  and a database named `life_engine_auth`. Create it once:
  ```bash
  PGPASSWORD=life createdb -h localhost -p 5433 -U life life_engine_auth
  ```
- Docker (only required for integration tests, which use Testcontainers)

### Configure env vars

```bash
cp .env.template .env.local
# edit .env.local — at minimum set JWT_SECRET (>= 32 bytes) for non-local profiles
```

`.env.local` is git-ignored. Only `.env.template` is committed and only contains
empty placeholders.

> **Why both `APP_ENV` and `LIFEENGINE_DEPLOYMENT_ENV` must be exported.**
> `LifeengineApplicationEnvironmentPreparedListener` fires with
> `@Order(HIGHEST_PRECEDENCE)` at `ApplicationEnvironmentPreparedEvent`, before
> Spring loads `application.yml`. It reads `lifeengine.deployment.env`, which
> only relaxed-binding `LIFEENGINE_DEPLOYMENT_ENV` (or
> `-Dlifeengine.deployment.env=…`) reaches at that point. The YAML default
> `${APP_ENV:local}` is not yet visible. Exporting `APP_ENV` alone fails fast
> with `APP_ENV is required (binds lifeengine.deployment.env)`. `.env.template`
> and `.env.local` therefore set both.

### Run unit tests

Unit tests are pure JVM and require no external services:

```bash
mvn -B test
```

### Run integration tests

Integration tests (`*IT.java`) spin up PostgreSQL via Testcontainers and
exercise the full WebFlux stack against real Flyway-migrated schemas. They
run under Maven Failsafe, so `mvn test` does NOT execute them.

```bash
mvn -B verify
```

Requires a working local Docker daemon. If Docker is unavailable the build
fails (no silent skip).

### Start the service locally

```bash
bash scripts/run-local.sh
```

`scripts/run-local.sh` sources `.env.local` via `scripts/load-env-local.sh`
and then runs `mvn spring-boot:run`. The service binds to
`:${LIFE_ENGINE_AUTH_PORT:-8081}` (8081 by default to avoid colliding with the
legacy modulith on 8080).

#### IntelliJ run configuration

A shared run config is checked in at
`.run/LifeEngineAuthApplication.run.xml`. IntelliJ auto-detects it (Run →
Edit Configurations → LifeEngineAuthApplication). The inline `<envs>` block
contains only **local-only** placeholder values (clearly named, e.g.
`local-dev-jwt-hs512-secret-minimum-32-chars-long-xx`, `admin123456`); the
production secrets path is environment variables only.

### Health endpoint

Spring Boot Actuator is enabled. Once the service is up:

```bash
curl http://localhost:8081/actuator/health
```

Prometheus scrape endpoint: `/actuator/prometheus`.

### API surface

All routes live under:

- `/api/auth/**` — login, refresh, logout, `/me/**`, password change/reset,
  Google OAuth callback
- `/api/security/**` — admin control plane (sessions, tokens, users, dashboard)
- `/api/auth/security/**` and `/api/auth/timeline`, `/api/auth/metrics/overview`
  — admin observability feeds
- `/api/dev-auth/reset-password` — local-only dev helper, gated by profile
- `/actuator/health`, `/actuator/prometheus`, `/actuator/metrics`

## Required env vars / properties

The full set is documented in `.env.template`. The minimal contract for the
`local` profile is satisfied entirely by template defaults: the service boots
on a fresh checkout with no exported variables, provided the
`life_engine_auth` database exists.

For `dev` and `prod` profiles the following must be set (the boot validator
fails fast otherwise):

- `JWT_SECRET` — at least 32 UTF-8 bytes (HS256 minimum). Generate with
  `openssl rand -hex 32`.
- `AUTH_BOOTSTRAP_USER` / `AUTH_BOOTSTRAP_PASSWORD` — first admin seed.
- `SPRING_DATASOURCE_PASSWORD` / `SPRING_R2DBC_PASSWORD` /
  `SPRING_FLYWAY_PASSWORD` — Postgres credentials.
- `LIFEENGINE_HTTP_CORS_ALLOWED_ORIGINS` — production-only (comma-separated).

Optional:

- `RESEND_API_KEY` + `RESEND_FROM` for outbound password-reset email.
- `GOOGLE_LOGIN_CLIENT_ID` / `GOOGLE_LOGIN_CLIENT_SECRET` for Google OAuth.

## Database

This service owns the `life_engine_auth` database (schema `public`). No other
service writes to it. Multi-schema isolation inside one database is **not**
used between auth and runtime — separation is at the database level.

Flyway runs the auth-only migrations `V32..V39` and `V47..V54` (the historical
`V40..V46` gap belongs to other modules in the legacy modulith and is
intentionally not part of identity).

## CI

GitHub Actions runs on every push to `main` and on every pull request to
`main`. The workflow at `.github/workflows/ci.yml`:

1. Checks out the source
2. Sets up JDK 21 (Temurin) with the Maven cache
3. Runs `mvn -B -DskipTests compile`
4. Runs `mvn -B test` (Surefire / unit tests only)

Integration tests (`*IT.java`) require Docker + Postgres via Testcontainers
and run under Failsafe (`mvn verify`). They are intentionally not part of the
default lane and can be added as a second job later without changing this one.

## Repository hygiene

- No real secrets are committed. `.env.local` is git-ignored; `.env.template`
  ships empty placeholders. The IntelliJ run config carries only
  obviously-named dev placeholders (`local-dev-*`, `admin123456`,
  `dev-only-reset-key`).
- `target/`, `.idea/`, `*.iml`, `*.log`, `logs/`, `tmp/`, `.DS_Store`, and
  `dist/` / `build/` / `out/` are all git-ignored.
- Boundary mentions of `runtime`, `agent`, `workflow`, `crypto`, `rag` in
  source/README are deliberate documentation of what this service does NOT
  do (e.g. the `SecurityConfig` path-matchers preserve the original guard
  ordering even though no controllers respond to those routes here).
