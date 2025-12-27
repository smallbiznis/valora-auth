# smallbiznis-auth

Enterprise-grade, multi-org OAuth2/OIDC server implemented in Go. The service mirrors Auth0-style capabilities (org discovery, OAuth flows, password/OTP logins, JWKS exposure) while remaining lightweight and self-hostable. It embraces Clean Architecture: HTTP transport is isolated from domain services and repositories, and dependencies are wired via Uber Fx.

---

## Table of Contents
1. [Architecture](#architecture)
2. [Technology Stack](#technology-stack)
3. [Configuration](#configuration)
4. [Running Locally](#running-locally)
5. [HTTP Surface](#http-surface)
   - [Discovery & OIDC](#discovery--oidc)
   - [OAuth Token Grants](#oauth-token-grants)
   - [External OAuth Providers](#external-oauth-providers)
   - [Token Utility APIs](#token-utility-apis)
   - [REST Auth Endpoints](#rest-auth-endpoints)
   - [User APIs](#user-apis)
6. [Org Resolution](#org-resolution)
7. [Services & Components](#services--components)
8. [Persistence & SQLC](#persistence--sqlc)
9. [Extending the System](#extending-the-system)
10. [Testing](#testing)

---

## Architecture

```
+-----------------------------+         +--------------------------+
|           Gin HTTP          | <--->   |  Middleware (Org,        |
|  routes & middleware        |         |  Auth/Bearer validation) |
+-----------------------------+         +--------------------------+
                 |                                     |
                 v                                     v
+-------------------------------------------------------------+
|                  Service Layer (AuthService,                |
|             DiscoveryService, REST helpers)                 |
+-------------------------------------------------------------+
                 |                                     |
                 v                                     v
+-------------------------------------------------------------+
|                   Repository Layer (SQLC)                   |
|  OrgRepo, UserRepo, TokenRepo, CodeRepo, KeyRepo            |
+-------------------------------------------------------------+
                 |                                     |
                 v                                     v
+-------------------------------------------------------------+
|          PostgreSQL via pgxpool + sqlc-generated SQL        |
+-------------------------------------------------------------+
```

- **Dependency Injection**: `cmd/auth/main.go` uses Uber Fx to construct configuration, logger, pgx connection pool, sqlc queries, repositories, services, HTTP router, and server lifecycle hooks.
- **JWT**: `internal/jwt` layers include `KeyManager` (per-org HMAC keys via `oauth_keys`) and `Generator` that issues/validates HS256 access tokens.
- **Clean architecture**: HTTP handlers call services; services depend only on repository interfaces and helper components; repositories encapsulate SQLC-generated queries.

## Technology Stack

- **Language**: Go 1.25+
- **Frameworks**: [Uber Fx](https://github.com/uber-go/fx) for DI, [Gin](https://github.com/gin-gonic/gin) for HTTP
- **Database Access**: [pgxpool](https://github.com/jackc/pgx) with sqlc-generated queries (no ORM)
- **Auth**: `github.com/go-jose/go-jose/v4` for JWS/JWT, bcrypt for password hashing
- **Logging**: Uber's `zap` structured logger

## Configuration

Configuration is environment-driven (see `internal/config/config.go`):

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_ENV` | `development` | Controls log level |
| `HTTP_PORT` | `8080` | Port bound by HTTP server |
| `DATABASE_URL` | _required_ | PostgreSQL connection string |
| `ACCESS_TOKEN_TTL` | `1h` | Access-token lifetime |
| `REFRESH_TOKEN_TTL` | `720h` (30d) | Refresh token lifetime |
| `REFRESH_TOKEN_BYTES` | `32` | Size of refresh token entropy |
| `REDIS_ADDR` | `127.0.0.1:6379` | Redis endpoint for OAuth state/PKCE storage |
| `REDIS_PASSWORD` | `""` | Redis password (optional) |
| `REDIS_DB` | `0` | Redis logical DB index |

## Running Locally

```bash
export DATABASE_URL="postgres://user:pass@localhost:5432/smallbiznis?sslmode=disable"
export REDIS_ADDR="127.0.0.1:6379"
export APP_ENV=development
export HTTP_PORT=8080

# Ensure Postgres + Redis are running locally, then run migrations (sql files under sql/)

go run ./cmd/auth
```

Uber Fx wires the dependencies, opens the pgx pool, and starts the Gin server with graceful shutdown.

### Container Image

A multi-stage `Dockerfile` is provided for minimal images:

```bash
docker build -t smallbiznis-auth .
docker run --rm -p 8080:8080 \
  -e DATABASE_URL=postgres://user:pass@db:5432/smallbiznis?sslmode=disable \
  smallbiznis-auth
```

## CI / Workflows

GitHub Actions definitions under `.github/workflows/` cover both unit and integration checks:

- `ci.yml` (unit tests/lint) runs on pushes and pull requests targeting `main`/`master`.
- `integration.yml` spins up PostgreSQL, applies `sql/migrations/*.sql`, runs `go test -tags=integration`, and notifies Slack via `SLACK_WEBHOOK_URL`. It runs on push/PR to the default branches or can be triggered manually via *workflow_dispatch*.

## HTTP Surface

### Discovery & OIDC

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/.well-known/org` | Org branding/providers metadata (`/.well-known/tenant` remains as a compatibility alias) |
| `GET` | `/.well-known/openid-configuration` | OIDC discovery document |
| `GET` | `/.well-known/jwks.json` | Org JWKS (HS256 public material) |

### OAuth Token Grants

`POST /oauth/token` supports password, refresh_token, authorization_code, client_credentials (stub), device_code (stub), and Auth0-style OTP grants. `GET /oauth/authorize` is reserved for browser-based flows. Responses follow OAuth error structure:

```json
{ "error": "invalid_grant", "error_description": "Wrong email or password." }
```

### External OAuth Providers

Browser clients can enumerate and start external (Google/Microsoft/etc.) flows through `/auth/oauth/*` endpoints:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/auth/oauth/providers` | List enabled IdPs for the resolved org (name, icon, display name). |
| `GET` | `/auth/oauth/start` | Generates state/nonce/PKCE verifier and returns the IdP authorization URL. |
| `GET` | `/auth/oauth/callback` | Handles IdP redirects, validates state, issues SmallBiznis session cookies, then redirects to caller-provided URI. |

### Token Utility APIs

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/oauth/introspect` | RFC 7662-compliant token introspection (always returns HTTP 200 with `active` flag). |
| `POST` | `/oauth/revoke` | RFC 7009 token revocation for access/refresh tokens. |

### REST Auth Endpoints

Purpose-built for Next.js dashboards and console apps (JSON in/out). All require org resolution via `Org` middleware.

| Method | Path | Handler | Description |
|--------|------|---------|-------------|
| `POST` | `/auth/password/login` | `AuthHandler.PasswordLogin` | Issue OAuth tokens for email/password |
| `POST` | `/auth/password/register` | `AuthHandler.PasswordRegister` | (Stub) Registration entry point |
| `POST` | `/auth/password/forgot` | `AuthHandler.PasswordForgot` | Initiate password reset |
| `POST` | `/auth/otp/request` | `AuthHandler.OTPRequest` | Request login OTP via configured channel |
| `POST` | `/auth/otp/verify` | `AuthHandler.OTPVerify` | Verify OTP and issue tokens |
| `GET` | `/auth/me` | `AuthHandler.Me` | Return profile for bearer token |

Success responses use `AuthTokensWithUser`:

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "43f50c...",
  "id_token": "",
  "token_type": "Bearer",
  "expires_in": 3600,
  "user": {
    "id": 123,
    "org_id": 456,
    "tenant_id": 456,
    "email": "user@org.com",
    "name": "Jane Doe",
    "avatar_url": "https://cdn/img.png"
  }
}
```

### User APIs

- `GET /oauth/userinfo` – Standard OIDC userinfo endpoint backed by OAuth access tokens.
- `GET /auth/me` – REST-friendly user profile via `AuthService.GetUserInfo`.

## Org Resolution

`internal/middleware/org.go`:

1. Parses `Host` header (`kopi.tenant.local:3000 → kopi.tenant.local`).
2. Calls `org.Resolver.Resolve` which queries `domains` using `OrgRepository` (SQLC).
3. Loads org metadata (branding, providers, configs) and stores it in:
   - the Gin context (`c.Set("org_id", ...)`, `c.Set("orgContext", ...)` and `tenant_id`/`tenantContext` aliases for compatibility)
   - the request context for service-layer access.

Every handler (OAuth and REST) requires the org context; failures result in `invalid_tenant` for compatibility.

## Services & Components

- **AuthService (`internal/service/auth_service.go`)**
  - Implements OAuth grants (password, refresh, authorization code, client credentials stub, device code stub, OTP).
  - Issues JWT access tokens via `jwt.Generator`, persists refresh tokens with `TokenRepository`.
- Validates OTP using org-specific settings and per-user secrets.
  - Exposes helper `JWKS`, `ValidateToken`, and new REST-oriented methods in `auth_rest.go`.
- **OAuthService (`internal/service/auth/oauth_service.go`)**
  - Owns external IdP orchestration: listing providers, generating PKCE state/nonce, handling callbacks.
  - Persists OAuth state in Redis via `internal/adapter/cache/redis_state_store.go`.
  - Provides RFC-compliant `/oauth/introspect`, `/oauth/revoke`, and `/oauth/userinfo` behaviors.

- **REST helpers (`internal/service/auth_rest.go`)**
  - Wrap OAuth flows into Next.js friendly responses (`AuthTokensWithUser` / `UserViewModel` defined in `models.go`).
  - Handles forgot password (currently logs), OTP request/verify, and profile lookup.

- **Repositories (`internal/repository/postgres.go`)**
  - Thin wrappers using sqlc-generated queries (`sqlc/queries.go`).
  - Only accept `*sqlc.Queries` built from `pgxpool.Pool`.

- **JWT utilities (`internal/jwt/`)**
- `KeyManager` ensures each org has an HS256 key stored in `oauth_keys`.
- `Generator` signs/validates tokens with allowed algorithms enforced per org.

- **HTTP middleware (`internal/http/middleware`)**
- `Org` (host-based resolution) and `Auth` (Authorization header validation) keep handlers slim.
- `RequestLogger` adds structured per-request logging with request IDs and org metadata.

## Persistence & SQLC

- All SQL lives under `sql/` (queries and migrations). `sqlc` generates strongly typed Go structs in `sqlc/`.
- Repositories (e.g., `PostgresUserRepo`) adapt sqlc rows into domain models located in `internal/domain/`.
- OAuth tokens, codes, keys, and org metadata tables are defined in `sql/migrations/0001_schema.sql` (DB tables/columns still use `tenant` naming for now).

## Extending the System

1. **Add SQL** – define queries in `sql/query/*.sql`, run `sqlc generate`.
2. **Create repository method** – wrap sqlc query in `internal/repository/postgres.go`.
3. **Inject via Fx** – update `cmd/auth/main.go` if new repositories/services are needed.
4. **Expose via HTTP** – add handler + route in `internal/http/router.go`, reuse middleware or create new ones.
5. **Maintain OAuth-style errors** – always return `{ "error": "...", "error_description": "..." }`.

## Testing

```bash
go test ./...
```

Unit tests exist for org resolver and service components; extend coverage alongside new features. Use test doubles for repositories to keep service tests deterministic.

---

This document should serve as the onboarding guide for engineers integrating or extending `smallbiznis-auth`. Contributions are welcome—please keep Clean Architecture boundaries and OAuth specs in mind.
