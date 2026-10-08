# AstraNull API reference (production contract)

This document defines the **production API contract** for AstraNull and records **current implementation status** in developer validation mode. Route shapes and permissions below are the target unless marked as a production release blocker.

## Authentication

| Mode | Use | Production |
|---|---|---|
| **OIDC JWT (`oidc-jwt`)** | `Authorization: Bearer <RS256 compact JWT>` from enterprise IdP | **Default human auth** when `NODE_ENV=production` (or set `ASTRANULL_AUTH_MODE=oidc-jwt`). Verifier requires RS256, `kid`, and RSA signing JWKS keys (`kty`, optional `use`, optional `alg`); JWKS fetch uses a bounded timeout (`ASTRANULL_OIDC_JWKS_FETCH_TIMEOUT_MS`) and **does not follow HTTP redirects**; production startup requires **HTTPS** `ASTRANULL_OIDC_JWKS_URL`. Validates issuer, audience, strict numeric `exp`, optional numeric `nbf`, and maps tenant/user/role claims to AstraNull RBAC. **Not** valid on agent or probe-worker routes. |
| **Password credential lane** | Public `POST /v1/auth/login`, one-time setup at `POST /v1/auth/set-password`, self-service recovery at `POST /v1/auth/request-password-reset` + `POST /v1/auth/reset-password`, and authenticated TOTP conditional access at `POST /v1/auth/mfa/enroll|verify|disable`; successful login mints the deployment's existing customer bearer-session format | **Additive and feature-gated** — it does not replace or relax OIDC, bundled-staging, or production auth-mode gates. The current minters support non-production `signed-session` and bundled staging OIDC only; a deployment without one fails closed with `503 password_login_unavailable`. Enterprise MFA/conditional access integration, production session minting, live email-delivery evidence, and abuse monitoring remain production blockers. |
| **Signed session (`signed-session`)** | HMAC bearer token (`asn1.<payload>.<sig>`) minted with `ASTRANULL_SESSION_SECRET` | **Non-production only** — local tests and operator flows; refused at startup when `NODE_ENV=production`. Not a production IdP. |
| **Bearer agent credential + production gateway mTLS fingerprint** | `POST /v1/agents/register` → `agc_v1.…` (`agc_v1.<tenantB64>.<agentIdB64>.<random>`) on heartbeat, jobs, observations; legacy opaque `agc_…` still accepted in dev JSON store | **Required** — full credential verified against stored `credential_salt` / `credential_hash`; in production `ASTRANULL_AGENT_IDENTITY_MODE=gateway-mtls` requires a forwarded client certificate SHA-256 fingerprint matching the registered agent fingerprint |
| **Service account token** | `Authorization: Bearer svc_…` on `/v1/*` and `/internal/*` (not agent or probe-worker routes) | **Built-in automation boundary** — tenant-bound, revocable, scoped; secret shown once at create/rotate as `svc_v1.…` with embedded tenant/account id hints (salted hash of full secret stored; legacy opaque `svc_…` still accepted in dev store). Works independently of human auth mode (`oidc-jwt`, `signed-session`, `dev-headers`). Not a substitute for agent credentials or probe-worker HMAC. |
| **Developer validation headers (`dev-headers`)** | `x-tenant-id`, `x-user-id`, `x-role` for local UI and CI | **Forbidden in production** — refused at startup if `NODE_ENV=production`; see [`docs/release-checklist.md`](release-checklist.md) |

### Human auth environment (`oidc-jwt`)

| Variable | Required | Notes |
|---|---|---|
| `ASTRANULL_OIDC_ISSUER` | Yes | Expected JWT `iss`. |
| `ASTRANULL_OIDC_AUDIENCE` | Yes | Expected JWT `aud`. |
| `ASTRANULL_OIDC_JWKS_URL` | Yes | JWKS document URL for RS256 verification. Must use **HTTPS** when `NODE_ENV=production`. |
| `ASTRANULL_OIDC_TENANT_CLAIM` | No | Default `tenant_id`. |
| `ASTRANULL_OIDC_ROLE_CLAIM` | No | Default `role` (mapped to AstraNull RBAC). |
| `ASTRANULL_OIDC_USER_CLAIM` | No | Default `sub`. |
| `ASTRANULL_OIDC_JWKS_CACHE_TTL_MS` | No | Bounded JWKS cache TTL (default 300000 ms). |
| `ASTRANULL_OIDC_JWKS_FETCH_TIMEOUT_MS` | No | Bounded JWKS HTTP fetch timeout (default 5000 ms; min 1000, max 30000). Redirect responses are not followed. |

`resolveAuthMode()` defaults to `oidc-jwt` when `NODE_ENV=production`. `loadRuntimeConfig()` refuses both `dev-headers` and `signed-session` in production.

### Password authentication configuration

| Variable / public key | Contract |
|---|---|
| `ASTRANULL_PASSWORD_LOGIN_ENABLED` | Optional strict `1` / `0` feature flag. When unset, defaults to enabled only for `signed-session` or `oidc-jwt` with bundled staging OIDC enabled; otherwise defaults off. Enabling it never bypasses the production refusal of `dev-headers` or `signed-session`. |
| `password_login_enabled` | Exact top-level boolean returned by `GET /v1/public/site-config`; clients use it to decide whether to offer the password lane. A missing injected service or unavailable session minter still fails closed at request time with `503`. |

Passwords are stored only as salted scrypt verifiers in the canonical format `scrypt$N=16384,r=8,p=1$<saltB64url>$<hashB64url>` (16-byte random salt, 32-byte derived key). Plaintext passwords and invite tokens are never persisted or audited; invite records store only a SHA-256 token digest. The schema and migration force tenant RLS on `user_credentials` and `user_password_invites`.

Agent calls use `Authorization: Bearer <agc_v1.…>` (or legacy `agc_…` in dev store) on agent-scoped routes. Newly issued credentials embed tenant and agent id lookup hints; verification still uses the full secret against stored salt/hash. Invalid addressed `agc_v1` bearer auth audits `agent.auth_denied` only when a matching `(tenant_id, agent_id)` agent row exists; nonexistent or mismatched hints return `401` without tenant-local audit. Unknown legacy opaque route agents return `401` without audit; invalid legacy opaque for an existing route agent still audits under the confirmed tenant. Production defaults `ASTRANULL_AGENT_IDENTITY_MODE` to `gateway-mtls` and refuses bearer-only mode; the gateway must forward the verified client certificate fingerprint in `x-client-cert-fingerprint`, `x-astranull-client-cert-fingerprint`, or `x-forwarded-client-cert-sha256`, and it must match the agent fingerprint captured at registration. Packaged agents default to HTTPS control-plane URLs (`ASTRANULL_API_URL`); localhost HTTP requires `--allow-insecure-localhost-api` or `ASTRANULL_ALLOW_INSECURE_LOCALHOST_API=1` (developer validation only). Packaged installs persist registration identity at `/var/lib/astranull/identity.json` (`0700` directory / `0600` file; override with `--identity` or `ASTRANULL_AGENT_IDENTITY`). Shipped generic Linux tarballs are validated to block server-side `src/*` imports (packaged source-isolation test). Automation uses `Authorization: Bearer <svc_…>` where human OIDC JWTs are not appropriate; effective access requires both the service account **role** and an explicit **scope** (or `*` for admin-only accounts).

Unless noted, responses are JSON. Errors use `{ "error": "<code>", "message"?: "…" }` with HTTP 4xx/5xx.

## Safety notes (all endpoints)

- Validation checks use governed probe profiles. `ASTRANULL_PROBE_MODE=simulation` (default outside production) runs metadata-only `SAFE_PROBE_SIMULATION` in-process for developer validation and CI only; startup **refuses** explicit `simulation` when `NODE_ENV=production`. Production defaults to `signed-worker` so external workers consume HMAC-signed jobs via `/internal/probe/*`. Deploying and operating the probe fleet remains a release blocker.
- High-scale **start** must invoke **governed** execution adapters only (SOC role, approved pack, schedule window). `ASTRANULL_HIGH_SCALE_ADAPTER_MODE` defaults to `governed-adapter` in production and `dry-run` outside production; `dry-run` is refused when `NODE_ENV=production`. Developer validation uses adapter dry-run metadata — **production release blocker**: partner/internal governed adapter.
- Event ingestion rejects `packet_payload` and `raw_packet`.
- Agent observation ingestion requires a matching **acked** `agent_job_id` (job poll/ack proof); rejects raw packet/log/header/body payload fields; stores **metadata only** after `redactObject`.
- Exports pass through `redactObject` (no `ast_` / `svc_` / `agc_` / full dotted `agc_v1…` tokens in output).
- Notifications record delivery intent; external send requires configured providers — **production release blocker** for customer-facing alerting.

## API rate limiting (service layer)

A fixed-window limiter applies to all `/v1/*` and `/internal/*` requests before auth and handlers run. These paths are **not** limited: `GET /health`, `GET /ready`, `GET /metrics`, and static UI (`/`, `/react-app.js`, `/react-app.css`).

| Variable | Default | Bounds | Notes |
|---|---|---|---|
| `ASTRANULL_RATE_LIMIT_WINDOW_MS` | `60000` | `1000`–`3600000` | Window length in milliseconds. |
| `ASTRANULL_RATE_LIMIT_MAX_REQUESTS` | `600` | `1`–`100000` | Max requests per client key per window. |
| `ASTRANULL_RATE_LIMIT_DISABLED` | off | — | `=1` allowed only outside `NODE_ENV=production`; production startup **fails closed** if set. |
| `ASTRANULL_TRUST_PROXY_HEADERS` | `false` | — | When `=1`, the client key is read from `x-forwarded-for`. `x-real-ip` is never used: it carries no positional information, so an edge-written value cannot be told apart from a caller-supplied one. Enable **only** behind a proxy that appends the real client address. |
| `ASTRANULL_TRUSTED_PROXY_HOPS` | `1` | `1`–`10` | Number of proxies in front of the API that append to `x-forwarded-for`. Only used with `ASTRANULL_TRUST_PROXY_HEADERS=1`. The client address is taken this many entries from the **right**, because conforming proxies append. Setting it too low collapses callers into one bucket (unfair, not spoofable); too high reads caller-supplied entries (**spoofable**), so prefer under-counting when unsure. |

When limited, the API returns HTTP `429` with JSON `{ "error": "rate_limited" }` and a `Retry-After` header (seconds). Counter `api_rate_limited_total` increments. Gateway/WAF limits and staging load/abuse evidence remain **production release blockers** (see checklist).

## Public / unauthenticated

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/health` | — | Liveness: `{ status, service }` (`service` is `astranull`). |
| GET | `/ready` | — | Readiness for deploy gates: `{ status, service, auth_mode, persistence, probe_mode, probe_worker_secret_configured, timestamp }` (no secrets or database URLs); `503` with `status: not_ready` when the store is unavailable. |
| GET | `/metrics` | — | Prometheus-style metrics. Bearer-gated by `ASTRANULL_METRICS_TOKEN`: when the token is set the scraper must present it as `Authorization: Bearer <token>` (`401 unauthorized` otherwise). When the token is unset the route **fails closed** in production (`401 {"error":"unauthorized","reason":"metrics_token_not_configured"}`) and stays open only outside `NODE_ENV=production` for local scrapes. Production deployments must configure `ASTRANULL_METRICS_TOKEN` and the matching scraper credential, and still restrict scrape access at the gateway/network layer. |
| GET | `/`, `/react-app.js`, `/react-app.css` | — | React SPA shell and bundle assets. |
| GET | `/v1/public/site-config` | — | Public landing/login/signup configuration with no secrets, including exact top-level boolean `password_login_enabled`. |
| POST | `/v1/auth/login` | — | Feature-gated customer password exchange; stored user tenant/role are authoritative. Requires a non-replayed TOTP code for MFA-enrolled accounts. |
| POST | `/v1/auth/set-password` | — | Feature-gated one-time invite consumption and password setup; does not log the user in. |
| POST | `/v1/auth/request-password-reset` | — | Enumeration-safe self-service reset request. Public response is always `{ "status": "reset_requested" }`; eligible accounts enqueue a one-time token through the configured durable out-of-band delivery hook without exposing account or delivery state. |
| POST | `/v1/auth/reset-password` | — | Feature-gated one-time reset-token consumption; replaces the credential, increments session generation, and clears lockout/forced-change state. Success returns only `{ "status": "password_reset" }` and does not log the user in. |
| POST | `/v1/auth/bundled-staging-login` | — | Bundled staging login exchange for hosted/local staging. Not a production enterprise IdP substitute. |
| POST | `/v1/signup-requests` | — | Public account request intake. Returns `201 { request }`, `400 validation_failed`, `403 signup_disabled`, `409 duplicate_request`, or `429 rate_limited`. |
| GET | `/v1/signup-requests/:id` | — | Public-safe signup request status (`{ request }`) or `404`. |
| GET | `/v1/signup-requests/:id/events` | — | Ordered signup queue events `{ events, count }`; messages truncated to **500** chars; rate-limited to **12/min** per request id (`429 rate_limited`). |
| GET | `/v1/checks` | `check:read` | Authenticated global check catalog. The permission is explicit for every customer role; future tenant-customized catalogs must retain tenant scoping. |
| GET | `/v1/checks/:id` | `check:read` | Exact catalog row `{ check }` (same section fields as the list). Unknown id is `404 not_found`. Does not start a run. |
| GET | `/v1/vectors` | `check:read` | Authenticated 721-row public-safe vector library. Query with bounded `limit` (1–100, default 50), `offset` (0–721), `q`/`search` (first 200 characters across safe descriptive/contract fields), or exact `vector_id`, `section`, `domain`, `scope`, `family`, `validation_tier`, `evidence_tier`, `evidence_capability`, `execution_disposition`, `registry_source`, and `check_id` filters. Each item keeps the source claim neutral as `targeted_resource_or_assumption`; `intended_detection_goal` is explicitly intent, never an observed result. `evidence_capability` classifies E1 declaration-only, E2 transport-only, E3 semantic-safe, E4 SOC-governed, or E5 monitor-only, while `execution_disposition` independently states whether safe validation, SOC governance, or monitoring applies. Supplemental E1 metadata remains in `metadata_available`/`metadata_check_ids` and never converts an authoritative E4 vector into safe validation. No `detects` field is published. Response is `{ items, count, meta: { total: 721, filtered_total, offset, limit, returned } }`; this metadata route never starts traffic. |
| GET | `/v1/state` | `tenant:read` | Dashboard aggregate. In `postgres` mode uses `runtime.services.state.getState` (evidence-backed readiness from Postgres repositories); high-scale counts and kill-switch state return explicit not-wired metadata until those route families migrate. |
| GET | `/v1/placement/reviews` | `target_group:read` | Optional query `target_group_id`. Metadata-only per-target-group placement diagnostics (`proven`, `needs_baseline`, `missing_agent`, `misplaced_risk`) with summary counts, bound/online agent ids, recent observation counts, and warnings. `404` `not_found` when `target_group_id` is not declared for the tenant. Postgres mode uses `runtime.services.placement.listPlacementReviews`. |

## Password login and one-time setup

Both routes are unauthenticated, JSON-only, bounded by `ASTRANULL_MAX_JSON_BODY_BYTES`, protected by the API-wide limiter, and additionally protected by password-auth client/email buckets. They are additive to the bundled staging exchange: existing bundled-login feature gates and production refusals are unchanged. Error bodies below do not include the service's internal numeric `status` field.

### `POST /v1/auth/login`

Request:

```json
{
  "email": "person@example.com",
  "password": "the account password (1-200 characters at this boundary)",
  "tenant_id": "optional-tenant-id",
  "totp": "required for MFA-enrolled accounts (6 digits)"
}
```

`email` is trimmed and lowercased. `tenant_id` only scopes account lookup; it never supplies identity or authorization. Any client-supplied `role` is ignored. Without `tenant_id`, exactly one matching tenant is required; the session's `tenant_id`, `user_id`, and `role` always come from the stored user.

| HTTP | Response | Condition |
|---|---|---|
| `200` | `{ "access_token": "…", "token_type": "Bearer", "expires_in": 3600, "principal": "customer", "tenant_id": "…", "user_id": "…", "role": "owner|admin|engineer|soc|auditor|viewer" }` | Correct credential for an active user, no forced change, and an available session minter. |
| `400` | `{ "error": "validation_failed", "message": "One or more authentication fields are invalid.", "fields": ["email"|"password"|"tenant_id", …] }` | Malformed/missing email, empty or over-200-character password, or invalid optional tenant id. |
| `400` | `{ "error": "tenant_required", "message": "This email belongs to more than one tenant; tenant_id is required." }` | More than one tenant has the normalized email and no tenant was supplied. |
| `401` | `{ "error": "invalid_credentials", "message": "Email or password is incorrect." }` | Unknown user, wrong tenant, active user without a credential, malformed stored verifier, or wrong password. Unknown users, missing credentials, and wrong passwords deliberately share this exact response and comparable scrypt work; a malformed stored verifier fails safely without process error. |
| `403` | `{ "error": "password_setup_required", "message": "Set a password using the current invitation before signing in." }` | Stored user is still `invited`. |
| `403` | `{ "error": "account_disabled", "message": "This account is disabled." }` | Stored user is not active or invited. |
| `403` | `{ "error": "password_change_required", "message": "The password must be changed before this account can sign in." }` | Correct credential has `must_change=true`. |
| `401` | `{ "error": "mfa_required", "message": "This account requires an authentication code." }` | Correct password for an MFA-enrolled account, but no `totp` code was supplied. Re-submit with `totp`. |
| `401` | `{ "error": "mfa_invalid", "message": "The authentication code is invalid or expired." }` | Correct password for an MFA-enrolled account, but the `totp` code is wrong/expired or a replayed step. |
| `423` | `{ "error": "account_locked", "message": "The account is temporarily locked. Try again later.", "retry_after_seconds": <seconds> }` | The fifth consecutive credential failure establishes a 15-minute lock and returns `423`; later attempts while locked also return `423` without scrypt. Header `Retry-After` equals `retry_after_seconds`. A successful login resets the counter and lock. |
| `429` | `{ "error": "rate_limited", "message": "Too many authentication attempts. Try again later.", "retry_after_seconds": <seconds> }` | Password-auth client/email limiter. Header `Retry-After` is present. The earlier API-wide limiter can instead return `{ "error": "rate_limited" }`, also with `Retry-After`. |
| `503` | `{ "error": "password_login_unavailable", "message": "Password login cannot mint sessions on this deployment." }` | Credentials are valid but the deployment has no supported customer-session minter. |

Unknown email, ambiguous-email, and pre-lookup client-rate-limit outcomes cannot safely emit a tenant audit event because no tenant has been authenticated. Once lookup establishes a known account, outcomes emit `auth.password_login.succeeded`, `auth.password_login.failed`, or `auth.password_login.locked`; audit metadata never includes the password or verifier.

### `POST /v1/auth/set-password`

Request:

```json
{
  "token": "pwi_<one-time-secret>",
  "password": "a policy-compliant password"
}
```

Password policy is 12–200 characters, at least three of lowercase/uppercase/digit/symbol, must not contain the invited email's local part (case-insensitive), and must not be in the built-in common-password denylist.

| HTTP | Response | Condition |
|---|---|---|
| `200` | `{ "status": "password_set", "tenant_id": "…", "user_id": "…", "email": "…" }` | The password verifier is upserted, invite consumed, user activated, and lockout/forced-change state reset. This is one Postgres tenant transaction. **No bearer token is returned; the client must call `/v1/auth/login` separately.** |
| `400` | `{ "error": "validation_failed", "message": "One or more authentication fields are invalid.", "fields": ["token"|"password", …] }` | Missing/empty token or password, token over 2048 characters, or password over 200 characters. |
| `400` | `{ "error": "weak_password", "message": "The password does not meet the password policy.", "failures": [<code>, …] }` | Policy failure. Endpoint-visible assessment codes are `too_short`, `insufficient_character_classes`, `contains_email_local_part`, and `common_password`; the underlying policy helper also reports `invalid_type` and `too_long`, but the HTTP boundary maps those two cases to `validation_failed` first. |
| `401` | `{ "error": "invalid_invite", "message": "The password invitation is invalid or has already been used." }` | Token is unknown or consumed, the bound user is missing/disabled, or another request wins the atomic consume race. |
| `410` | `{ "error": "invite_expired", "message": "The password invitation has expired." }` | Invite expiry is at or before request time, including the transaction-time recheck. |
| `429` | Same password-auth/API-wide limiter variants described above. | Too many setup attempts from the client bucket. |

### Common route-level failures

| HTTP | Response | Condition |
|---|---|---|
| `400` | `{ "error": "invalid_json" }` | Body is not valid JSON. |
| `403` | `{ "error": "password_login_disabled", "message": "Password login is not enabled on this deployment." }` | Feature flag is off; applies to both login and setup. |
| `413` | `{ "error": "payload_too_large" }` | Body exceeds `ASTRANULL_MAX_JSON_BODY_BYTES`. |
| `503` | `{ "error": "password_login_unavailable", "message": "Password authentication is not available on this deployment." }` | Required injected password service method is absent. |

Invite issuance is intentionally a backend service/staff operation, not a new public HTTP endpoint. `issuePasswordInvite` returns the `pwi_…` token once while persisting only its digest and auditing `auth.password.invite_issued`; password setup audits `auth.password.set`. The issuer remains responsible for approved out-of-band invite delivery; the service does not send it. Enterprise MFA/conditional access integration, production session minting, live invite/reset delivery evidence, and staging/security/operations evidence remain explicit production blockers.

## Password recovery and TOTP conditional access

### `POST /v1/auth/request-password-reset`

Unauthenticated, enumeration-safe, feature-gated with the password lane. Request: `{ "email": "person@example.com" }`.

| HTTP | Response | Condition |
|---|---|---|
| `200` | `{ "status": "reset_requested" }` | Same response for valid/invalid email syntax, known/unknown/ambiguous accounts, missing credentials, delivery unavailability, durable-enqueue failure, and the recovery service's private client-bucket limit. For one eligible active account, the service creates a one-time `pwr_…` token (30-minute TTL), persists only its SHA-256 digest, and transactionally invokes `enqueuePasswordReset` before committing the reset row and audit. The enqueue contract must be durable and idempotent; failure rolls back the usable reset record. Neither token nor delivery state is public. The API-wide limiter may still return its generic `429 rate_limited` before this handler. |

Eligible requests audit `auth.password.reset_requested`; missing or failed durable delivery enqueue audits `auth.password.reset_delivery_enqueue_failed`. Audit metadata never contains the token.

The always-on Postgres delivery runner still requires its database URL, 32-byte envelope key, valid HTTPS public base URL, explicit tenant scope, and bounded poll interval. `ASTRANULL_SMTP_HOST` is intentionally optional: blank or missing keeps the worker in truthful queue-only provider-unconfigured mode, where encrypted outbox items remain nondelivered and receive retryable `smtp_not_configured` metadata under the existing lease, retry, and max-attempt bounds. Setting a real SMTP host enables delivery; queue-only mode never fabricates a successful send.

### `POST /v1/auth/reset-password`

Unauthenticated, feature-gated. Request: `{ "token": "pwr_<one-time-secret>", "password": "a policy-compliant password" }`.

| HTTP | Response | Condition |
|---|---|---|
| `200` | `{ "status": "password_reset" }` | Token consumed atomically, verifier replaced, failed-attempts/lock/forced-change cleared, and session generation incremented so existing password sessions are invalidated. **No identity fields or bearer token are returned.** |
| `400` / `401` / `410` | `validation_failed` / `weak_password` / `invalid_reset_token` / `reset_token_expired` | Same shapes as the invite-setup route; reset tokens are single-use and expire after 30 minutes. |
| `429` | `{ "error": "rate_limited", … }` | Reset-set client limiter (10/minute per client key). |

### `POST /v1/auth/mfa/enroll` · `/v1/auth/mfa/verify` · `/v1/auth/mfa/disable`

Authenticated TOTP conditional access under the `profile:mfa` permission (every customer role). Enrollment generates a base32 RFC 6238 secret (SHA-1, 30 s, 6 digits) and returns `{ "status": "mfa_enrollment_started", "secret": "<base32>", "otpauth_uri": "otpauth://totp/…" }` exactly once; `verify` activates it after the user proves possession (`{ "totp": "<code>" }` → `{ "status": "mfa_enabled" }`); `disable` requires a currently valid code (`{ "status": "mfa_disabled" }`). Error shapes: `400 mfa_enrollment_not_started` / `409 credential_required` / `409 mfa_not_enrolled` / `401 mfa_invalid`. Logins for enrolled accounts require a non-replayed code (`mfa_required` / `mfa_invalid`); last accepted step is persisted to reject replay within the acceptance window. Audits `auth.mfa.enrollment_started`, `auth.mfa.enabled`, `auth.mfa.disabled`. Postgres persistence: migration `0043_password_resets_and_mfa.sql` (tenant-RLS `user_password_resets` with pre-tenant token-lookup policy; MFA columns on `user_credentials`).

## Tenant

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| GET | `/v1/tenants/current` | `tenant:read` | — | Tenant object incl. `privacy_settings`. |
| GET | `/v1/tenant/deployment-features` | `tenant:read` | — | `{ waf_posture, external_discovery, connectors }`. `connectors` is `isConnectorsEnabledForTenant(runtimeConfig, tenant)` (`ASTRANULL_CONNECTORS_ENABLED` + `ASTRANULL_CONNECTORS_ENABLED_TENANTS`), the single source of truth. In Postgres mode the row in `tenant_connector_features` is a database projection of that value (read by SQL-level connector/worker gates); this endpoint, every `/v1/connectors*` route, and `targets:bulk-import` with `connector_id` reconcile the projection to the runtime value (audited `connector.feature.enabled`/`disabled`, actor `runtime-config-connector-sync`), matching `scripts/connector-poll-runner.mjs`. |
| PATCH | `/v1/tenants/current` | `tenant:write` | `{ privacy_settings?, name? }` | Updated tenant. `privacy_settings.metadata_retention_days`, `evidence_retention_days`, and `audit_retention_days` are normalized/clamped on read and write (defaults **365** / **1825** / **2555** per migration `0034`); changing privacy settings runs an immediate metadata retention purge for the current tenant (see [Privacy retention](#privacy-retention-metadata)). |

> **Environments removed (ADR-0008).** `GET/POST/PATCH /v1/environments*` are gone and now return `404`. Environment membership is expressed as a target tag (`env:<name>`), backfilled by migration `0058`. The `environments` table stays dormant in the database until a separate approved cleanup migration.

## Target groups

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| GET | `/v1/target-groups` | `target_group:read` | `?archived=true` lists soft-deleted groups only | `{ items, count }` active groups by default (`deleted_at` / `archived_at` null). Each item carries the group row plus summary keys `target_count` (active declared targets in the group), `loa_state` (`signed` when an active LOA signature exists, else `required`), and `open_findings_count` (exact `open` lifecycle only — `in_progress` and closure statuses are excluded; legacy `state`-only rows count by their effective status; membership is the same overlap predicate the findings list uses, so per-group counts are per-finding links and their sum is not a unique tenant open total). The heavier detail fields stay on `GET /v1/target-groups/:id`. |
| GET | `/v1/targets` | `target_group:read` | No query string | `{ items, count, meta }` tenant-scoped inventory across active groups and targets. Every item exposes top-level `tags: string[]`. Verification, provenance, and eligibility are derived from authoritative server records, never target metadata. The legacy kind-only stamp `eligibility: "eligible"` with a null reason is rewritten on this read: a declaration whose verification is below the ownership-proof rank (`dns_verified`, `provider_verified`, `user_confirmed`) is `not_runnable_now`. A recorded proof stays `eligible`. This read does not start a run. `POST /v1/test-runs` still applies the strict startup gate. `environment_id`/`environment_name` are no longer returned (ADR-0008). Any query string uses the declared-host predicate below (default unit `target`, page limit 1–200) and does not return this unpaged list. `400` on an unknown parameter. |
| POST | `/v1/targets` | `target_group:write` | `{ kind, value, expected_behavior?, tags?, target_group_id? }` | `201` target with top-level `tags`. Omitted `target_group_id` lands the target in the tenant default group — the active group whose `settings_json.default_scope === true`, created on demand (`Default`, `external_only`, UTC, `expected_behavior_default` from body or `block_at_edge`) and audited. `400 invalid_target` / `invalid_target_tags`, `404 target_group_not_found` for an unknown explicit group, or `409 target_exists`. Audited `target.added`. |
| PATCH | `/v1/targets/:id` | `target_group:write` | `{ tags?, expected_behavior? }` | Updated target (top-level `tags`), `404 not_found`, or `400 invalid_target_tags`. Kind/value are immutable. A patch that omits `tags` never erases existing tags. Audited `target.updated`. |
| GET | `/v1/targets/:id/compatible-checks` | `target_group:read` | — | Read-only catalog compatibility for that target. `runtime_launch_gates` and every pair `launch_block_reason` are `not_evaluated`; `launchable` is `null`. Does not start a run. `404` when the target is missing or another tenant's. |
| GET | `/v1/targets/:id` | `target_group:read` | `?runs_limit=&findings_limit=&findings_cursor=` | Target-detail hydrator. `target` includes top-level `tags: string[]` (ADR-0008). `target.eligibility` uses the same runtime rule as the unfiltered list: an unproven declaration is `not_runnable_now`; recorded proof stays `eligible`. `eligibility_reason` is left as stored. Coverage launch gates stay `not_evaluated` and `launchable` stays null. In addition to target, verification, WAF posture, checks, runs, findings, LOA, and counts, `edge_detection` contains the latest persisted signed-worker classification described below. |
| GET | `/v1/analytics/declared-hosts` | `target_group:read` | See below | Current-scope WAF/CDN cohort. Default unit `normalized_hostname`. |
| POST | `/v1/target-groups` | `target_group:write` | `{ name, description?, timezone?, safe_test_windows?, safety_policy?, settings_json? }` | `201` group with server-owned `ownership_status: "unverified"`, `dns_ownership: null`, and `validation_mode: "external_only"`. Active names are unique **per tenant** (case-insensitive). `environment_id` is ignored on write and omitted from responses (ADR-0008). Client ownership fields are ignored. |
| GET | `/v1/target-groups/:id` | `target_group:read` | — | Active group with active `targets[]` (each with top-level `tags`), `target_count`, LOA data, six recent runs (including persisted `policy_id` when scheduled), finding summaries, and empty-state `meta`. Archived target rows remain in history but are not returned. |
| PATCH | `/v1/target-groups/:id` | `target_group:write` | partial group fields | Updated group or `404`; changing the name rechecks the tenant-wide name uniqueness. `environment_id` is ignored; `validation_mode` always resolves to `external_only`. |
| DELETE | `/v1/target-groups/:id` | `target_group:write` | — | Soft-archives the group (`deleted_at`, `deleted_by`) or returns `409 target_group_active_run` while an active run still references it. |
| POST | `/v1/target-groups/:id/restore` | `target_group:write` | — | Clears `deleted_at` / `deleted_by` and returns `{ target_group }`; returns `404 not_archived` or `409 target_group_exists` when restoration would collide. |
| POST | `/v1/target-groups/:id/targets` | `target_group:write` | `{ kind?, value, expected_behavior?, tags?, metadata? }` | `201` canonical target (with top-level `tags`), `400 invalid_target` / `invalid_target_tags` for malformed values (including `IP:port` with kind `ip`), or `409 duplicate_target`. |
| POST | `/v1/target-groups/:id/targets:csv` | `target_group:write` | `multipart/form-data` with the CSV in field `file` (portal), raw `text/csv`, or JSON `{ csv }` | Customer CSV declaration (no discovery). **All-or-nothing:** `201 { created: Target[], errors: [] }` only when every row passes the same validation as `POST /v1/target-groups/:id/targets` (kind/value normalization, per-group dedupe); otherwise `422 { error: "csv_import_rejected", created: [], errors: [{ row, error, field?, message }] }` and nothing is written. `row` is the 1-based file line. Limits: 256 KiB CSV, 1000 data rows (`413 csv_too_large` / `csv_too_many_rows`). Header row optional: recognized columns `kind`/`type`, `value`/`target`/`fqdn`/`hostname`/`domain`/`url`/`ip`, `expected_behavior`; `label`/`name`/`notes` are ignored; other columns (incl. `port`, use `tcp` + `host:port`) → `400 invalid_csv`. Without a header: 1 column = value, 2 = kind,value, 3 = kind,value,expected_behavior. Missing kind: the value-column name (`ip`/`url`/`fqdn`) or inference (IP → `ip`, `http(s)://` → `url`, else `fqdn`). Audits `target.added` per row (`import_source: csv`) plus one `target.csv_imported` summary; Postgres writes all rows and audits in one tenant transaction. `404` for unknown or other-tenant groups. |
| POST | `/v1/target-groups/:id/targets:bulk-import` | `target_group:write` | `{ items: Target[], source?, connector_id? }` | `201 { imported, skipped, count }`. With `connector_id`, only canonical values present in that tenant-owned connector's latest inventory may be imported; otherwise source labels are customer declarations and are not trusted provenance. |
| PATCH | `/v1/target-groups/:id/targets/:targetId` | `target_group:write` | partial target fields (incl. `tags?`) | Updated canonical target (with top-level `tags`), `404`, or scoped validation/dedupe/`invalid_target_tags` error. |
| DELETE | `/v1/target-groups/:id/targets/:targetId` | `target_group:write` | — | Soft-deletes the target (`deleted_at`, `deleted_by`) while retaining verification, run, and audit history. |

Every target payload (inventory items, detail targets, group-detail targets, POST/PATCH responses) exposes top-level `tags: string[]` stored in target metadata. Tag rules (ADR-0008): trimmed, lowercased, matched against `^[a-z0-9][a-z0-9:_.-]{0,47}$`, deduplicated, at most **16** per target; invalid input returns `400 invalid_target_tags`. `tags` is a reserved metadata key, so a client metadata blob can neither spoof nor erase the trusted tag list, and a metadata-only patch preserves the existing tags.

Canonical target kinds are `fqdn`, `ip`, `url`, `tcp`, `dns_zone`, and `canary` (`domain`/`hostname` normalize to `fqdn`; omitted kind remains `fqdn`). FQDNs are lowercase without a trailing dot, URLs are credential-free HTTP(S) URLs without fragments, and TCP values use `host:port` or `[IPv6]:port`. Active target uniqueness is tenant/group/kind/canonical-value scoped. Every successful mutation is audited; Postgres mutation and audit rows share the same tenant transaction. Client ownership, verification, eligibility, source/provenance, audit, and internal provenance metadata fields are stripped rather than trusted.

### Target detail edge-detection summary

Execution logs: `GET /v1/test-runs/:id/activity?limit=200` requires `test_run:read` and returns a passive, tenant-scoped `{ run_id, check_id, target_id, status, created_at, started_at, completed_at, requests_sent, telemetry_recorded, items, count, truncated }` snapshot. Counts are nullable until recorded; simulations are explicitly labeled. `items` describe recorded run lifecycle, authenticated worker attempts/requests/responses/phases, not-sent reasons, and final results. Paths withhold declared private query values; generated benign markers and bounded redacted application payload previews are available in expanded events. Credential/header values and raw protocol packets are excluded. Events include their vector/check identity, actual method, Content-Type, status, payload encoding and explicit truncation state. Across-tenant reads return 404.

The internal worker publishes batches to `POST /internal/probe/jobs/:id/activity` with the existing HMAC over path, method, timestamp, tenant and raw body. Only the current lease holder may publish for an active run. Body: `{ leased_at, items: [{ sequence, at, stage, operation?, method?, url?, protocol?, status_code?, duration_ms?, error_class?, reason?, requests_sent?, body_bytes?, header_names?, outcome?, phase?, request_content_type?, response_content_type?, request_payload_preview?, request_query_preview?, response_payload_preview?, request_payload_encoding?, response_payload_encoding?, request_payload_truncated?, response_payload_truncated?, response_bytes_observed?, response_bytes_captured?, response_payload_available? }] }`, at most 16 items/32 KiB per batch and 256 ordinals per lease. Unknown/raw fields return 400; canceled or changed leases and conflicting replays return 409; wrong holders return 403. Identical replays are immutable. Activity is not verdict evidence and public `/v1/events` cannot publish this signal. Existing audited test-run and validation-scan cancel APIs provide the Stop controls.

Customer-facing edge evidence uses `evidence.waf_fingerprint` and `evidence.edge_classifier`. Retained source keys are normalized at presentation time, including inspector evidence. New labels are **AstraNull WAF fingerprint** and **AstraNull edge classifier**. Stored signed evidence, corpus provenance, and custody digests are unchanged.

Fingerprint version `2.1.0` additionally exposes bounded `evidence.asn_dataset_version` (SHA-256 or null), `evidence.asn` (nullable `{ asn, name, org, provider, country }`), `evidence.asn_matches[]` (`{ provider, asn, org, name }`), and `evidence.cname_cdn_matches[]` (`{ provider, family, suffix }`). ASN-derived CDN layers have source `asn_lookup`. These are network-ownership observations, not proof of WAF enablement or enforcement. Zero marker attempts yield inconclusive effectiveness and cannot establish an unprotected posture. A known WAF without enforcement evidence is `detected_only`. Existing event/custody records are retained; a new versioned run is required for corrected CDN classification.

A fingerprint-only deadline can retain `partial_provider_observation: true` in the signed result when vetted DNS already provided positive typed CDN/cloud evidence. The polling API and current target observation then remain overall `inconclusive`, with the supported provider family `detected` and WAF `inconclusive`; effectiveness is untested. A failed HTTP operation never becomes a protected verdict, and failures without typed DNS provider evidence keep the existing error behavior. CloudFront/Fastly CDN and generic ELB plugin matches cannot establish WAF presence. Framer response/CNAME signatures identify its own edge hosting.

`GET /v1/targets/:id` coverage uses the persisted latest run's check/scenario versions and producer classification. Valid signed external runs with finalized, evidence-backed verdicts count as conclusive or inconclusive without rewriting stored results. Missing versions remain partial; mismatches return `check_version_mismatch` or `scenario_version_mismatch`. Declaration-only E1, `metadata_marker`, and control-plane `ops_readiness` checks appear as excluded pairs with `exclusion_reason: "declaration_only"`, outside the live applicable/not-run denominator. Setup-dependent checks retain `setup_required`. E2 and observation-only probe kinds are excluded with `exclusion_reason: "observation_only"`; `coverage.observation_only_count` gives their count. `coverage.inconclusive_reasons` is an additive array of `{ reason, label, next_step, count, check_ids }` describing current applicable inconclusive pairs. Its counts sum to `coverage.inconclusive_count`. Read-only detail projection never rewrites historical verdicts. The portal Run all selection omits observation-only checks; individual observations remain available. A single-check start runs only that check; `POST /v1/validation-scans` with the reviewed compatible check IDs starts the sequential batch and preserves every ownership, SOC, rate, window, and concurrency gate.

`GET /v1/targets/:id` returns `edge_detection: null` until a trusted, non-simulated `waf.fingerprint.safe` result has been persisted. When present, the additive object retains the existing `status`, `reason`, `waf`, `cdn`, `cloud`, provider lists, confidence, corpus/run timestamps, and metadata-only evidence fields, and also returns:

- `layers[]`: each independently observed CDN, WAF, or cloud layer with `provider`, corpus-derived `family`, bounded `sources[]` (`response_fingerprint`, `address_range`, `cname_suffix`, or `response_header` — a curated vendor-unique CDN/edge-platform response header such as `x-vercel-id`, `x-azure-ref`, or `x-amz-cf-id`; header layers are always `cdn` family and never imply a WAF), `confidence`, and `evidence_consistency`. Different providers are not collapsed into one vendor. Conflicting/ambiguous evidence is explicitly flagged and lowers aggregate confidence.
- `effectiveness`: `{ status, label, attempted_count, tested_count, blocked_count, passed_count, inconclusive_count, percentage, coverage_complete, required_class_coverage_complete, per_class }`. `percentage` uses only definitive marker outcomes and is `null` when the denominator is zero or no WAF was detected. `present_but_not_effective` means a WAF signature was observed and all three required safe marker classes were tested but every usable marker passed. Transport errors and timeouts remain `inconclusive` and can never produce a protected claim. Inspection-limit coverage is `not_tested` unless that specific bounded probe supplied evidence.
- `protection`: the evidence-tiered posture. `protected` requires external marker blocking plus bound origin/agent corroboration; `edge_protected` is external-only; presence alone is `detected_only`.
- `network_firewall`: direct-origin reachability is reported independently from application-layer bypass. Any HTTP response from the declared direct origin proves network reachability, while `application_bypass_confirmed` remains separate. `port_exposure.status` is `not_tested` for the fingerprint scan and points to the separate bounded `l3.firewall_exposure_scan.safe` check; no closed-port claim is inferred by absence.
- `plain_language_summary` and `summary.{edge,effectiveness,network_firewall}`: non-technical explanations derived from those same evidence-backed fields (for example, `Detected Amazon CloudFront (CDN) and AWS WAF. The WAF blocked 9 of 10 safe test probes (90%).`).

The object contains labels and bounded metadata only; raw headers, cookies, bodies, and packet content are never returned.

### Declared-host analytics

`GET /v1/analytics/declared-hosts` and a `GET /v1/targets` URL that has any query string share one predicate. Permission is `target_group:read` (viewer included). Postgres without the reader returns `503 postgres_route_not_wired`. There is no default estate cap; a finite snapshot of 5001 or 10000 rows returns `complete: true` and that exact `total`. The page limit is 1–200 (default 50). The response page is not the whole estate.

`as_of` is the caller evaluation clock, not a historical selector. `scope` is `current`, `historical` is false, and `snapshot_id` is null. Omitting `as_of` on the first page uses the server clock and returns it. A later page without `as_of` keeps the cursor clock. A different `as_of` than the cursor is `409 cursor_clock_mismatch`.

Allowlisted query keys: `q`, `target_group_id`, `verification_state`, `kind`, `tag`, `service_role`, `criticality`, `owner_status`, `owner`, `family`, `family_status`, `freshness`, `has_open_finding`, `unit`, `cursor`, `limit`, `as_of`, `cohort_version`. Explicit aliases, applied only when the canonical key is absent or equal: `search`→`q`, `group`→`target_group_id`, `verification`→`verification_state`, `role`→`service_role`. Unit tokens: `normalized_hostname`→`hostname`, `declared_target`→`target`. `origin_status` is not an alias. Unknown names and unknown enum values are `400` (`unknown_query_param`, `invalid_query_value`, `family_required`, `invalid_limit`, `invalid_cursor`, `invalid_as_of`), not an empty cohort.

`cohort_version` is a hash of the echoed filters plus every target id in the requested unit. Send it back with the same filters. A changed scope is `409 cohort_changed` with `filters`, `as_of`, `scope: current`, `historical: false`, and no `total` or `items`. Refetch the same filters without `cohort_version`. A cursor from another filter set is `409 cursor_filter_mismatch`.

Analytics JSON (family `waf` or `cdn` selects the segment array; the family does not drop rows unless `family_status` or `freshness` is set):

- `unit`: `normalized_hostname` or `declared_target` (the dashboard compares this string). `canonical_unit`: `hostname` or `target`.
- `denominator`: requested-unit total. `units.target_records` and `units.normalized_hosts` are both counts from the same snapshot.
- `segments`: array copied from `rollup.segments.all` for the requested family. Each item is `{ key, count, percentage, list_query }`. Keys are `detected`, `not_detected`, `inconclusive`, `not_checked`, `not_recorded`, `stale`, `conflict`. The `unknown` bucket is not in this array.
- `unknown_count`: that family's `unknown` bucket only. It is not `unknown` + `not_checked` + `not_recorded`. `null` when `family` is omitted.
- `stale_count`: the `stale` bucket (also present as a segment). `null` when `family` is omitted.
- `list_query.query`: echoed filters. `unit` inside that object is the canonical `hostname` or `target`. The targets page copies `service_role`, `criticality`, `owner_status`, `tag`, `family`, `family_status`, `freshness`, `has_open_finding`, and `unit` from it.
- `role_segments`: the role rollup (`all`, `api`, `login`, `website`, `unclassified`).
- `page`: `{ items, count, total, next_cursor, limit }`, also copied to the top-level `items`, `count`, `total`, `next_cursor`, and `limit`.
- `source`: `active_declared_targets`. `version`: `declared-host-analytics.v1`. `as_of_semantics`: `caller_evaluation_clock` or `not_recorded`.
- `rollup.freshness_policy.applied` stays false. The reader still stamps family freshness with `deriveProtectionProfile` at `as_of` before the predicate runs. `conflict` wins over `stale`.

Filtered `GET /v1/targets` keeps legacy `items`, `count`, and `meta`, and adds `total`, `page`, `units`, `filters`, `list_query`, `as_of`, `cohort_version`, `scope`, `historical`, `complete`. Its `unit` is the canonical token (`target` by default). Its `segments` is the role rollup object, not the family array. `page.total` and `total` match the analytics denominator for the same filters and unit.

No raw edge metadata, evidence JSON, or connector config is returned. `verification_state` is the effective state: a stored `provider_verified` proof is `pending` when the connector feature is disabled or the provider source is not current. The field is that status only. A missing verification stays null and matches `verification_state=unknown`, not `unverified`.

`GET /v1/targets/:id/compatible-checks` returns `{ target_id, kind, value, target_group_id, runtime_launch_gates, launch_block_reason, coverage, checks }`. Each check copies the catalog identity (`check_id`, `name`, `version`, `vector_family`, `supported_targets`, `required_customer_setup`, `safety_class`, `risk_class`) and forces `runtime_launch_gates`, `launch_block_reason` to `not_evaluated` and `launchable` to `null`. Pairs the target kind cannot run are omitted. Probe profiles are not copied.

### Target history and origin bindings

Read-only family history for a declared target plus the declared protected→origin bindings. Dev and Postgres implement the same routes through the target history services (Postgres mode never falls back to the dev store; an unwired or partial service is `503 postgres_route_not_wired`). A missing target or a target owned by another tenant is `404 not_found`. Every read below is passive: it never writes observations, current pointers, bindings, runs, or audits.

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| GET | `/v1/targets/:id/observations` | `target_group:read` | `?family&from&to&cursor&limit` | `{ items, count, next_cursor, filters, current[], comparison }`. `items` is the newest-first page of projected observations (`id`, `tenant_id`, `target_id`, `target_group_id`, `family`, `check_id`, `test_run_id`, `source_kind`, `source_id`, `corpus_version`, `scenario_version`, `check_version`, `observed_at`, `source_completed_at`, `outcome`, `attempt_class`, `producer_kind`, `origin_binding_id`, redacted `provenance`, `created_at`); internal nonce/digest columns are never returned. `limit` is 1–100 (default 50); `next_cursor` is opaque and resumes exactly at the page boundary. `filters` echoes the applied filter set. `current[]` is the per-family retained state (`family`, `last_successful`, `latest_failed_attempt`, `fresh_negative`, `provider_loss`). `comparison` compares only the two newest successful observations per family on an unfiltered page (`scope: newest_page`; with `cursor`, `from`, or `to` it is `filtered_page` and empty): `comparable_changes[]` holds comparable changed pairs and `comparison_gaps[]` holds pairs that cannot be compared, each entry `{ family, previous_id, observation_id, comparable, reason, change, direction, details? }` where `details` on a `provider_changed` pair is `{ before_provider, after_provider }` from recorded provenance only; gap reasons include `provider_not_recorded`, `missing_version`, `corpus_changed`, `scenario_changed`, `check_version_changed`, `context_mismatch`, and `transport_failure`. Failed attempts never compare. `400` `invalid_family`, `invalid_timestamp` (with `field`), or `invalid_cursor` for bad query values. |
| GET | `/v1/targets/:id/origin-bindings` | `target_group:read` | — | `{ items, count }` where the target is the protected side or the origin side of the binding. Items carry `id`, `tenant_id`, `protected_target_id`, `protected_target_group_id`, `origin_target_id`, `origin_target_group_id`, `host`, `sni`, `port`, `path`, `status`, `assurance` (always `none`), `lockdown` (`not_tested`), `relation` (`declared_binding`), `capacity_assurance: false`, `currently_authorized`, `authorization_state`, `created_at`, `archived_at`. No binding read starts a run or probe. |
| POST | `/v1/origin-bindings` | `target_group:write` | `{ protected_target_id, origin_target_id, scope? }` | `201` active binding. `host`, `sni`, `port`, and `path` are derived server-side from the protected target and its declared `allowed_scope` — a body cannot retarget them; a body containing `direct_ip`, `discovered_endpoint`, `endpoint`, or `destination` anywhere is `400 scope_not_declared`. `status: active`, `assurance: none`, `lockdown: not_tested`, `currently_authorized` reflects the origin's current proof. Replaying the exact same active pair with the same derived scope returns `200` with `replayed: true` and no second audit. Errors: `400 protected_target_not_hostname`, `400 scope_mismatch` / `port_unspecified` / `path_unspecified` / `declaration_scope_invalid`, `409 ownership_not_verified` (the origin target must carry a current ownership proof), `409 binding_target_mismatch` (identical pair), `409 scope_conflict` (same active pair, different scope), `404 unknown_target` (missing, other-tenant, or foreign-tenant protected target), `403` for viewers. Audited `origin_binding.created` exactly once per pair. |
| GET | `/v1/origin-bindings/:id` | `target_group:read` | — | One binding with the fields above; tenant-scoped `404` for an unknown or other-tenant id. Read-only. |
| POST | `/v1/origin-bindings/:id/archive` | `target_group:write` | — | `200` archived binding (`status: archived`, stamped `archived_at`); `currently_authorized` flips to false. Archiving again is `409 already_archived`; unknown or other-tenant id is `404`. Audited `origin_binding.archived` exactly once. A binding is not an origin lockdown and not a capacity assurance; reachability evidence for a bound origin is only accepted from an approved host/SNI check against the bound origin recorded after the binding was created. |

`GET /v1/targets/:id` (target detail) additionally exposes the same history read model under both `protection_profile` and `coverage`: `retained_family_states[]`, `comparable_changes[]`, `comparison_gaps[]`, and `origin_bindings[]` as explicit arrays (empty when there is no recorded history), plus `protection_profile.origin` when the target is a bound origin.

## Tenant subscription and support summary

`GET /v1/subscription/current` is customer-accessible with `tenant:read` and returns only tenant-scoped subscription/account metadata plus derived usage counts. It does not create a default plan when no subscription exists; `subscription`, `plan`, and `account` can be `null`, and the React UI must show an empty/not-configured state instead of invented plan data.

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| GET | `/v1/subscription/current` | `tenant:read` | — | `{ tenant_id, account, subscription, plan, usage, support }` with usage derived from users, declared target groups, agents, safe runs started in the last hour, findings, high-scale requests, and recent tenant audit metadata. |

## Public signup and staff internal management

Public signup routes are intentionally narrow and expose only sanitized request state. Staff routes require service-account or staff principal access with `staff:*` permissions; customer principals are denied with `403 staff_forbidden`. In Postgres mode these routes fail closed with `503 postgres_internal_admin_not_wired` unless the internal management service is injected.

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| GET | `/internal/admin/overview` | `staff:signup:read` | — | Internal queue and tenant summary. |
| GET | `/internal/admin/signup-requests` | `staff:signup:read` | `state?` | `{ items }` signup queue. |
| POST | `/internal/admin/signup-requests/:id/approve` | `staff:signup:decide` | approval payload | Creates/updates tenant onboarding state; `404` or `409` on invalid lifecycle. |
| POST | `/internal/admin/signup-requests/:id/reject` | `staff:signup:decide` | rejection payload | Rejected request or `404`/`409`. |
| GET | `/internal/admin/tenants` | `staff:tenant:read` | `q?` | `{ items }` tenant directory. |
| GET | `/internal/admin/tenants/:id` | `staff:tenant:read` | — | Tenant detail or `404`. |
| PATCH | `/internal/admin/tenants/:id` | `staff:tenant:write` | allowed tenant fields | Updated tenant detail or validation error. |
| GET | `/internal/admin/tenants/:id/subscription` | `staff:subscription:read` | — | Subscription and entitlement summary. |
| PATCH | `/internal/admin/tenants/:id/subscription` | `staff:subscription:write` | subscription fields | Updated subscription or validation error. |
| POST | `/internal/admin/tenants/:id/entitlements` | `staff:entitlement:write` | entitlement grant | Upserted entitlement grant. |
| POST | `/internal/admin/tenants/:id/users/:userId/resend-invite` | `staff:support:write` | invite metadata | Invite resend intent. |
| POST | `/internal/admin/tenants/:id/users/:userId/disable` | `staff:support:write` | reason metadata | Disabled tenant user. |
| GET | `/internal/admin/approval-requests` | `staff:approval:read` | `state?, kind?` | `{ items }` internal approval requests. |
| GET | `/internal/admin/soc/high-scale-requests` | `staff:soc:read` (`soc_analyst`, `soc_lead`) | `state?, tenant_id?, limit?` (≤500) | `{ items, count, tenants }` — cross-tenant summary of governed high-scale requests (`id`, `tenant_id`, `tenant_name`, `target_group_id`, `kind: high_scale`, `state`, `scheduled_window`, timestamps; no contacts, artifacts, or objectives) plus `tenants[{ tenant_id, name }]` for the SOC execution-tenant picker. Read-only: approval/schedule/start/stop/close/kill switch remain on tenant-scoped `/internal/soc/*` with `soc:*` permissions. Every read appends internal audit `staff.soc.high_scale_queue_viewed`. Postgres reads under `withPlatformScope()` via the SELECT-only `platform_scope_read_high_scale_requests` policy (migration `0056`). |
| POST | `/internal/admin/approval-requests/:id/decision` | `staff:approval:decide` | decision payload | Approval decision or lifecycle conflict. |
| GET | `/internal/admin/audit-log` | `staff:audit:read` | `tenant_id?, staff_id?, action?, limit?` | `{ items }` internal audit rows. |

## WAF posture add-on

**OpenAPI:** [`docs/api/waf-posture-openapi.json`](api/waf-posture-openapi.json) — OpenAPI 3.1 artifact for WAF assets, coverage analytics, safe validations, orchestrator execute/retest/cancel paths, CVE playbooks, action items, RBAC, and metadata-only safety notes. Check locally with `npm run api:waf:openapi:check`. This artifact does **not** close staging/live orchestrator, provider, or security/release signoff gates.

Disabled by default. `ASTRANULL_WAF_POSTURE_ENABLED=1` enables the current route family; when disabled, `/v1/waf/*` returns `404 { "error": "waf_feature_disabled" }`. The add-on does **not** require cloud/WAF credentials for core no-access mode. PostgreSQL schema, migration support (`0008_waf_posture` and `0057_waf_offensive_workflow`), repository primitives, and `runtime.services.wafPosture` adapters exist for the WAF asset/coverage/validation/drift routes. `runtime.services.wafOffensive` durably backs the customer request and internal SOC route families in Postgres mode. Custom Postgres servers missing the applicable injected WAF service fail closed with `503 { "error": "postgres_route_not_wired" }`; they never fall through to the dev JSON store.

WAF evidence is metadata-only. WAF validation contracts reject raw payload/body/header/packet fields, secrets, exploit material, SOC-gated profiles, prohibited profiles, automatic discovery approval, and protected-posture finalization without bound safe test-run evidence or explicit metadata-only scenario evidence.

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| POST | `/v1/waf/edge-detection` | `waf:run` | `{ target_group_id, target_id }` — both required opaque identifiers for an existing tenant-owned declared target. Raw `hostname`, URL/IP destinations, timeout overrides, and arbitrary probe fields are rejected (`400 raw_hostname_not_allowed`, `invalid_target_group_id`, `invalid_target_id`, or `unsupported_fields`). | `202 { detection_request }` only after the shared `testRuns.startTestRun` boundary durably accepts fixed check `waf.fingerprint.safe` for the exact group/target binding. The request includes `status: "queued"`, `test_run_id`, target ids, `check_id`, `run_status`, `test_run_url`, and `events_url`; response headers set `Location` to `test_run_url` and `Retry-After: 2`. Poll the returned test-run and events URLs for signed-worker evidence and the eventual verdict. The control plane performs no caller-directed DNS/HTTP egress; ownership, safe-window/rate, kill-switch, audit, and signed-worker dispatch gates are inherited from test-run start. The signed fingerprint profile uses pre-reserved, destination-pinned HTTP response evidence only: it does not collect standalone CNAME/A/AAAA or TLS hints, and it does not follow redirects. Missing test-run wiring fails closed with `503 edge_detection_test_runs_unavailable`; governed start denials pass through. |
| GET | `/v1/waf/assets` | `waf:read` | — | `{ items }` tenant-scoped declared WAF assets. |
| POST | `/v1/waf/assets` | `waf:write` | `{ target_group_id, canonical_url? \| hostname?, target_id?, owner_hint?, expected_waf_required? }` | `201 { asset }`. Discovery candidates cannot be auto-approved through this route. |
| GET | `/v1/waf/assets/:id` | `waf:read` | — | `{ asset, current_posture? }` or `404`. |
| PATCH | `/v1/waf/assets/:id` | `waf:write` | metadata fields only | `{ asset }`; unsafe/raw fields are rejected. |
| POST | `/v1/waf/assets/:id/exception` | `waf:write` | `{ owner, reason, expires_at, scope_hash? }` | `201 { exception, posture }`; approved metadata-only exception is tenant-scoped, future-expiring, audited, and available to compliance exports. |
| GET | `/v1/waf/exceptions` | `waf:read` | — | `{ items }` active, non-expired tenant-scoped WAF exceptions. |
| GET | `/v1/waf/coverage` | `waf:read` | `window_days?` | Status counts, `percentages`, aggregate `coverage_ratio`, and `trend[]` rollups when available. |
| GET | `/v1/waf/coverage/summary` | `waf:read` | — | Dashboard summary from `waf_coverage_summary` matview (dev-json parity via rollup refresh): `{ assets_total, protected, edge_protected, underprotected, unknown, coverage_pct, by_vendor, connectors_active, connectors_degraded, connectors_disabled, refreshed_at }`; `edge_protected` never increases `protected` or `coverage_pct`. |
| GET | `/v1/waf/offensive-suites` | `waf:read` | — | `{ suites[] }` SOC-gated offensive suite catalog (SQLi, XSS, RCE, etc.). |
| POST | `/v1/waf/offensive-requests` | `waf_offensive:request` | `{ waf_asset_id, objective, requested_suites[], emergency_contacts[], scope_confirmation: true, ... }` | `201 { offensive_request }`. Customer request only — SOC must approve and execute. |
| GET | `/v1/waf/offensive-requests` | `waf_offensive:read` | — | `{ items }` offensive validation requests. |
| GET | `/v1/waf/offensive-requests/:id` | `waf_offensive:read` | — | `{ offensive_request }` or `404`. |
| POST | `/v1/waf/offensive-requests/:id/artifacts` | `waf_offensive:write` | metadata-only authorization artifact | `201 { artifact }`. |
| POST | `/v1/waf/validations` | `waf:run` | `{ waf_asset_id, modes?, probe_profile?, marker_profile? }` | `201 { validation_run }`. Safe marker profiles enforce `max_requests` 1-5 and `timeout_ms` 100-5000. SOC offensive runs are created via `/internal/soc/waf-offensive/:id/start`, not this route. |
| GET | `/v1/waf/validations` | `waf:read` | — | `{ items }` validation runs. |
| GET | `/v1/waf/validations/:id` | `waf:read` | — | `{ validation_run, scenario_results }` or `404`. |
| POST | `/v1/waf/validations/:id/finalize` | `waf:run` | metadata-only summary and `scenario_results[]` | `{ validation_run, posture }`; writes a current posture snapshot, refreshes WAF posture findings for underprotected/unprotected outcomes, and creates/refreshes behavior-drift events when previously protected posture weakens. `protected` is returned only when WAF is detected and validation passes with corroborating metadata evidence. |
| GET | `/v1/waf/drift-events` | `waf:read` | — | `{ items }` open and historical behavior-drift events. |
| PATCH | `/v1/waf/drift-events/:id` | `waf:write` | `{ status, notes? }` | `{ drift_event }`; allowed statuses are `open`, `acknowledged`, `remediation_started`, `retest_pending`, `resolved`, `accepted_risk`, and `false_positive`. |

### Internal SOC WAF offensive workflow

All routes below require `soc:waf_offensive`. Every successful mutation is audited. Approval, schedule, start, stop, reject, and close lock the request row in the tenant transaction. A second approval must come from a distinct SOC user; start requires an accepted artifact of every type in `WAF_OFFENSIVE_REQUIRED_ARTIFACT_TYPES`, a current schedule window, an unchanged scope hash computed from the request target group's authoritative Postgres targets, and an inactive Postgres tenant kill switch. Start creates one linked `waf_validation_runs` row with `execution_class: "offensive_suite"` and `status: "planned"`; it does not expose a raw or unmanaged traffic generator.

| Method | Path | Request | Response / gate |
|---|---|---|---|
| POST | `/internal/soc/waf-offensive/:id/artifacts/:artifactId/review` | `{ status: "accepted"|"rejected"|"needs_revision", notes? }` | `{ artifact, authorization_pack_status }`; `404 artifact_not_found` for an unknown artifact. |
| POST | `/internal/soc/waf-offensive/:id/approve` | — | First distinct SOC principal moves to `under_review`; second moves to `approved` and binds `scope_hash`; repeated principal gets `409 duplicate_soc_approval`. |
| POST | `/internal/soc/waf-offensive/:id/reject` | `{ reason? }` | Moves submitted/review request to `rejected`. |
| POST | `/internal/soc/waf-offensive/:id/schedule` | `{ window_start, window_end }` | Moves approved request to `scheduled`; missing window or scope hash returns `409`. |
| POST | `/internal/soc/waf-offensive/:id/start` | — | Moves scheduled request to `running` and returns `{ offensive_request }`; `409 kill_switch_active`, `outside_schedule_window`, or `scope_hash_mismatch` fails closed without creating a run. |
| POST | `/internal/soc/waf-offensive/:id/stop` | — | Moves `running` to `stopped`. |
| POST | `/internal/soc/waf-offensive/:id/results` | `{ suite_results[] }` | Stores normalized metadata-only curated-suite results while `running` or `stopped`. |
| POST | `/internal/soc/waf-offensive/:id/post-test-report` | `{ executive_summary?, blocking_verdict?, bypass_findings?, remediation_notes? }` | Creates (`201`) or updates (`200`) the one report allowed for a stopped request. |
| GET | `/internal/soc/waf-offensive/:id/post-test-report` | — | `{ report }` or `404 report_not_found`. |
| POST | `/internal/soc/waf-offensive/:id/close` | — | Moves stopped request to `closed`; `409 post_test_report_required` until its report exists. |

### WAF coverage analytics

Implemented as read-only WAF analytics routes in developer validation and documented in [WAF API Contract](backend/13-waf-posture-api-contract.md). They remain subject to staging export signoff, scheduled rollup evidence, and WAF add-on release approval before customer-facing promotion.

| Method | Path | Permission | Response summary |
|---|---|---|---|
| GET | `/v1/waf/coverage/vendors` | `waf:read` | Vendor/product mix and counts. |
| GET | `/v1/waf/coverage/entities` | `waf:read` | Business-unit/subsidiary rollups. |
| GET | `/v1/waf/coverage/criticality` | `waf:read` | Coverage by `business_criticality`. |
| GET | `/v1/waf/coverage/geography` | `waf:read` | Coverage by declared region. |
| GET | `/v1/waf/coverage/risk-roadmap` | `waf:read` | Tier 1–4 deployment priorities. |
| GET | `/v1/waf/coverage/vendor-consolidation` | `waf:read` | Read-only multi-vendor advisory. |
| GET | `/v1/waf/products` | `waf:read` | Seeded WAF product catalog entries and metadata. |
| GET | `/v1/waf/scenario-intake` | `waf:read` | Submitted product/scenario intake requests. |
| POST | `/v1/waf/scenario-intake` | `waf:write` | `202` accepted metadata-only intake request; raw exploit/probe material is rejected by service contracts. |

CVE playbook routes (`/v1/waf/cve-pipeline/:id/playbook`, `/playbook/approve`, and `/coordinated-retest`) are implemented with `waf:read`, `waf:write`, and `waf:run` respectively; see [Multi-Vendor CVE Playbook](detection/17-multi-vendor-cve-mitigation-playbook.md).

### WAF connector framework

The connector routes are also disabled when `ASTRANULL_WAF_POSTURE_ENABLED` is off. The current slice is metadata-only: it stores connector configuration summaries and operator-provided normalized snapshots, but does not call provider APIs, discover assets, or require credentials for core validation. Credential material must live in the secret vault and be referenced by `secret_id`; raw configs, headers, bodies, logs, plaintext tokens, and full policy bodies are rejected.

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| GET | `/v1/connectors` | `waf:connector_read` | — | `{ items }` tenant-scoped connector metadata. |
| POST | `/v1/connectors` | `waf:connector_write` | `{ provider, name, secret_id?, config, status?, validate_only? }` | `201 { connector }`; `config` is reduced to allowlisted metadata such as `read_only`, resource hashes, owner hints, tags, and polling interval. `validate_only: true` runs the feature gate and the same validation without persisting or auditing and returns `200 { valid: true, connector }`; the portal calls it before storing a vault secret so a rejected connector cannot orphan a credential. |
| POST | `/v1/connectors/:id/validate` | `waf:connector_write` | — | `{ status, capabilities, redacted_errors?, connector? }`; validation is local-only and requires `config.read_only=true`. |
| POST | `/v1/connectors/:id/poll` | `waf:connector_write` | `{ snapshots?: [...] }` | `202 { poll_job, snapshots }`; this ingests normalized metadata snapshots only. |
| GET | `/v1/connectors/:id/snapshots` | `waf:connector_read` | — | `{ items }` normalized metadata snapshots. |
| GET | `/v1/connectors/:id/inventory` | `waf:connector_read` | `?cursor=&limit=` | Credential-free, canonical, deduplicated target candidates from the tenant-owned connector's latest snapshot: `{ provider, account, scope: "read_only", discovered_at, items, count, next_cursor? }`. Missing, disabled, or revoked connectors fail closed. |
| POST | `/v1/connectors/:id/disable` | `waf:connector_write` | `{ reason? }` | `{ connector }`. |

## Bootstrap tokens

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| POST | `/v1/bootstrap-tokens` | `bootstrap_token:create` | `{ name, target_group_id?, environment_id?, max_registrations?, expires_at?, prebind_fqdn?, deployment_packaging? }` — independent of agent update releases/trust keys; in Postgres an omitted `environment_id` is stored as `NULL` (no `env_demo` default); — optional `prebind_fqdn` (string) pins the FQDN an agent may report on heartbeat `probe_endpoint.declared_fqdn`; optional `deployment_packaging` is `image`, `standalone`, or `helm` (stored on token metadata). | `201` metadata + **`secret` once** (`ast_v1.…` tenant/token id hints; salted hash stored only; legacy opaque tokens still verify in dev store). |
| GET | `/v1/bootstrap-tokens` | `bootstrap_token:read` | — | List without hash/salt/secret. |
| POST | `/v1/bootstrap-tokens/:id/revoke` | `bootstrap_token:revoke` | — | Revoked token metadata. |

## Service accounts (automation)

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| POST | `/v1/service-accounts` | `service_account:create` | `{ name, role, scopes, expires_at? }` | `201` metadata + **`secret` once** (`svc_…`, not stored plaintext). `role` must be `admin`, `engineer`, `auditor`, or `viewer` (not owner/SOC). `scopes` are permission strings; each must be allowed by `role` unless `scopes` is `["*"]` (admin only). |
| GET | `/v1/service-accounts` | `service_account:read` | — | List without hash/salt/secret. |
| POST | `/v1/service-accounts/:id/revoke` | `service_account:revoke` | — | Revoked account metadata. |
| POST | `/v1/service-accounts/:id/rotate` | `service_account:rotate` | — | `200` metadata + **`secret` once** (`svc_…`). Prior bearer stops working immediately. Revoked accounts return `409` (`service_account_revoked`). Response omits `secret_hash` / `secret_salt`. |

API calls authenticate with `Authorization: Bearer <svc_…>`. RBAC checks require matching scope (or `*`) in addition to role permission. Revoked or invalid tokens return `401`. Service account tokens do not satisfy agent or probe-worker authentication.

## Secrets (integration credentials)

Tenant-scoped integration secrets are stored as **AES-256-GCM** envelopes. The public API never returns plaintext, ciphertext, or auth tags, and there is **no** decrypt endpoint—plaintext is accepted only on create and rotate.

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| POST | `/v1/secrets` | `secret:write` | `{ purpose, name, plaintext, metadata? }` | `201` `{ secret }` metadata + redacted envelope (no plaintext). `503` `{ error: "encryption_not_configured" }` when `ASTRANULL_SECRET_ENCRYPTION_KEY` is unset. Developer validation only (`npm start`/`dev:api` with dev-json or memory persistence, `NODE_ENV` ≠ production, no `ASTRANULL_DEPLOYMENT_PROFILE`): startup generates a key at `<dev data dir>/dev-secret-encryption.key` (mode 0600; ephemeral in memory with `ASTRANULL_NO_PERSIST=1`) and logs a warning. Postgres, deployment profiles, and production always require an explicit key. |
| GET | `/v1/secrets` | `secret:read` | — | `{ items }` metadata-only records per tenant. |
| POST | `/v1/secrets/:id/rotate` | `secret:rotate` | `{ plaintext, metadata? }` | `200` updated metadata + redacted envelope; `404` `{ error: "not_found" }`; `503` when encryption key is unset. |

Sensitive metadata keys are redacted on store and in responses. Internal workflows may decrypt for authorized use only (not exposed on `/v1`).

## Agents (outbound)

| Method | Path | Auth | Request | Response |
|---|---|---|---|---|
| POST | `/v1/agents/register` | bootstrap `secret` in body | `{ bootstrap_token, hostname, capabilities? }` | `201` `{ agent, agent_credential }`. |
| GET | `/v1/agents` | `agent:read` | — | Fleet list. |
| POST | `/v1/agents/:id/revoke` | `agent:revoke` | — | Marks the tenant agent `revoked`, records `agent.revoked`, and immediately rejects the old agent credential on heartbeat, jobs, observations, and update poll/status routes. `404` when the agent is not in the caller tenant. |
| POST | `/v1/agents/:id/heartbeat` | Bearer agent credential | `{ version, placement?, capabilities?, probe_endpoint? }` — optional `probe_endpoint` object (`declared_fqdn?`, `declared_ip?`, `discovered_public_ip?`, `agent_local_ip?`, `listen_port?`, `path_prefix?`, `discovered_via?` ∈ `operator_env` \| `cloud_metadata` \| `dns_resolve` \| `stun`). Server validates schema (FQDN format; routable IPv4/IPv6 literals rejecting loopback, link-local, metadata, RFC1918, and ULA unless dev-private override; port 1–65535; `path_prefix`; `discovered_via` enum), then applies binding: `declared_fqdn` must equal the bootstrap token `prebind_fqdn` when set and must appear among the agent target group FQDN targets when any exist. Failures set `probe_endpoint_status: rejected` and `probe_endpoint_error` to `invalid_probe_endpoint`, `fqdn_prebind_mismatch`, or `target_group_mismatch`; success stores normalized `probe_endpoint` with `probe_endpoint_status: reported` and updates `last_token_validation_at` / `last_token_validation_status` (`valid` on accepted binding path). Heartbeat always returns `200`; response includes `probe_endpoint_accepted` (boolean). Invalid endpoints are rejected without failing the heartbeat HTTP status. Fleet `GET /v1/agents` exposes `probe_endpoint`, `probe_endpoint_status`, `last_token_validation_at`, and `last_token_validation_status`. | `200` health update with `probe_endpoint_accepted`. |
| GET | `/v1/agents/:id/jobs` | Bearer | — | `{ jobs }` (long-poll up to ~3s). |
| POST | `/v1/agents/:id/jobs/:jobId/ack` | Bearer | — | Acknowledged job. |
| POST | `/v1/agents/:id/observations` | Bearer | `{ agent_job_id, test_run_id, target_id, nonce_hash, metadata? }` | Correlation input tied to acked agent job (`403` `agent_job_mismatch`, `409` `agent_job_not_acked`, `400` `missing_agent_job_id`, `400` `raw_packet_rejected`); metadata redacted; `429` `event_cap_exceeded` when run event budget is exhausted. |
| GET | `/v1/agents/:id/update` | Bearer | — | `{ update: null }` or `{ update: { release_id, action: upgrade\|rollback, version, channel, manifest, signature, rollback_version?, download: { manifest_url, signature_url, artifact_url } } }`. `download` carries absolute HTTPS URLs from the release (or embedded rollback) distribution metadata. Eligible upgrade from active releases matching staged rollout; rollback when release `state` is `rollback_requested` and agent previously reported `applied`. Host agents can consume `download` via `--download-and-apply-update`; **production gate:** unattended daemon orchestration, service restart, and fleet rollout/rollback drills. |
| POST | `/v1/agents/:id/update-status` | Bearer | `{ release_id, status, installed_version?, action?, error_code? }` | `201` status record. `status` must be `downloaded`, `verified`, `applied`, `failed`, or `rolled_back`. `installed_version` required semantics for version bump when `status` is `applied` or `rolled_back`. `error_code` optional lowercase identifier. Errors: `400` `invalid_release_id`, `invalid_status`, `invalid_installed_version`, `invalid_error_code`, `invalid_action`; `404` `not_found`. Audits `agent_update.status_recorded`. |

## Agent update releases (tenant admin)

Tenant-scoped ledgers: `agentUpdateReleases`, `agentUpdateStatuses` in developer validation; `agent_update_releases`, `agent_update_statuses`, and `runtime.services.agentUpdates` in `ASTRANULL_PERSISTENCE_MODE=postgres`. Manifests must use package `astranull-agent`, matching `version`, signed artifact metadata (safe `*.tar.gz` basename, SHA-256, positive size), `signing.signed: true`, detached Ed25519 signature over canonical manifest fields (same algorithm as `scripts/package-agent.mjs`).

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| POST | `/v1/agent-updates` | `agent_update:write` | `{ version, channel?, manifest, signature, distribution, rollout?, rollback? }` | `201` `{ release }` including stored `distribution`. `channel` defaults to `stable` (`stable`/`beta`/`canary`). Required `distribution`: `{ manifest_url, signature_url, artifact_url }` — each an absolute **HTTPS** URL (query strings allowed, e.g. CDN signed URLs); URL credentials rejected; malformed URLs and malformed `artifact_url` path encoding rejected; decoded `artifact_url` pathname basename must equal `manifest.artifact.name`. `rollout`: `{ percentage?, environment_ids?, target_group_ids?, agent_ids? }`. Optional `rollback`: `{ version, manifest, signature, distribution }` with the same distribution rules. Manifest `signing.public_key_der_base64` must match an **active** tenant trust key or `400` `untrusted_signing_key`. Errors include `invalid_version`, `invalid_channel`, `invalid_manifest`, `invalid_package`, `version_mismatch`, `invalid_artifact_name`, `invalid_artifact_sha256`, `invalid_artifact_size`, `unsigned_manifest`, `missing_signature`, `invalid_signature`, `missing_signing_public_key`, `invalid_signing_public_key`, `signature_verification_failed`, `invalid_rollout`, `untrusted_signing_key`, `missing_distribution`, `invalid_distribution_url`, `artifact_url_mismatch`, rollback-specific `missing_rollback_signature` / `invalid_rollback_signature` / `invalid_rollback_manifest` / `invalid_rollback_distribution`. Audits `agent_update.release_created` with metadata that **excludes** distribution URLs and query strings. |
| GET | `/v1/agent-updates` | `agent_update:read` | — | `{ items: Release[] }` for caller tenant. Malformed stored rows (missing id/version or non-object manifest) are skipped rather than failing the list; they are also never offered by agent update polls. |
| POST | `/v1/agent-updates/:id/rollback` | `agent_update:rollback` | — | `200` `{ release }` with `state: rollback_requested` when embedded rollback exists; `404` `not_found`; `400` `rollback_not_available`. Audits `agent_update.rollback_requested`. **Production gate:** fleet rollback drill with staging evidence (distribution metadata required at release creation). |

Tenant-scoped ledger: `agentUpdateTrustKeys` in developer validation; `agent_update_trust_keys` through `runtime.services.agentUpdates` in Postgres mode. Public keys are stored server-side; list/create responses are metadata-oriented (no raw DER in list payloads).

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| POST | `/v1/agent-update-trust-keys` | `agent_update:write` | `{ name, public_key_der_base64 }` | `201` `{ trust_key }` with `id`, `name`, `fingerprint_sha256`, `status: active`, timestamps. Validates DER SPKI Ed25519; rejects invalid key material and duplicate active fingerprint. Audits `agent_update.trust_key_added`. |
| GET | `/v1/agent-update-trust-keys` | `agent_update:read` | — | `{ items: TrustKey[] }` metadata for caller tenant (`id`, `name`, `fingerprint_sha256`, `status`, `created_at`, `revoked_at?`). |
| POST | `/v1/agent-update-trust-keys/:id/revoke` | `agent_update:write` | — | `200` `{ trust_key }` with `status: revoked`; `404` `not_found`; `400` `already_revoked`. Audits `agent_update.trust_key_revoked`. |

## Test policies

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| GET | `/v1/test-policies` | `test_policy:read` | — | `{ items }` active, non-archived per-target rules enriched with exact active target, target-group, and check metadata. Policies for archived groups are omitted. |
| POST | `/v1/test-policies` | `test_policy:write` | `{ target_group_id, target_id, check_id, cadence?, expected_verdict?, safe_windows?, timezone?, enabled?, max_concurrent_runs? }` | `201` policy. `target_id` is required and must name one active target in `target_group_id`. Exactly one active rule is allowed per tenant/group/target/check, so the same check may be scheduled independently for different targets in one group. Only customer-runnable safe checks can be bound; SOC-gated/high-scale checks return `403 soc_gated_check`, and a check whose `supported_targets` excludes the target's effective kind returns `400 target_kind_not_supported` with `check_id`, `target_kind`, and `supported_targets`. |
| PATCH | `/v1/test-policies/:id` | `test_policy:write` | `{ cadence?, expected_verdict?, safe_windows?, timezone?, enabled?, max_concurrent_runs?, state? }` | Updated rule or `404`; `state` is `active` or `paused`, `enabled` is strictly boolean, and scheduling fields are recalculated server-side. `target_group_id`, `target_id`, and `check_id` form the immutable policy identity and cannot be changed; archive and create a new policy to bind a different target or check. |
| DELETE | `/v1/test-policies/:id` | `test_policy:write` | — | Soft-archives the rule and returns the archived record or `404`. |

Cadence is one of `manual`, `daily`, `weekly`, or `monthly`; timezone must be an IANA name. Safe windows accept at most 14 `{ day, start, end, timezone? }` entries, with `Mon`–`Sun` days, strict 24-hour `HH:MM`, and same-day `start < end`. Event-triggered policies are not exposed because no durable event consumer is configured; `event_driven` or `event_trigger` input fails closed. `expected_verdict` is `pass`, `warn`, `fail`, or `manual_review`. The current safety and active-run invariants cap `max_concurrent_runs` at exactly `1`.

Developer JSON and Postgres both persist due time, schedule revision, lease state, last dispatch/run, and durable occurrence records. Runtime-internal scheduling (not a public lease endpoint) queries due rules by tenant, acquires expiring tenant-scoped leases, and derives a stable tenant/policy/scheduled-time idempotency key. In Postgres deployments, schedule `npm run test-policy:runner -- --tenant-id <tenant>` (or `--tenant-ids-file <path>`) from cron/Kubernetes CronJob; it requires signed-worker configuration, never enumerates tenants, supports metadata-only `--dry-run`, and does not auto-migrate. Before each probe/agent dispatch, run creation re-reads the active group, active target, ownership evidence, enabled rule binding, and live lease; failures cancel a just-persisted run. Successful scheduled runs retain `policy_id`. Policy mutations and dispatch transitions are audited transactionally in Postgres.

## Validation scans

A validation scan is an on-demand or scheduled batch of bounded safe checks against one exact target or a whole target group. It orchestrates ordinary test runs one at a time through the same `startTestRun` gates; see [Test Orchestration](backend/02-test-orchestration.md#validation-scans-multi-check-orchestration) and [ADR-0006](adr/0006-validation-scans-as-sequential-test-run-batches.md).

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| POST | `/v1/validation-scans` | `test_run:start` | `{ target_group_id, target_id?, check_ids, name?, scheduled_for?, recurrence? }` | `201` scan. Omitting `target_id` plans every active compatible target; incompatible pairs are returned in `excluded`. Run-now scans return already `running` with the first step in progress. `scheduled_for` must be at least one minute ahead; `recurrence` is `daily`, `weekly`, or `monthly` (string or `{ cadence, timezone }`) and requires `scheduled_for`. Errors: `400 invalid_validation_scan` (with `field`), `400 unknown_check`, `400 check_requires_additional_input`, `400 target_kind_not_supported`, `400 scan_has_no_runnable_steps`, `400 scan_too_large` (more than 500 check/target steps; `check_ids` is capped at 500), `403 soc_gated_check` (with `check_id`), `404 target_group_not_found`, `404 target_not_found`, `409 concurrent_scan_blocked`. |
| GET | `/v1/validation-scans` | `test_run:read` | `?target_group_id&target_id&status&limit` | `{ items, count, meta: { empty_reason } }`; `status` accepts a comma-separated list; `target_id` keeps only exact-target scans (the target detail page reads its latest run-all scan with `limit=1`). |
| GET | `/v1/validation-scans/:id` | `test_run:read` | — | Passive scan read: `{ scan_id, status, summary, steps[] (per-step `status`, `request`, `response`, `requests_sent`, `requests_simulated`, `verdict`, `test_run_id`, `error_code`, `skip_reason`, `eligible_at`), excluded[], schedule fields, abort_reason, cancel provenance }`. The read NEVER advances an active scan and NEVER dispatches a due scheduled scan — no HTTP caller, no role, and no query parameter (including `advance=true`, which is ignored) can trigger dispatch, child-run starts, or other side effects. Advancement happens only through the explicit runner path (`npm run validation-scan:runner`) or the internal start path. Step `error_code: probe_dispatch_failed` means the child run was cancelled because its signed probe job could not be created. |
| PATCH | `/v1/validation-scans/:id` | `test_run:start` | `{ target_id?, check_ids?, name?, scheduled_for?, recurrence? }` | `200` re-planned scan; only while `scheduled` and not leased by a dispatcher, else `409 scan_not_editable`. The scan row and its steps are replaced in one transaction. Audits `validation_scan.updated` with `changed_fields`. |
| POST | `/v1/validation-scans/:id/cancel` | `test_run:start` | `{ reason?, cancel_series? }` | `200` cancelled scan for `scheduled`, `pending`, or `running`; pending steps become `skipped`; every active child run bound to the scan (linked to a step or not) is cancelled with `source: scan`, and a child run that commits after Stop is cancelled by the executor and audited as `validation_scan.orphan_run_cancelled`. `cancel_series: true` also removes the recurrence and cancels every scheduled occurrence in the series. `409 not_cancellable` otherwise. |
| GET | `/v1/validation-scans/:id/activity` | `test_run:read` | `?after=<cursor>&limit` | Passive read that never advances the scan or starts runs (an `advance` query parameter is ignored). `{ scan_id, status, items, count, cursor }`. `cursor` is opaque (`c1.` prefix) and tracks ingestion order (audit sequence plus event `ingested_at`), so polling with `after=<cursor>` returns late observations even when their event time precedes earlier items; items remain sorted by event time for display. A legacy item id is still accepted. Items are `{ id, at, kind: scan|run|event, action, summary, step_id, check_id, test_run_id, actor_role, metadata }` with allowlisted metadata only. |

Scan statuses are `scheduled`, `pending`, `running`, `completed`, `denied`, `cancelled`; step statuses are `pending`, `deferred`, `starting`, `running`, `collecting`, `verdicted`, `denied`, `skipped`, `cancelled`. A cooldown or a rolling hourly safe-run cap defers the next step (`eligible_at`); window, kill switch, suspension, or foreign concurrency denials stop the scan with the remaining steps `skipped`. Due scheduled scans are dispatched only after kill switch, suspension, group, safe window, and concurrency re-checks; denied dispatches audit `validation_scan.schedule_denied` and never force-run. HTTP callers cannot fabricate the internal `scanDispatch` context; child runs carry `scan_id` and `scan_step_id`. `GET /v1/checks` items include `section_id` and `section_label` (taxonomy attack-surface domain) for grouped selection. In Postgres deployments schedule `npm run validation-scan:runner -- --tenant-id <tenant>` from cron or a Kubernetes CronJob to dispatch due scans and advance running ones.

## Test runs

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| POST | `/v1/test-runs` | `test_run:start` | `{ check_id, target_group_id, target_id?, origin_binding_id?, retest_of_finding_id?, probe_profile? }` | Starts a manual run. HTTP callers cannot fabricate trusted policy dispatch context or a scheduled `policy_id`; scheduled runs enter through the runtime-internal leased dispatcher. Returns `201` run + correlation nonce, with simulation/probe-job details by configured mode. Safety denials include `429` window/rate/cooldown errors, `403 soc_gated_check`, `409 concurrent_run_blocked`, and signed-worker Host/SNI `400 missing_target_bound_direct_address` unless the verified target itself is an IP or IP-literal URL. A bound run (`origin_binding_id`) must pass the origin scope gate: active same-tenant binding, the run target exactly the bound origin, an approved Host/SNI check, the stored scope re-derived from the current declaration (`409 scope_mismatch` otherwise), and both origin and protected proofs current (`409 ownership_not_verified`); body destination keys are rejected outright. The signed job carries only the server-validated approved scope from the run's provenance stamp — a bound record without a stored approved scope fails closed (`probe_job_dispatch_failed` / recovery blocked) and target metadata can never repair it. Body `producer_kind`, `check_version`, `live`, and `expected_behavior` are ignored and recorded. A `retest_of_finding_id` requires `finding:write` and the same tenant/target/check pair. |
| GET | `/v1/test-runs` | `test_run:read` | query `target_group_id?`, `target_id?`, `check_id?`, `limit?` (default 100, max 100) | `{ items, count, meta.empty_reason }`, newest first; each item carries its published `verdict` (or `null`). Filters apply identically in dev-json and Postgres mode. |
| GET | `/v1/test-runs/:id` | `test_run:read` | — | Run detail + verdict when present. |
| GET | `/v1/test-runs/:id/events` | `test_run:read` | — | Timeline events. |
| POST | `/v1/test-runs/:id/finalize` | `test_run:read` | — | Verdict after collection window. |
| POST | `/v1/test-runs/:id/cancel` | `test_run:start` | `{ reason? }` | `200` cancelled run when status is `planned`, `running`, or `collecting`; `409` `{ error: "not_cancellable" }` for terminal runs. Pending or leased probe jobs and pending or acked agent jobs are revoked; the run records `summary.cancellation` and the `test_run.cancelled` audit carries `reason`, `cancelled_by`, `cancelled_by_role`, `source`, and revoked job ids. |

In `postgres` mode, `runtime.services.testRuns` backs the safe validation loop: `POST /v1/test-runs` and `POST /v1/test-runs/:id/cancel` enforce target declaration, customer-runnable check gating, prerequisites, safe windows, tenant rate/cooldown limits, concurrent-run blocking, tenant kill switch, audit logging, agent job dispatch, and signed probe-job creation in `signed-worker` mode; probe results ingest through `runtime.services.probeJobs`; agent `POST /v1/agents/:id/observations` uses exact-once job transition before observation evidence is written; probe/agent events correlate; automatic verdict publication runs when both sides correlate; `POST /v1/test-runs/:id/finalize` forces bounded no-observation finalization after the observation window; findings upsert from verdicts; audits cover starts, cancellations, probe jobs, observations, verdict publication, no-observation finalization, findings, denials, and rejected observations; raw packet/payload/header fields are rejected for metadata-only evidence. Guarded high-scale/SOC routes are backed by `runtime.services.highScale` in Postgres mode. **Release blockers** remain live/staging Postgres acceptance and tenant unit-of-work/concurrency hardening under load, not rewiring these route families.

## Findings

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| GET | `/v1/findings` | `finding:read` | `?q&status&severity&check_id&target_group_id&target_id&test_run_id&limit&page&offset` | `{ items, count, total, page, pages, has_more, limit, meta: { empty_reason } }`. `count` and `total` are the full matched count for the applied filters (not the page size), `has_more` is `page * limit < total`. `limit` is 1–200 (default 50), `page` 1–1,000,000; `offset` conflicts with `page` (`400`). `q` matches safe identity columns only (`title`, `id`, `check_id`, `target_id`, `target_group_id`, `assignee`); notes and evidence are never searched. `status=all` and `severity=all` mean unfiltered. Unknown parameters or unsupported values are `400` (`unknown_query_param`, `invalid_query_value` with `field`). Repeated query parameters, including a repeated blank, are `400 invalid_query_value`; internal repository parameters are not accepted over HTTP. Items are external-only customer projections (notes/remediation scrubbed). `target_group_id` matches findings stored in the group plus findings whose target is a member of it. |
| GET | `/v1/findings/:id` | `finding:read` | — | Finding with `closed_at`, `lineage`, `retests`, `originating`, and `latest` retest lineage. `latest` carries `{ test_run_id, relation, status, finalized, completed_at, pending, can_advance_remediation }`: an unfinalized run is explicitly `pending` and never claims a later passing result or advances remediation on its own. Closure stamps `closed_at`; it does not claim a fix was proved. Siblings are never closed. `404` when missing or another tenant's. |
| PATCH | `/v1/findings/:id` | `finding:write` | `{ status?, notes?, assignee? }` | Updated external-only finding projection. Lifecycle transitions are validated: an unsupported `status` is `400 invalid_lifecycle`, never a false `200`; an open finding may be resolved/closed (stamping an audited `closed_at` — a closure timestamp, not a claim that a fix was proved), and reopening clears it. `404` when missing or another tenant's. Customer writes accept status, notes, and assignee only; supplied closure timestamps, verdict references, and evidence references are ignored. Audited `finding.updated`. |
| POST | `/v1/findings/:id/export` | `finding:read` | — | Redacted export JSON: existing finding fields plus top-level `custody` (digest manifest; see **Export custody** below). |

## Reports

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| GET | `/v1/reports` | `report:read` | `limit?` | `{ items, capabilities }`. `items` is generated report metadata for the tenant, newest first; each item carries `period` (`null` when the report was generated without a declared window). This GET does not generate, export, or send a report. `capabilities` is the builder contract below. |
| GET | `/v1/reports/capabilities` | `report:read` | — | `{ capabilities }` with the same object as `GET /v1/reports`. Registered before `GET /v1/reports/:id`, so `capabilities` is not a report id. Does not generate, export, or send. |
| POST | `/v1/reports` | `report:create` | `{ kind?, title?, period?, target_ids?, target_group_ids?, run_ids? }` | `201` report with summary when generation succeeds. A body the report service rejects (`error` plus `status`) is returned with that status, not `201`, and nothing is written. `period` is optional and must be one of `last-7-days`, `last-30-days`, `quarter`, `all-time`; anything else returns `400 { error: 'unsupported_period', supported_periods }`. Omitted or empty stores `period: null`. Scope keys are top-level exact id lists only: a `metadata.target_ids` / `metadata.target_group_ids` / `metadata.run_ids` block is `400 { error: 'unrecognized_scope', fields: ['metadata.…'] }`, never a silently ignored scope. |
| GET | `/v1/reports/:id` | `report:read` | — | Report metadata, including `period`. |
| GET | `/v1/reports/:id/export?format=json\|markdown\|html` | `report:read` | — | `format=json`: `{ payload, custody }`. `format=markdown` or `html`: redacted report text with an embedded **Custody** section (artifact id, `content_sha256`, canonicalization, `created_at`, optional `previous_audit_hash`). Self-contained HTML has no external scripts. Export stays on this route. `GET /v1/reports` does not export. |

### Report builder capabilities

`capabilities` on `GET /v1/reports` and `GET /v1/reports/capabilities` keeps `default_kind`, `default_format`, `default_period`, `kinds`, `formats`, and `periods` from `reportCapabilities()` and adds:

```json
{
  "scope": {
    "fields": ["target_ids", "target_group_ids", "run_ids"],
    "max_ids": 100,
    "declared_members_cap": 100,
    "omitted": "tenant"
  },
  "capture": {
    "runs_when_run_ids_omitted": 10,
    "findings": 100,
    "evidence": 100
  },
  "readiness_score": {
    "scoped": "unknown",
    "reason": "published_readiness_formula_is_tenant_wide"
  },
  "snapshot_frozen": true
}
```

`max_ids`, `declared_members_cap`, and the capture caps are the exported `MAX_REPORT_SCOPE_IDS` (100), `MAX_DECLARED_MEMBERS` (100), `MAX_CAPTURED_RUNS` (10), `MAX_SNAPSHOT_FINDINGS` (100), and `MAX_SNAPSHOT_EVIDENCE` (100). The builder enables only `scope.fields`. Omitted scope is the tenant. An explicit scope does not receive the tenant readiness formula: `readiness_score.scoped` is `unknown` for that reason. `snapshot_frozen` is true for a report generated through the current world reader. There is no `primary_run_id` capability. `primary_run_id` on the create body is `400 unrecognized_scope`. A generated summary stores `primary_run_id: null` and does not take `run_ids[0]`. `metadata.target_ids`, `metadata.target_group_ids`, and `metadata.run_ids` are `400 unrecognized_scope` and do not grant scope. Check-version stamping is not accepted on this body.

### Export custody (developer validation)

Report and finding exports attach a metadata-only **custody** manifest (`schema_version`: `astranull.custody.v1`) built by `src/lib/custody.mjs`:

- **Digest:** `content_sha256` is SHA-256 over the export payload using deterministic `json-key-sorted-v1` canonical JSON (plain objects/arrays only; unsupported types fail verification).
- **Linkage:** `previous_audit_hash` matches the global tamper-evident audit chain predecessor for the `report.exported` / `finding.exported` event; `previous_tenant_audit_hash` may be present when a prior tenant-scoped audit entry exists.
- **Verification:** clients can call `POST /v1/custody/verify` with `{ payload, custody }` (`audit:read`) or the local `verifyCustodyManifest({ payload, custody })` helper. Both recompute the digest; neither performs KMS/signature validation yet.
- **Verification response:** `/v1/custody/verify` returns `{ ok, verification }` with safe manifest metadata and `error` such as `custody_missing` or `content_sha256_mismatch`; it does not echo the submitted payload.
- **Audit metadata:** export audit rows record only `format`, `content_sha256`, and `custody_schema_version` (no full manifest duplication).
- **Verification audit:** custody verification records `custody.verified` with metadata-only status, artifact type, digest, and schema version.

**Production gates still open:** external signing/KMS ceremony, durable immutable evidence snapshots, retained export custody storage, retention/legal-hold enforcement evidence, and staging signoff. Digest manifests are **not** a substitute for signed immutable evidence archives.

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| POST | `/v1/custody/verify` | `audit:read` | `{ payload, custody }` | `200` `{ ok, verification }`; safe metadata only, no payload echo. Audits `custody.verified`. |

## Events and evidence

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| POST | `/v1/events` | `event:ingest` | `{ event_id, signal_type?, metadata?, test_run_id?, evidence? }` | `201` or `200` duplicate; rejects cross-tenant `tenant_id`, packet fields, and reserved producer signals (`probe_result`, `agent_observation`, `ownership_observation`) which must use signed-worker or authenticated-agent ingestion. |
| GET | `/v1/evidence` | `evidence:read` | — | `{ items }`. |
| GET | `/v1/evidence/:id` | `evidence:read` | — | Evidence record (metadata). |

## Production release evidence

Release readiness evidence is tenant-scoped, metadata-only, and validated by `src/contracts/productionReleaseEvidence.mjs`. Accepted kinds (canonical list in `PRODUCTION_RELEASE_EVIDENCE_KINDS`) are:

`third_party_security_review`, `migration_apply`, `operator_runbook_exercise`, `oidc_prod_auth_preflight`, `edge_protection`, `agent_sbom_provenance`, `agent_install_matrix`, `agent_mtls_gateway`, `agent_trust_key_ceremony`, `governed_adapter`, `provider_approval`, `kill_switch_drill`, `postgres_concurrency`, `dr_restore`, `ui_accessibility_matrix`, `notification_provider_config`, `probe_fleet_matrix`, `vector_safety_policy`, `secret_rotation_drill`, `observability_slo`, `support_readiness`, `evidence_snapshot_manifest`, `postgres_tenant_query_audit`, `rollback_fixforward`, `kms_vault_posture`, `control_plane_container_release`, `staging_e2e_matrix`, `compliance_legal_signoff`, `authorization_custody`, `placement_confidence_staging`, and `gateway_load_abuse`.

Each kind requires top-level metadata fields aligned with the corresponding operator evidence manifests (URIs, digests, signoff references, validation summaries, and a retained `evidence_uri` custody pointer — not raw logs, packet captures, SQL dumps, IP inventories, attachments, ciphertext, or secrets). Forbidden nested keys include packet/pcap/raw SQL/raw dump/target IP inventory/api key fields and other secret- or payload-bearing names; `authorized_scope_hash` and similar scope digests remain allowed.

**Developer validation vs production gates:** `POST` accepts metadata that passed contract validation and records custody pointers in the tenant ledger. That inventory step is **not** staging execution, operator drill completion, independent security review, SOC/legal signoff, or promotion approval. Rehearsal fixtures from `npm run release:sample-evidence` must not be treated as operator-attested production evidence.

In `postgres` mode, the route family is backed by `runtime.services.productionReleaseEvidence` and the `production_release_evidence` table.

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| GET | `/v1/production-release-evidence` | `release_evidence:read` | — | `{ items }` for the caller tenant. |
| POST | `/v1/production-release-evidence` | `release_evidence:write` | `{ kind, evidence, release_id?, notes? }` | `201` `{ evidence }` with redacted evidence metadata, validation result, creator, and `status: "accepted"`. Errors: `400` `invalid_evidence_kind`, `missing_evidence_fields`, or `forbidden_evidence_fields`. Audits `production_release_evidence.recorded` with kind/release id only. |
| GET | `/v1/production-release-evidence/attestation` | `release_evidence:read` | — | `200` `{ attestation, records }` — metadata-only staging readiness summary derived from **accepted** tenant ledger rows (see below). Viewers and other roles without `release_evidence:read` receive `403`. |
| GET | `/v1/production-release-evidence/:id` | `release_evidence:read` | — | Evidence record or `404` when missing or cross-tenant. |

### Attestation (`GET /v1/production-release-evidence/attestation`)

Aggregates accepted records for the caller tenant through the same logic as `scripts/staging-readiness-attestation.mjs` (`aggregateStagingReadinessAttestation`). The API always evaluates profile **`full`** (every kind in `PRODUCTION_RELEASE_EVIDENCE_KINDS`). Offline CLIs can scope required kinds with `--profile` (see [Offline attestation and gap audit](#offline-attestation-and-gap-audit)).

**Response shape**

- **`attestation`** — `artifact_type: staging_readiness_attestation`, `profile`, `release_id`, `production_ready`, `signoff_status` (`missing_evidence`, `invalid_evidence`, `evidence_complete`, or `blocked`), `required_evidence_kinds` (`required`, `present`, `missing`, `invalid`, `rejected`), `optional_evidence_kinds`, `blocker_summary`, `record_counts`, and `caveats`.
- **`records`** — per-kind summaries only: `id`, `kind`, `status`, `release_id`, `created_at`, `validation` (no `evidence` bodies, notes, or secret-bearing fields).

**Production gate caveat:** `attestation.production_ready: true` means the tenant ledger contains contract-valid **accepted** metadata for every kind required by the evaluated profile. It does **not** close [`docs/release-checklist.md`](release-checklist.md), external staging/security/SOC/legal gates, or customer promotion. Checklist rows and operator signoff outside AstraNull still govern release.

### Offline attestation and gap audit

| Command | Purpose | Profiles |
|---|---|---|
| `node scripts/staging-readiness-attestation.mjs --input <evidence.json> [--profile …] [--release-id rel] [--out file] [--validate-only]` / `npm run release:staging-attestation` | Metadata-only attestation over a local evidence bundle or record list | `full` (default), `safe-validation-ga`, `high-scale-ga` — see `STAGING_READINESS_RELEASE_PROFILES` in `scripts/staging-readiness-attestation.mjs` |
| `node scripts/production-readiness-gap-audit.mjs [--evidence bundle.json] [--release-id rel] [--out file] [--validate-only]` / `npm run release:gap-audit` | Cross-checks evidence inventory against **all** contract kinds plus open gates parsed from `docs/release-checklist.md` and this release plan; reports `external_gates` categories that local validation cannot satisfy | Inventory step uses the full kind set; pair with a profile-scoped staging attestation when evaluating `safe-validation-ga` or `high-scale-ga` milestones |

Both CLIs reject secrets, raw payloads, logs, packet captures, SQL dumps, IP inventories, tokens, database URLs, and ciphertext in input. `production_ready` in CLI output has the same meaning as the API field: evidence inventory only, not production sign-off.

## Notifications

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| GET | `/v1/notifications` | `notification:read` | — | `{ rules, events, events_window, latest_deliveries }` for the caller’s tenant. `events` is the 100 most recent events; `events_window` is `{ limit, returned, truncated }`. `latest_deliveries` maps each live rule id to its latest delivery attempt over the **full** attempt history (`{ id, event_id, status, reason, attempt_number, created_at, attempted_at }`, no destination or provider error), or `null` when the rule has no attempt. Removed rules are not listed. Rules expose `destination_preview` only; events include `delivery_attempts` (channel, `destination_preview`, status, timestamps). No cross-tenant data and no full provider destinations. |
| POST | `/v1/notifications` | `notification:write` | `{ channel?, destination?, triggers?, enabled? }` | Created rule on success with `destination_preview` only in the HTTP response. Validates `channel` (`in_app`, `webhook`, `email`, `slack`, `teams`), `triggers` (allowed set), and `destination`: non-`in_app` rules require one with no whitespace or control characters (`invalid_destination`, max 2048 chars); `email` must be a single address (`invalid_email_destination`); `webhook`, `slack`, and `teams` must be `https://` (or dev-only `http` hosts) without `user:password@` credentials (`invalid_webhook_destination` / `webhook_url_credentials_not_allowed`). Invalid input returns HTTP `400` with `{ error, status: 400 }`. **Default:** external channels record `queued_provider_not_configured` (no outbound send). **Opt-in:** set `ASTRANULL_NOTIFICATION_DELIVERY_MODE` to `webhook`, `email`, `slack`, `teams`, `all`, or a comma-separated list (for example `slack,teams`) to send redacted payloads for those channels (`delivered_provider` / `provider_retry_scheduled` / `provider_failed_dlq`). Email also needs `ASTRANULL_SMTP_HOST` (plus optional `_PORT`, `_FROM`, `_USERNAME`, `_PASSWORD`, `_STARTTLS`); without it email stays `queued_provider_not_configured`. Slack, Teams, and webhook destinations containing `user:password@` credentials or non-https URLs are rejected at the delivery precheck (`webhook_url_credentials_not_allowed` / `invalid_webhook_destination`). Each created rule includes a `delivery_note` derived from the active delivery mode for its channel. Events fire for `finding.high_severity`, `high_scale.state_change`, `safe_test.completed` (verdicted runs), and `report.ready` (after `POST /v1/reports`). Teams cards are capped at 28 KB and carry a portal link only when `ASTRANULL_PORTAL_URL` is set. Portal UI and setup guide: [`docs/integrations/04-notification-channels.md`](integrations/04-notification-channels.md). |
| PATCH | `/v1/notifications/:id` | `notification:write` | `{ enabled?, triggers?, destination? }` (at least one) | `200` updated rule with `destination_preview` only. Tenant-scoped: another tenant's or a removed rule returns `404 not_found`. The merged rule is validated exactly like `POST` (same destination and trigger errors); `channel` cannot change (`400 channel_immutable`); non-boolean `enabled` → `400 invalid_enabled`; empty body → `400 no_changes`. Audits `notification.rule_updated` with `{ channel, changed_fields, enabled, trigger_count, destination_changed }` (never the destination). `503 postgres_route_not_wired` if the Postgres service lacks the method. |
| DELETE | `/v1/notifications/:id` | `notification:write` | — | `200 { id, deleted: true, deleted_at }`. Soft delete: the rule is disabled, its stored destination is cleared, and it no longer emits, retries, or redrives; delivery history is kept. Tenant-scoped `404 not_found` for another tenant's or an already removed rule. Audits `notification.rule_deleted` with `{ channel }`. |
| POST | `/v1/notifications/provider-credentials` | `notification:write` | `{ channel, provider_id?, plaintext, webhook_url? (required for webhook), credential_id? (rotate) }` | Stores the provider secret encrypted (secret vault in `postgres` mode; `503 postgres_route_not_wired` if the vault is not injected). `201` on create, `200` on rotation, `{ provider_credential }` without the secret value. Errors return `{ error, message }`. |
| POST | `/v1/notifications/retries/process` | `notification:write` | `{ dry_run?, as_of? }` | Processes due `provider_retry_scheduled` attempts in forced metadata-only mode. Returns safe retry summary (`due_count`, `scheduled_not_due_count`, `held_count`, `cancelled_count`, `processed`, `network_sends_performed`) without internal `delivery_record`, full destinations, provider URLs, request/response bodies, logs, tokens, or secrets. A turned-off rule's attempts are held (`held_rule_disabled`, nothing written); a removed rule's are closed as `cancelled_rule_removed`. In Postgres, due work is read from the attempt ledger oldest-first and each attempt is claimed with a lease before processing ([ADR-0010](adr/0010-notification-delivery-leases-and-outbox-reconciliation.md)); the summary also carries `in_flight_count`, `claim_lost_count`, `lease_lost_count`, `pages_read`, `work_budget`, `budget_exhausted`, and, when outbox reconciliation is wired, a `reconciliation` object (`missing_count`, `reconciled_count`, `already_recorded_count`, `no_subscriber_count`, `failed_count`, `by_trigger`, `window_from`, `window_to`). Production still uses an externally scheduled runner plus provider/staging evidence. |
| POST | `/v1/notifications/dlq/redrive` | `notification:write` | `{ dry_run?, attempt_ids?, rule_id? }` | Requeues selected `provider_failed_dlq` attempts through the HTTP/UI metadata-only path. Summary: `requeued_count`, `skipped_count`, `still_dlq_count`, `held_count`, `cancelled_count`, `processed`. A turned-off rule's DLQ rows are held and left untouched; a removed rule's are cancelled. In Postgres, rows are read from the ledger (not the recent-event feed), claimed before processing, and the summary adds `in_flight_count`, `claim_lost_count`, `lease_lost_count`, `pages_read`, `work_budget`, `budget_exhausted`; `still_dlq_count` counts the full live DLQ. Audits `notification.dlq_redrive`. Client-supplied provider-delivery overrides are ignored; response strips internal `delivery_record`, full destinations, provider URLs, request/response bodies, logs, tokens, and secrets. |

## High-scale (customer)

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| POST | `/v1/high-scale-requests` | `high_scale:request` | **Required:** `target_group_id`; `reason` or `objective` (both stored from supplied text); `environment`; `business_criticality`; non-empty `requested_scenario_families[]` — **ids from the governed scenario taxonomy** (`src/contracts/governedScenarios.mjs`, e.g. `udp_flood`, `syn_flood`, `http_get_flood`, `dns_query_flood`, `carpet_bombing`; unknown ids → `400 { error: "unknown_scenario_families", unknown: [...], governed_families: [...] }`); **optional** `delivery_patterns[]` validated against the governed delivery-pattern labels (unknown → `400 unknown_delivery_patterns`); `requested_limits` with at least one of `max_rate` (metadata string) or `max_duration_minutes` (positive number); non-empty metadata objects `stop_criteria` and `abort_criteria` (redacted on persist); `requested_window` with `window_start`/`window_end` (aliases `start`/`end` accepted — normalized ISO, optional `timezone`); non-empty `emergency_contacts[]` (metadata-only, redacted); `provider_context` with at least one provider label (`provider_name` / `provider` / `name`, `providers[]`) or `requires_provider_approval: true` (stored redacted); `scope_confirmation: true`. **Optional (redacted metadata):** `maintenance_approval`, `provider_contacts`, `provider_approvals[]`. | `201` request in `submitted` state with normalized intake fields stored on the request record (including `abort_criteria` and `delivery_patterns`). Target scope errors unchanged: `400` `missing_target_group_id`, `404` `target_group_not_found`, `400` `target_group_empty`. After valid scope, incomplete intake returns `400` `{ error: 'missing_high_scale_request_fields', missing: [...] }` (may include `abort_criteria`, `stop_criteria`, `environment`, etc.). Invalid dates or `start >= end` returns `400` `invalid_requested_window`. Provider checklist initialization unchanged: when provider metadata is supplied, the server initializes `provider_approval_checklist` (metadata-only items; string fields redacted). If `requires_provider_approval` is true and no provider name is given, a required `unspecified_provider` checklist item is created. **SOC approve requires complete `authorization_pack_status` and scenario-family authorization (SOC-011): every requested governed family must be covered by `approved_scenario_families` on an accepted `scope_and_rate_plan` / `test_plan` / `provider_approval` artifact, otherwise `409 { error: "scenario_family_not_authorized", uncovered: [...], approved: [...] }`.** Customer roles cannot approve, schedule, start, stop, or close. |
| GET | `/v1/high-scale-requests` | `high_scale:read` | `?scope=my-tenant` filters to inline SOC queue states (`submitted`, `soc_review`, `scheduled`, `under_review`) ordered by `state`, `created_at` | `{ items, count }`. |
| POST | `/v1/high-scale-requests/:id/artifacts` | `high_scale:request` | **Required:** `type` (expanded SOC-009 pack types, e.g. `customer_authorization_letter`, `target_ownership_confirmation`, `emergency_contacts`, `stop_criteria`, `test_plan`, `business_approval`, `legal_approval`, `scope_and_rate_plan`, `abort_criteria`, `provider_approval`). **Optional metadata-only proof fields (redacted on persist):** `reference_uri` (URI/ticket pointer — not binary upload in developer validation); `approval_reference`; `approver`; `valid_window` (`window_start`/`window_end` or aliases); `approved_targets[]`; `approved_scenario_families[]`; `max_rate`; `max_duration_minutes` (positive number); `emergency_contacts[]`; `abort_criteria` (object); `retention_policy` (object); `retained_artifact_metadata` (object); `contact_path`. **Provider approval (`type: provider_approval`):** `provider_name`, `provider_ref`, plus the proof fields above as applicable. Required proof fields per type are enforced when computing `authorization_pack_status` (see authorization pack doc). | `201` artifact metadata record (proof fields stored on the artifact; bodies are metadata references only). `type: provider_approval` updates or creates the matching `provider_approval_checklist` item (`pending_review`, or `expired` when the valid window end is in the past). SOC artifact review sets linked checklist items to `accepted` or `rejected` (expired windows remain `expired`). **Production gate:** secure durable document store/custody for real authorization letters, legal approvals, and provider attestations — API accepts metadata references only until that store is integrated. |
| GET | `/v1/high-scale-requests/:id/artifacts` | `high_scale:read` | — | `{ items }`. |

## SOC internal (`/internal/soc/*`)

Requires `soc:high_scale` or `soc:kill_switch`. **Customer roles (engineer, viewer, auditor) receive 403** and `rbac.denied` audit entries.

| Method | Path | Permission | Body | Notes |
|---|---|---|---|---|
| POST | `/internal/soc/high-scale/:id/approve` | `soc:high_scale` | — | Requires complete authorization pack. |
| POST | `/internal/soc/high-scale/:id/schedule` | `soc:high_scale` | `{ window_start, window_end }` | Sets approved window. |
| POST | `/internal/soc/high-scale/:id/start` | `soc:high_scale` | — | **Production:** governed adapter only. Developer validation: dry-run adapter; gated by window + scope hash. |
| POST | `/internal/soc/high-scale/:id/stop` | `soc:high_scale` | — | Stop transition. |
| POST | `/internal/soc/high-scale/:id/post-test-report` | `soc:high_scale` | `{ impact_summary?, recommendations?, customer_summary?, residual_risk?, next_steps?, attachments?, evidence_ids? }` | Upsert metadata-only SOC post-test report. Requires request `state === stopped`; otherwise `409` `report_requires_stopped_request`. Customer/engineer roles receive `403`. Body and derived SOC note text are redacted before persistence. Response includes derived `timeline` (from audit trail), artifact summary (id/type/status/reviewed_at), redacted SOC notes, adapter status metadata (`traffic_generated` retained when present), safe `telemetry_summary` (record counts, per-category counts, latest live status — not full metric payloads), and `final_state`. |
| GET | `/internal/soc/high-scale/:id/post-test-report` | `soc:high_scale` | — | Read stored post-test report for the request. `404` if none. |
| POST | `/internal/soc/high-scale/:id/close` | `soc:high_scale` | — | Close request from `stopped` only. `409` `post_test_report_required` if no post-test report exists. |
| POST | `/internal/soc/high-scale/:id/artifacts/:artifactId/review` | `soc:high_scale` | `{ status: accepted\|rejected }` | SOC review. |
| GET/POST | `/internal/soc/high-scale/:id/notes` | `soc:high_scale` | `{ body }` on POST | SOC transcript notes (redacted on export). |
| GET | `/internal/soc/high-scale/:id/adapter-status` | `soc:high_scale` | — | Adapter status; production must reflect real fleet state. |
| POST | `/internal/soc/high-scale/:id/telemetry` | `soc:high_scale` | `{ category, live_status?, observed_at?, source?, metrics? }` | Metadata-only SOC telemetry during governed runs. Allowed when request `state` is `scheduled`, `running`, `stopped`, or `closed`; otherwise `409` `telemetry_not_active`. Categories: `external_availability`, `agent_health`, `service_health`, `mitigation`, `stop_evidence`, `adapter_metric`. Optional `live_status`: `stable`, `mitigating`, `degraded`, `breached_threshold`, `stopping`, `stopped`, `inconclusive`. Rejects nested raw/payload/header/log/body fields in `metrics` with `400` `forbidden_telemetry_fields`. Customer/engineer roles receive `403`. Audit: `high_scale.telemetry_recorded` (category, live status, request id only). **Production gate:** live provider/staging telemetry feeds. |
| POST | `/internal/soc/high-scale/:id/telemetry/ingest` | `soc:high_scale` | `{ adapter_id, adapter_type?, provider_key?, provider_run_id?, snapshots: [{ category, live_status?, observed_at?, metrics? }] }` | Batch governed-adapter telemetry ingest. Same active-state gate as manual telemetry. Rejects forbidden attack/payload/header/log fields in envelope and snapshots. Audit: `high_scale.adapter_telemetry_ingested` (adapter id, snapshot count, ingestion id only). Scheduled operator helper: `scripts/governed-adapter-telemetry-ingest-runner.mjs` / `npm run soc:adapter-telemetry:ingest`. **Production gate:** live partner/provider adapter feeds wired to the scheduled ingest manifest. |
| GET | `/internal/soc/high-scale/:id/telemetry` | `soc:high_scale` | — | Tenant-scoped telemetry items for the request (newest `observed_at` first). |
| POST | `/internal/soc/kill-switch` | `soc:kill_switch` | `{ active, reason? }` | Tenant-scoped kill switch for the SOC caller’s tenant. On `active: true`, auto-stops running high-scale requests, auto-cancels in-flight safe test runs (`test_run.kill_switch_auto_cancel` per run), and in Postgres mode cancels open signed-worker probe jobs tied to those runs (`probe_job.kill_switch_auto_cancel` per job, metadata-only). Response and `soc.kill_switch.activated` audit metadata include `tenant_id`, `stopped_request_ids`, `cancelled_run_ids`, and `cancelled_probe_job_ids`. Legacy dev-json shape without `tenant_id` while active blocks all tenants. Clearing does not cancel runs or probe jobs. **Release blocker:** staging/live signed-worker fleet stop-path evidence — control-plane cancellation does not by itself prove external workers halt in flight. |

## Probe workers (internal, HMAC)

Authenticated with `x-probe-worker-id`, `x-probe-timestamp`, and `x-probe-signature` (HMAC over method, path, timestamp, raw body, and optional tenant id). Requires `ASTRANULL_PROBE_MODE=signed-worker` and `ASTRANULL_PROBE_WORKER_SECRET` (at least 32 decoded high-entropy bytes; for example, `openssl rand -hex 32`). In `ASTRANULL_PERSISTENCE_MODE=postgres`, workers must also include signed `x-probe-tenant-id` (the reference worker accepts `--tenant-id` / `ASTRANULL_PROBE_TENANT_ID`) so `/internal/probe/*` routes can use tenant-scoped Postgres repositories. Human OIDC JWTs, signed-session tokens, and dev headers are **not** accepted on these routes.

| Method | Path | Auth | Response |
|---|---|---|---|
| GET | `/internal/probe/jobs` | Probe worker HMAC | `{ jobs: SignedProbeJob[] }` — pending jobs are leased to the worker on fetch. |
| POST | `/internal/probe/jobs/:id/result` | Probe worker HMAC | `{ external_result, safety_attestation, metadata? }` metadata only. **`safety_attestation`** (alias **`execution_summary`**) is required. Current signed jobs require exact split accounting: `{ requests_sent, probe_requests_sent, destination_resolver_attempts, total_operations, duration_ms, worker_version?, region?, completed_at? }`, where `requests_sent === total_operations === probe_requests_sent + destination_resolver_attempts`. Results must stay within signed `max_probe_requests`, destination-resolver floor/cap, `max_total_operations` (also carried as compatibility `max_requests`), and `timeout_ms`; legacy unsplit jobs retain bounded compatibility validation. Errors: `400` `missing_safety_attestation` / `invalid_safety_attestation`; `422` `invalid_signed_operation_caps` / `safety_attestation_exceeded`. Rejects `packet_payload` / `raw_packet`. Accepted results create probe timeline event and evidence including sanitized attestation. |

`POST /v1/test-runs` in `signed-worker` mode returns `probe_job` metadata (including `job_signature`) and leaves the run in `running` until the worker posts a result, then `collecting` for agent correlation.

In Postgres mode, probe worker leasing and result ingestion are wired through `runtime.services.probeJobs`, and customer `POST /v1/test-runs` / finalize orchestration is backed by `runtime.services.testRuns` in the same persistence boundary. **Release blockers** remain staging/live multi-region signed-worker fleet matrix evidence (`probe_fleet_matrix`), gateway load/abuse and concurrency isolation under realistic probe load (`gateway_load_abuse`, `postgres_concurrency`), and operator-attested acceptance of customer-declared targets by vector — not missing internal poll/result or test-run route wiring.

## Audit and observability

| Method | Path | Permission | Response |
|---|---|---|---|
| GET | `/v1/audit-log` | `audit:read` | `{ items, count, total, next_cursor, filters, limit }`. Filters: `resource` (type or id), `actor` (`actor_user_id` exact), `action`, `since`, `until` (inclusive timestamps), `cursor`, `limit` (1–500, default 200). Aliases, applied only when the canonical key is absent or equal: `actor_user_id`→`actor`, `from`→`since`, `to`→`until`. A conflict is `400 invalid_query_value`. `total` is the filtered count. A filter does not substitute the newest 200. The cursor timestamp is microsecond text (`YYYY-MM-DDTHH:MM:SS.USZ`). Bad `since`, `until`, `limit`, or `cursor` is `400`. Same permission as before (`owner`, `admin`, `soc`, `auditor`; viewer is `403`). |
| GET | `/v1/audit-log/:id` | `audit:read` | `{ entry }` the stored event for that tenant, including `entry_hash`, `prev_hash`, and `metadata` when the audit row has them. Does not rebuild the event. `404 not_found` when the id is missing or belongs to another tenant. |
| GET | `/v1/observability` | `tenant:read` | JSON counters + inventory counts. |

## Role → permission map

See `src/contracts/roles.mjs` for the canonical list. SOC-only permissions: `soc:high_scale`, `soc:kill_switch`.

## Persistence modes

| Mode | When | Notes |
|---|---|---|
| `dev-json` | Default outside `NODE_ENV=production` | Local `.data/astranull-dev.json` for developer validation only. |
| `memory` | `ASTRANULL_NO_PERSIST=1` (non-production only) | Ephemeral store for tests and CI. |
| `postgres` | Default when `NODE_ENV=production` | Requires `ASTRANULL_DATABASE_URL` in production; startup **fails closed** if unset, migration preflight fails, or a required injected service is missing (no fake adapter; JSON store is never used while reporting `postgres`). `memory` and `dev-json` are refused in production. See [`db/README.md`](../db/README.md). |

Set explicitly with `ASTRANULL_PERSISTENCE_MODE`. `/ready` exposes `persistence` mode name only, never connection strings.

**Operator preflight:** `npm run postgres:startup-check` (`scripts/postgres-startup-check.mjs`) requires `ASTRANULL_DATABASE_URL`, pings Postgres, asserts latest migration applied (optional `--migrate` to apply pending migrations first). Connection strings are redacted in output. Runtime `postgres` mode initializes the same Postgres facade at startup and injects migrated control-plane services (catalog, auth, agents, agent updates, validation safe loop including events, notifications, evidence, findings, production release evidence, secrets, reports, state, probe jobs, high-scale/SOC, audit, retention). A route returns `postgres_route_not_wired` only when its required injected service is missing or that handler is not yet Postgres-backed. See [`docs/operator-local-runbook.md`](operator-local-runbook.md).

## Privacy retention (metadata)

Per-tenant `privacy_settings.metadata_retention_days` controls how long **metadata** is kept in `events`, `evidenceVault`, `reports`, and `notificationEvents`. Values are clamped to 1–3650 days on read/update.

Retention enforcement:

- Runs immediately when `PATCH /v1/tenants/current` changes privacy settings.
- Exported as `enforceMetadataRetentionForTenant(tenantId)` for scheduled jobs.

Purge rules:

- Deletes current-tenant rows in the four collections when `timestamp` / `created_at` is older than the retention window.
- Preserves other tenants, rows with invalid/missing timestamps, audit logs, findings, test runs, high-scale requests, authorization artifacts, SOC notes, targets, and agents.
- Emits audit entries with action `privacy.retention_purged` when rows are removed.

**Production gates still open:** audit and high-scale legal retention, regional residency, durable Postgres-backed purge at scale, and redaction coverage on every export path.

## Production release blockers (current implementation status)

| Capability | Verification evidence |
|---|---|
| OIDC/SSO and disabled header auth | Built-in `oidc-jwt` + JWKS verification (HTTPS JWKS URL in production, bounded fetch timeout, no redirect follow) plus production-default MFA claim enforcement (`ASTRANULL_OIDC_REQUIRE_MFA`, `ASTRANULL_OIDC_MFA_CLAIM`, `ASTRANULL_OIDC_MFA_VALUES`); **remaining:** real IdP tenant/role mapping, conditional access/session policy evidence, staging login flow, header-only negative test in prod-like deployment, audit/ops signoff |
| PostgreSQL persistence and RLS | Migration CI job + tenant isolation integration tests |
| Rate limiting and WAF | Service limiter in code; gateway/WAF + staging load/abuse test report |
| Encrypted secrets store | Security review + rotation drill |
| Signed probe jobs and external workers | Probe worker E2E in staging |
| Signed agent packages | Install matrix on supported distros |
| Governed high-scale adapter | SOC runbook exercise with partner sandbox |
| External notification providers | Configured channel test per tenant |

See [`docs/release-checklist.md`](release-checklist.md) for the full gate list.

## Evidence context

`GET /v1/evidence-context` is read-only. It does not start a probe, advance a validation scan, export a report, verify custody, or send a notification.

Permission is `evidence:read` plus the entry permission: `finding` and `group_member` require `finding:read`, `check_result` requires `test_run:read`, `provider` requires `target_group:read`, `artifact` requires `evidence:read`, `report` requires `report:read`, and `audit` requires `audit:read`. The check happens before any record lookup. A role that cannot read the entry gets `403` `{ "error": "forbidden", "permission": "<permission>", "state": "denied" }` (viewer and engineer receive this for `audit`, not an empty body). An id outside the tenant, or a target/check/run/artifact tuple that is not linked, is `404` `{ "error": "not_found", "state": "not_found" }`. `group_id` is `400` `group_id_not_supported`. Ids must match `^[A-Za-z0-9_.:-]{1,128}$`.

In Postgres mode a missing configured read returns `503` `{ "error": "unavailable", "unavailable_reason": "fetch_failed", "state": "unavailable" }`. It does not fall through to the dev store. Dev mode uses an injected method when one is present, otherwise the dev module.

Query: `entry` is required.

| entry | Required query | Proof used |
|---|---|---|
| `finding` | `finding_id` | That finding's `evidence_ids` and its originating verdict only when the stored run's tenant, target, check, and id match the finding and `verdict_id` matches. Not the newest run on the target. |
| `group_member` | `finding_id` | That member finding only. Another finding's artifact is `404`. |
| `check_result` | `target_id`, `check_id`, `test_run_id` | That run and its verdict. The run must match the target and check. Sibling runs are not listed. |
| `provider` | `target_id`, `family` (`cdn`, `waf`, `cloud`, `dns`, `origin_hosting`) | That family's stored columns and `evidence_json` only. CDN does not copy `waf_vendor`. A method or status alone is not primary proof. |
| `artifact` | `evidence_id` | That vault row. |
| `report` | `report_id` | Captured `run_ids` and `summary.evidence_ids`, plus `summary` score, factors, and `as_of` / `generated_at`. Live runs are not read. |
| `audit` | `audit_id` | Actor, action, resource, and time. The action is not an infrastructure proof. |

`200` finding body (digest recorded, one correlated event, no later pointer):

```json
{
  "entry": "finding",
  "tenant_id": "ten_1",
  "subject": { "finding_id": "finding_1", "target_id": "tgt_1", "check_id": "app.marker.safe" },
  "answer": {
    "outcome": "allowed",
    "explanation": "scrubbed",
    "limitations": ["external_only", "bounded_check_not_capacity"],
    "expected_behavior": "block_at_edge",
    "observed_behavior": "allowed"
  },
  "primary": {
    "test_run_id": "run_open",
    "verdict_id": "verdict_open",
    "evidence_ids": ["evidence_1"],
    "observed_at": "2026-10-02T00:00:00.000Z",
    "integrity": {
      "status": "recorded_digest",
      "verified_at": null,
      "method": null,
      "refs": [
        { "evidence_id": "evidence_1", "status": "recorded_digest", "verified_at": null, "method": null }
      ]
    }
  },
  "latest_distinct": null,
  "originating": {
    "test_run_id": "run_open",
    "verdict_id": "verdict_open",
    "evidence_ids": ["evidence_1"],
    "observed_at": "2026-10-02T00:00:00.000Z"
  },
  "latest_same_check": null,
  "alternatives": [],
  "request_summary": { "status": "recorded", "event_id": "evt_1", "method": "GET", "path": "/health" },
  "response_summary": { "status": "recorded", "event_id": "evt_1", "status_code": 200, "external_result": "allowed" },
  "evaluation": {
    "status": "recorded",
    "expected_behavior": "block_at_edge",
    "observed": "allowed",
    "verdict": "allowed",
    "reasons": [],
    "rule_version": null,
    "confidence": "external_only"
  },
  "unavailable_reason": null,
  "state": "ready",
  "truncation": {
    "evidence_refs": { "source_count": 1, "returned": 1, "limit": 32, "truncated": false },
    "events": { "source_count": 1, "returned": 1, "limit": 20, "truncated": false }
  }
}
```

Integrity `status` is `not_recorded`, `recorded_digest`, `not_verified`, or `verified`. `verified` requires every covered ref to have its own top-level `verification` object with `ok: true`, a method matching `^[a-z0-9_.:-]{1,64}$` other than `customer_supplied`, an ISO `verified_at`, and `covered_refs` containing that row's id. `metadata.verified_at` and `metadata.verify_method` are customer claims: they yield `not_verified`, or `recorded_digest` when a digest is stored. One verified row does not upgrade its siblings. `verified_at` and `method` on the aggregate are set only when every ref is verified and those values agree.

A conflicting or unbound origin run does not supply the verdict, explanation, or evaluation. Evidence tied to that run is an alternative (`scope_conflict` or `unbound_evidence`) and is not integrity proof. A recorded field that disagrees is a conflict. A missing target or check on an evidence row is not a conflict, because the vault has no such columns. An event is used only when tenant, run, target, and check are all recorded and equal. Several events are not merged. The summary is taken from the single top-level `related_event_id` when that event matches, or from the one fully matched event when no related id is stored. Otherwise the summaries are `{ "status": "not_recorded" }` and the events stay `unmatched_operation` alternatives. A missing correlation is `partial`.

`latest_distinct` is set only when `last_verdict_id` points at a different verdict that passes the same later-run checks. `latest_same_check` is the newest other run with the same tenant, target, and check, status `verdicted` or `completed`, a non-empty verdict string, and at least one evidence id. `closes_finding` is false. Running, cancelled, unbound, or evidence-empty runs are not newer proof. `originating` and `latest_same_check` are present on `finding` and `group_member`.

Empty evidence ids yield `primary: null`, `unavailable_reason: "no_refs"`, `state: "no_refs"`. A listed id missing from the vault is `partial` plus `missing_evidence_ids`. Ids past the load cap are `truncation.evidence_refs` (`source_count`, `returned`, `limit` 32, `truncated`) and are not listed as missing. Events are read with a limit of 21 and the body keeps 20. `truncation.events.source_count` is the in-memory total in dev mode. In Postgres it is null when the SQL limit is hit, because the total is not counted. `state` is `partial` when any ref is unbound or conflicting, the origin linkage is not a match, the operation correlation is partial, or a ref or event list is truncated.

Report `primary` is null unless `summary` or the report row has `primary_test_run_id` or `primary_evidence_id` and that id is in the captured set. `run_ids[0]` is not a primary. Every captured run id is a `report_snapshot_run` alternative and every summary evidence id is a `report_snapshot_evidence` alternative with its own `integrity`. `subject.score` is `summary.readiness_score` or `summary.score`. `subject.factors` is `summary.readiness_factors` or `summary.factors`. `subject.as_of` is `summary.as_of` or `summary.generated_at`. `created_at` is not borrowed. Refs with no primary stay `state: "ready"` and `unavailable_reason: null`.

Provider `subject` adds `status`, `provider` (null when zero or several), `product`, `source`, `reason`, `confidence`, `conflict`, `corpus`, `observed_at`, and `proof`. `proof` is string arrays, each capped at 16: `{ "matched_signals": [], "methods": [], "cnames": [], "addresses": [], "fingerprints": [] }`. The current summary renderer drops arrays, so read `subject.proof` directly. Each distinct provider is a `provider_layer` alternative with the same scalar fields plus that layer's arrays. `primary` is set only when at least one signal, CNAME, address, or fingerprint is present. A method label alone leaves `primary: null`, `evaluation.status: "not_recorded"`, and `unavailable_reason: "no_refs"`. DNS and origin hosting stay `not_recorded` / `unknown` with `reason: "no_origin_hosting_observation"` until that family has its own observation. Headers, bodies, cookies, and authorization values are not copied.

`request_summary` and `response_summary` copy only recorded primitive fields from the one selected event (`engine`, `method`, `path` with the query removed, `protocol`, `max_requests`, `timeout_ms`, `external_result`, `status_code`, `received_at`). Recorded values are not recased. Missing fields are `{ "status": "not_recorded" }`. Evaluation from a stored verdict forces `confidence: "external_only"`. Responses are passed through `redactObject` again. Raw headers, cookies, authorization, bodies, URL queries, and agent or placement metadata are not returned. `GET /v1/test-runs/:id/events` remains the raw bounded event list and is not this payload.

## Application entry paths and firewall change acceptance

Provider-neutral, outside-in validation of declared application entry paths and firewall change behavior. Decision: [ADR-0017](adr/0017-application-entry-path-validation.md). Spec: [detection/23](detection/23-application-entry-path-validation.md). Contract: `src/contracts/protectionValidation.mjs` (`contract_version: "protection-validation-v1"`). Route names, permissions, and the `passive` flag are pinned by `PROTECTION_VALIDATION_ROUTES` and its unit tests.

Shared rules for every route below:

- All routes are tenant-scoped. A missing id, or an id owned by another tenant, returns `404` (`not_found`, `unknown_target`, or `unknown_origin_binding`) without saying whether the record exists.
- Postgres mode never falls back to the dev store. An unwired service returns `503 postgres_route_not_wired`.
- `passive` means the route never dispatches probe traffic or starts runs. Only the `start` mode of `POST /v1/entry-path-comparisons` can start runs.
- No route here selects a socket destination from relation metadata, redirects, response headers, or discovered endpoints. The keys `direct_ip`, `discovered_endpoint(s)`, `endpoint`, `destination`, `host_override`, `sni_override`, `source_ip`, `spoofed_source`, `inferred_from`, `credentials`, `password`, `api_key`, `token`, `secret`, and `raw_config` are rejected at any depth with `400 scope_not_declared`. The body is not echoed back.
- Server-owned fields (`id`, `tenant_id`, `status`, `declaration_version`, `declaration_digest`, `expectation_version`, `digest`, `created_at`, `created_by`, `archived_at`, `archived_by`, `contract_version`) in a create body return `400 server_owned_field` with `field`.
- Validation errors use `{ error, status, field, message }`.
- List routes accept `?cursor&limit`. `limit` is 1–100 (default 50). The response is `{ items, count, next_cursor }`.
- Every mutation is audited exactly once in the same transaction. An idempotent replay is not audited again.
- There is no public observation-write endpoint. Observations come only from signed, finalized runs.
- Every route is behind the tenant gate `protection_validation` (see [Tenant gate and runtime wiring](#protection-validation-tenant-gate-and-runtime-wiring)). When it is off, every route returns `404 protection_validation_disabled`.

| Method | Path | Permission | Passive |
|---|---|---|---|
| GET | `/v1/targets/:targetId/entry-paths` | `target_group:read` | yes |
| POST | `/v1/targets/:targetId/entry-paths` | `target_group:write` | yes |
| GET | `/v1/entry-paths/:entryPathId` | `target_group:read` | yes |
| POST | `/v1/entry-paths/:entryPathId/archive` | `target_group:write` | yes |
| GET | `/v1/targets/:targetId/protection-validation` | `evidence:read` | yes |
| POST | `/v1/entry-path-comparisons` | `test_run:start` | no (`mode: "start"` only) |
| GET | `/v1/entry-path-comparisons` | `evidence:read` | yes |
| GET | `/v1/entry-path-comparisons/:comparisonId` | `evidence:read` | yes |
| POST | `/v1/entry-path-comparisons/:comparisonId/cancel` | `test_run:start` | yes (stops; never starts) |
| GET | `/v1/firewall-expectations` | `target_group:read` | yes |
| POST | `/v1/firewall-expectations` | `target_group:write` | yes |
| POST | `/v1/firewall-expectations/:expectationId/archive` | `target_group:write` | yes |
| POST | `/v1/firewall-baselines` | `target_group:write` | yes |
| GET | `/v1/firewall-baselines` | `evidence:read` | yes |
| GET | `/v1/firewall-baselines/:baselineId` | `evidence:read` | yes |
| POST | `/v1/firewall-comparisons` | `target_group:write` | yes |
| GET | `/v1/firewall-comparisons` | `evidence:read` | yes |
| GET | `/v1/firewall-comparisons/:comparisonId` | `evidence:read` | yes |

Viewers and auditors can read. Owners, admins, and engineers can declare, capture, evaluate, and start. SOC holds no write permission here.

### Entry paths

`POST /v1/targets/:targetId/entry-paths` request:

```json
{
  "entry_target_id": "tgt_alt",
  "relation_kind": "alternate_hostname",
  "owner": "App Team",
  "purpose": "Legacy hostname kept for partner integrations",
  "expected_behavior": "must_be_protected_by_layers",
  "required_layers": ["waf", "cdn_edge"],
  "origin_binding_id": null
}
```

| Field | Rule |
|---|---|
| `relation_kind` | `primary_route`, `alternate_hostname`, `declared_api_url`, `declared_login_url`, `origin`, or `fallback_backend_route`. |
| `expected_behavior` | `must_be_protected_by_layers` needs at least one layer. `intentionally_public` needs zero layers. `must_not_be_reachable` takes any layers. A violation is `400 required_layers_conflict`. |
| `required_layers` | A subset of `waf`, `cdn_edge`, `network_firewall`, `ddos`, returned in that canonical order. |
| `origin_binding_id` | Required for `origin` (`400 origin_binding_required`) and forbidden otherwise (`400 origin_binding_not_allowed`). The binding must be active, in the same tenant, and join exactly `:targetId` → `entry_target_id`. A missing or archived binding is `404 unknown_origin_binding`. A binding that joins different targets is `409 origin_binding_mismatch`. |
| `entry_target_id` | Equals `:targetId` only for `primary_route`. Optional `anchor_target_id` in the body must equal `:targetId`. |
| `owner` / `purpose` | 1–120 / 1–500 characters. |

Other errors:

- `404 unknown_target`: the anchor or entry target is missing or belongs to another tenant.
- `409 target_not_active`: the target is deleted.
- `409 entry_path_conflict`: the same active scope (anchor, entry, kind, binding) already exists with a different declaration digest.
- `403`: the caller lacks the permission.

`201` returns the relation. Replaying an identical declaration returns `200` with `replayed: true` and no second audit. Audited as `entry_path.created`. Creating a relation never starts a run.

Relation response:

```json
{
  "id": "ep_1",
  "tenant_id": "ten_1",
  "anchor_target_id": "tgt_app",
  "entry_target_id": "tgt_alt",
  "relation_kind": "alternate_hostname",
  "owner": "App Team",
  "purpose": "Legacy hostname kept for partner integrations",
  "expected_behavior": "must_be_protected_by_layers",
  "required_layers": ["waf", "cdn_edge"],
  "origin_binding_id": null,
  "status": "active",
  "declaration_source": "explicit",
  "declaration_version": 1,
  "declaration_digest": "<sha256 hex>",
  "contract_version": "protection-validation-v1",
  "currently_authorized": true,
  "authorization_state": "dns_verified",
  "created_at": "2026-10-06T00:00:00.000Z",
  "created_by": "usr_1",
  "archived_at": null
}
```

The `GET` list returns relations where the target is the anchor or the entry. It accepts `?status=active|archived&relation_kind=…`.

`POST /v1/entry-paths/:entryPathId/archive` returns `200` with `status: "archived"` and `archived_at` set. Archiving again is `409 already_archived`. Audited as `entry_path.archived`. An archived relation cannot authorize new checks. `currently_authorized` reflects current ownership proofs and the target lifecycle. It is re-checked at execution time.

### Protection matrix

`GET /v1/targets/:targetId/protection-validation` is a passive per-path, per-layer read model:

```json
{
  "target_id": "tgt_app",
  "contract_version": "protection-validation-v1",
  "generated_at": "2026-10-06T00:00:00.000Z",
  "connectors_required": false,
  "paths": [
    {
      "entry_path_id": "ep_1",
      "anchor_target_id": "tgt_app",
      "entry_target_id": "tgt_alt",
      "relation_kind": "alternate_hostname",
      "expected_behavior": "must_be_protected_by_layers",
      "required_layers": ["waf", "cdn_edge"],
      "origin_binding_id": null,
      "status": "active",
      "declaration_version": 1,
      "declaration_digest": "<sha256 hex>",
      "outcome": "not_tested",
      "attribution": "unattributed",
      "layers": [
        {
          "layer": "waf",
          "declared_intent": "required",
          "vendor_detection": "unknown",
          "observed_enforcement": "not_tested",
          "application_identity": "not_tested",
          "suspected_bypass": "unknown",
          "confirmed_scoped_bypass": "unknown",
          "attribution": "not_applicable",
          "evidence_limitations": ["external_only"],
          "evidence_refs": [],
          "freshness": null
        }
      ],
      "evidence_refs": [],
      "latest_comparison_id": null,
      "freshness": null,
      "limitations": ["external_only", "not_capacity_assurance", "firewall_traversal_not_established", "stacked_layer_attribution_not_established", "marker_scope_only", "untested_paths_not_covered"]
    }
  ],
  "counts": { "paths": 1, "by_outcome": { "not_tested": 1 } },
  "limitations": ["external_only", "not_capacity_assurance"]
}
```

Each path lists all four layers (`waf`, `cdn_edge`, `network_firewall`, `ddos`). The layer states are:

| Field | States |
|---|---|
| `declared_intent` | `required`, `not_required`, `undeclared` |
| `vendor_detection` | `detected`, `not_detected`, `unknown` |
| `observed_enforcement` | `enforced`, `partially_enforced`, `not_enforced`, `inconclusive`, `not_tested` |
| `application_identity` | `confirmed`, `suspected`, `not_established`, `not_tested` |
| `suspected_bypass` | `suspected`, `not_suspected`, `unknown` |
| `confirmed_scoped_bypass` | `confirmed`, `not_confirmed`, `unknown` |

`outcome` is a path validation outcome:

- `intentional_public_access`
- `reachability_exposure`
- `weaker_observed_enforcement`
- `suspected_alternate_application_route`
- `scoped_application_bypass`
- `consistent_enforcement`
- `inconclusive`
- `not_tested`
- `skipped`

Rules for the matrix:

- Observed and confirmed states always carry `evidence_refs`.
- The `ddos` layer always carries `not_capacity_assurance`.
- A vendor label never sets `observed_enforcement`.
- The matrix does not attribute stacked layers.
- The matrix never reports "DDoS protected" or "all controls bypassed".

Evidence refs are reference-only:

```json
{ "test_run_id": "run_1", "check_id": "waf.marker.sqli", "check_version": "v3", "scenario_version": "s2", "verdict_id": "verdict_1", "evidence_ids": ["ev_1"], "target_id": "tgt_alt", "observed_at": "2026-10-06T00:00:00.000Z", "run_status": "verdicted", "finalized": true, "source_perspective": "public-worker-eu", "worker_id": "worker_eu_1" }
```

Headers, bodies, cookies, raw configuration, and credentials are never returned.

### Entry-path comparisons

`POST /v1/entry-path-comparisons` request:

```json
{
  "mode": "plan",
  "anchor_target_id": "tgt_app",
  "primary_entry_path_id": "ep_primary",
  "entry_path_ids": ["ep_primary", "ep_1", "ep_origin"],
  "expectation": { "scenario": "waf.sqli.marker", "layer_outcomes": { "waf": "enforce", "cdn_edge": "enforce" } }
}
```

| Field | Rule |
|---|---|
| `mode` | `plan` (the default) or `start`. |
| `entry_path_ids` | 1–32 declared, active entry paths of the anchor. `primary_entry_path_id` must be one of them. |
| `expectation` | A path-validation expectation. The server versions and digests it. |
| `layer_outcomes` | Maps each layer to `enforce`, `allow`, `not_reachable`, or `no_expectation`. |

`mode: "plan"` is passive. It returns `200` with this body:

```json
{
  "mode": "plan",
  "plan_digest": "<sha256 hex>",
  "anchor_target_id": "tgt_app",
  "primary_entry_path_id": "ep_primary",
  "expectation": { "id": "pvx_1", "scenario": "waf.sqli.marker", "layer_outcomes": { "waf": "enforce", "cdn_edge": "enforce" }, "expectation_version": 1, "digest": "<sha256 hex>" },
  "items": [
    { "entry_path_id": "ep_1", "target_id": "tgt_alt", "declaration_digest": "<sha256 hex>", "check_id": "waf.marker.sqli", "check_version": "v3", "origin_binding_id": null, "eligible": true, "ineligible_reason": null }
  ],
  "expectation_conflicts": [
    { "entry_path_id": "ep_1", "conflicts": ["required_layer_not_enforced:waf"] }
  ],
  "limitations": ["external_only", "not_capacity_assurance", "firewall_traversal_not_established", "stacked_layer_attribution_not_established", "marker_scope_only", "untested_paths_not_covered"]
}
```

`expectation_conflicts` lists one object per conflicting path: `{ entry_path_id, conflicts: string[] }`. Conflict codes are `required_layer_not_enforced:<layer>` (a declared required layer is expected to `allow` or has `no_expectation`), `unreachable_path_allows:<layer>` (a `must_not_be_reachable` path is expected to `allow` a layer), and `anchor_mismatch`. It is `[]` when the expectation matches every declaration. Conflicts never block planning; the portal shows them per path in the review step.

`mode: "start"` requires `reviewed_plan_digest`. The server recomputes the plan from current declarations and authorization. If anything changed, it returns `409 reviewed_plan_mismatch` and starts nothing.

When the digests match, it persists the approved scope and starts the eligible items through the existing signed run start. That start keeps origin-binding scope capture, destination vetting and pinning, request accounting, budgets, deadlines, cooldowns, concurrency, safe windows, cancellation, and kill switches. It returns `202` with `{ id, status: "running", plan_digest, items: [{ entry_path_id, test_run_id | null, outcome: "not_tested" | "skipped" }] }`. Audited as `entry_path_comparison.started`.

Archived relations, deleted targets, and targets whose ownership proof has lapsed are `skipped`. They are not executed.

`GET /v1/entry-path-comparisons` (`?anchor_target_id&cursor&limit`) and `GET /v1/entry-path-comparisons/:comparisonId` return the comparison:

- `id`, `status` (`running`, `completed`, or `cancelled`), `plan_digest`, `expectation`, `baseline` (the primary evidence set).
- `items[]`: `{ entry_path_id, scenario, outcome, attribution, reasons[], compatibility_reasons[], evidence_refs[], limitations[] }`.
- `compatibility`: `{ comparable, stale, reasons[] }`.
- `summary`: `{ total, evaluated, by_status, gaps, accepted }`.
- `evaluation_digest`, `evaluated_at`.

Rules for comparison results:

- Primary-route success never validates an untested alternate route.
- `scoped_application_bypass` requires a nonce-bound application identity. Weaker matches are `suspected_alternate_application_route`.
- Timeouts and transport errors are `inconclusive`.
- Reads never start runs.

### Firewall expectations

`POST /v1/firewall-expectations` request:

```json
{
  "destination_target_id": "tgt_fw",
  "protocol": "tcp",
  "port": 443,
  "expected": "allow",
  "source_perspective": "public-worker-eu",
  "change_id": "CHG-1001",
  "owner": "Network Team",
  "pre_post_mapping": { "pre_destination_target_id": "tgt_old", "post_destination_target_id": "tgt_fw", "declared_by_customer": true }
}
```

| Field | Rule |
|---|---|
| `protocol` | `tcp` or `udp` with an integer `port` (1–65535), or `service` with `service_endpoint: { service, port, path? }` and no `port`. The path has no query. |
| `expected` | `allow` or `deny`. |
| `pre_post_mapping` | Optional. It must be an explicit customer declaration that includes `destination_target_id`. An inferred IP change is never comparable. |
| `destination_target_id` | Must be an existing same-tenant target (`404 unknown_target`). |

`201` returns the expectation with `id`, `status: "active"`, `expectation_version`, `digest`, and `contract_version`. An identical replay returns `200` with `replayed: true`. A different digest for the same active scope (change, destination, protocol, port or endpoint, and source) is `409 firewall_expectation_conflict`. Audited as `firewall_expectation.created`.

`GET` lists accept `?change_id&destination_target_id&status`. Archive returns `200` (`409 already_archived` when repeated) and is audited as `firewall_expectation.archived`.

### Firewall baselines

`POST /v1/firewall-baselines` request:

```json
{ "change_id": "CHG-1001", "expectation_ids": ["fwx_1", "fwx_2"], "test_run_ids": ["run_1", "run_2"], "freshness_window_seconds": 2592000 }
```

The server captures one immutable baseline per expectation from the listed runs.

- Every referenced run must be finalized (`verdicted` or `completed`). Otherwise the request fails with `409 evidence_not_finalized`.
- Every run must have a recorded `source_perspective` and `worker_id`, and must belong to the expectation's destination.
- `freshness_window_seconds` is 3600–15552000 (default 2592000).
- Capturing a baseline never dispatches traffic.

`201` response:

```json
{
  "id": "fwb_1",
  "kind": "firewall_change",
  "tenant_id": "ten_1",
  "change_id": "CHG-1001",
  "captured_at": "2026-10-06T00:00:00.000Z",
  "freshness_window_seconds": 2592000,
  "immutable": true,
  "baseline_digest": "<sha256 hex>",
  "entries": [
    {
      "kind": "firewall_change",
      "expectation_id": "fwx_1",
      "expectation_version": 1,
      "expectation_digest": "<sha256 hex>",
      "declaration_digest": null,
      "target_id": "tgt_fw",
      "destination_mapping": null,
      "references": [ { "test_run_id": "run_1", "check_id": "net.tcp.reachability", "check_version": "v3", "scenario_version": null, "verdict_id": "verdict_1", "evidence_ids": ["ev_1"], "target_id": "tgt_fw", "observed_at": "2026-10-05T00:00:00.000Z", "run_status": "verdicted", "finalized": true, "source_perspective": "public-worker-eu", "worker_id": "worker_eu_1" } ],
      "captured_at": "2026-10-06T00:00:00.000Z",
      "freshness_window_seconds": 2592000,
      "baseline_digest": "<sha256 hex>"
    }
  ]
}
```

Replaying an identical capture returns `200` with `replayed: true`. Audited as `firewall_baseline.captured`. Baselines are never updated. A later declaration or expectation change does not reinterpret them.

### Firewall comparisons

`POST /v1/firewall-comparisons` request:

```json
{ "baseline_id": "fwb_1", "post_test_run_ids": ["run_9", "run_10"] }
```

The server evaluates the explicitly selected post-change runs against each baseline entry using `assessComparisonCompatibility`. It records an immutable evaluation and returns `201`. Audited as `firewall_comparison.evaluated`. No traffic is sent.

```json
{
  "id": "fwc_1",
  "kind": "firewall_change",
  "tenant_id": "ten_1",
  "baseline_id": "fwb_1",
  "baseline_digest": "<sha256 hex>",
  "compatibility": { "comparable": true, "stale": false, "reasons": [] },
  "items": [
    {
      "expectation_id": "fwx_1",
      "status": "regression",
      "gap_kind": "required_service_newly_unavailable",
      "expectation_met": false,
      "pre_state": "satisfied",
      "post_state": "not_observed",
      "reasons": [],
      "compatibility_reasons": [],
      "evidence_refs": [],
      "limitations": ["external_only", "sampled_public_ingress_only", "rule_table_equivalence_not_established", "routing_nat_egress_east_west_not_established", "not_capacity_assurance", "appliance_traversal_not_established", "transport_reachability_not_enforcement"]
    }
  ],
  "summary": { "total": 1, "evaluated": 1, "by_status": { "matched": 0, "regression": 1, "improvement": 0, "inconclusive": 0, "not_tested": 0, "stale": 0, "not_comparable": 0 }, "gaps": { "forbidden_service_newly_reachable": 0, "required_service_newly_unavailable": 1 }, "accepted": false },
  "limitations": ["external_only", "sampled_public_ingress_only", "rule_table_equivalence_not_established", "routing_nat_egress_east_west_not_established", "not_capacity_assurance", "appliance_traversal_not_established", "transport_reachability_not_enforcement"],
  "evaluated_at": "2026-10-07T00:00:00.000Z",
  "evaluation_digest": "<sha256 hex>"
}
```

Item `status` is one of `matched`, `regression`, `improvement`, `inconclusive`, `not_tested`, `stale`, or `not_comparable`. Rules:

- `matched` means the post-change side state equals the pre-change side state. Read `expectation_met` to see whether the expectation is satisfied.
- `gap_kind` is set only on regressions.
- `compatibility_reasons` uses the contract's `COMPATIBILITY_REASONS`, for example `source_mismatch`, `destination_mapping_missing`, `check_version_mismatch`, `evidence_not_finalized`, or `baseline_stale`. Any such reason forces `stale`, `not_comparable`, or `not_tested`.
- Expectations without post-change evidence are `not_tested`.
- Required allow needs a valid service response. Expected deny needs control-specific denial evidence. UDP silence and timeouts remain `inconclusive`. A transport connect shows reachability, not enforcement.
- `summary.accepted` is true only when at least one item exists and every item is `matched` or `improvement` with `expectation_met: true`.

Other errors:

- `404`: unknown or other-tenant baseline or run.
- `400 invalid_comparison_request`: malformed body.
- `409 baseline_not_comparable`: an evaluation would claim equivalence from incompatible evidence.

Reports state that sampled public-ingress behavior was tested. They leave rule-table, routing, NAT, egress, east-west, appliance-traversal, and capacity equivalence unestablished.

`GET /v1/firewall-baselines`, `GET /v1/firewall-comparisons` (`?change_id&baseline_id&cursor&limit`), and the `/:id` reads are passive. They return the stored records unchanged.

### Protection validation tenant gate and runtime wiring

**Tenant gate.** `GET /v1/tenant/deployment-features` returns `protection_validation: boolean`. The gate is resolved in this order:

1. `ASTRANULL_PROTECTION_VALIDATION_ENABLED=0` is a global off switch for every tenant, including demo tenants.
2. `ASTRANULL_PROTECTION_VALIDATION_ENABLED_TENANTS` (JSON object of `tenant_id` to `true`/`false` or `1`/`0`) overrides the default per tenant.
3. Otherwise `ASTRANULL_PROTECTION_VALIDATION_ENABLED` (default off). Demo tenants (ADR-0016) are on unless the global switch is off.

When the gate is off, the routes above and `GET /v1/reports/protection-validation` return `404 protection_validation_disabled`, and the portal hides the target sections with an explicit "not enabled" notice. Turning the gate off never deletes declarations, baselines, evaluations, or findings. A running comparison of a tenant whose gate is off starts nothing more: its next advance skips pending and deferred paths with `skip_reason: "protection_validation_disabled"` and finishes as `cancelled`. Already-started runs stay cancellable through `POST /v1/test-runs/:id/cancel`. Operator procedure: [protection validation rollout](backend/protection-validation-rollout.md).

**Persistence modes.**

| Route family | dev-json | Postgres |
|---|---|---|
| Entry paths, firewall expectations, baselines, comparisons, matrix, report | wired | wired |
| `POST/GET /v1/entry-path-comparisons*` (plan, start, list, get, cancel) | wired | wired (migration `0071_entry_path_comparison_lifecycle.sql`); `503 postgres_route_not_wired` only when a runtime dependency is missing |

**Postgres comparison lifecycle.** The dev store and Postgres run the same lifecycle code (`src/services/entryPathComparisons.mjs`). In Postgres mode:

- `POST /v1/entry-path-comparisons` with `mode: "start"` accepts an optional `Idempotency-Key` header. Repeating it with the same reviewed plan returns `200` with `replayed: true` and the original comparison; the same key with a different plan is `409 idempotency_conflict` with `existing_id`. A tenant has at most one running comparison per reviewed plan digest, so concurrent identical starts replay that comparison. A replay of a still-running comparison also advances it once.
- The background advance runs from the Postgres validation-scan runner (`npm run validation-scan:runner`, also run on every `test-policy-runner` tick). Each tick resumes deferred paths, settles paths whose runs ended while another worker held the comparison lock, and retries evaluation links. When the tenant gate reads as off in the runner, the comparison is paused, not cancelled; only the API process cancels on the gate.
- `POST /v1/entry-path-comparisons/:comparisonId/cancel` waits up to 5 seconds for the comparison lock and otherwise returns `409 comparison_busy`.
- A path that keeps being deferred (hourly cap or cooldown) is retried until 24 hours after the comparison started, then skipped with `skip_reason: "deferral_limit_reached"` so the comparison can finish. Deferrals do not count as start attempts.
- Path state names are stored as `running`/`completed`/`cancelled`/`failed`; the API keeps the dev names (`started`, `finalized`, `skipped`) and always returns `skip_reason`.

**Comparison stop.** `POST /v1/entry-path-comparisons/:comparisonId/cancel` (body `{ reason? }`) skips every pending or deferred path and cancels started runs through the existing run cancel path. It returns `200` with the comparison view (`status: "cancelled"`). A finished comparison is `409 not_cancellable`. It never starts traffic. On every delegated protection-validation route the path parameter is authoritative: a body or query field that repeats a path parameter (`comparisonId`, `targetId`) with a different value returns `400 path_parameter_mismatch` with `field`, and nothing runs.

**Declaration responses** add `digest_verified`, `currently_authorized`, `authorization_state`, `authorization_reason`, and `entry_target_value`. Create routes accept an optional `Idempotency-Key` header; reusing a key with a different body is `409 idempotency_conflict`. Firewall baseline lists and reads return full capture records with `entry_count`.

**Comparison start** responses add `scope_digest` and per-item `execution_state` (`pending`, `deferred`, `started`, `finalized`, `skipped`), `skip_reason` (for example `kill_switch_active`, `protection_validation_disabled`, `comparison_cancelled`, `run_cancelled`, `approved_scope_invalid`, `entry_path_archived`, `ownership_not_verified`, `safe_window_closed`, `deferral_limit_reached`, `start_interrupted`), and `deferred_until`. Plans mark a declared login or API path ineligible with `login_path_state_change_risk` or `api_path_state_change_risk` when the only matching check would send a body or a non-GET/HEAD method; declared login and API paths only run `waf_class_marker_probe`, `waf_evasion_marker_probe`, `waf_enforcement_probe` or `http_head` checks. For the generic `marker` scenario they select `waf.entry_path_login_marker.safe` or `waf.entry_path_api_marker.safe` (GET/HEAD only, no body, no redirects). Start errors add `423 kill_switch_active` and `409 no_eligible_entry_paths`. Reads add `execution[]` and `attempts[]` (reference-only observations per path). A leg that answered without usable evidence keeps its gap outcome in `attempts[].observation` (for example `not_applicable` when a CDN edge answered a direct-origin request) instead of `not_tested`.

**Comparison views** add `evaluation_id` (the recorded `pvc_` evaluation once finished) and `items[].test_run_id`. A finished comparison is recorded through the same evaluation store as firewall comparisons; its stored evaluation keeps `expectation_id` and `comparison_id`.

**Firewall baselines and comparisons** use the PV-05 classifier (`classifier_version: "firewall-acceptance-v3"`; v1/v2 baselines are `check_version_mismatch` and need a fresh capture):

- Each baseline entry adds `classifier_version`, `observations[]` (`{ evidence_id, test_run_id, check_id, observation_class, evidence_tier, source_perspective, worker_id, destination_fingerprint, observed_at }`), and `observations_digest`.
- Capture requires current ownership of each baseline destination (`409 ownership_not_verified`). Unknown expectations are `404 unknown_firewall_expectation`; unknown runs are `404 unknown_test_run`.
- A valid service response comes only from a completed TLS handshake (`tls_audit`) or a non-5xx `host_sni_bypass` origin observation. TCP connects, open ports, and UDP replies are transport-only (E2) and never satisfy a required allow.
- Repeated TCP or service silence before a change is `pre_state: "not_observed"` for an expected deny; a later response is a `forbidden_service_newly_reachable` regression with reason `baseline_denial_not_control_specific`. Silence on both sides stays `inconclusive`.
- Comparisons add `post_test_run_ids`, `classifier_version`, `readiness_effect: "none"`, `observations` (per-expectation pre/post summaries; dropped with `observations_truncated: true` when too large), and `statement` (`{ headline, gaps, scope, not_established, readiness_effect }`). Active expectations of the same change that are not in the baseline are listed as `not_tested` with reason `not_in_baseline`; baselined expectations with no post-change sample are `not_tested` with reason `post_change_not_sampled`. Deny expectations are satisfied only by `icmp_admin_prohibited`; a refusal after an open baseline is an observed service change (`rst_after_change`), never firewall enforcement. Any HTTP status, TLS reply or banner is reachable. A refusal without an open baseline stays unverified (`rst_without_open_baseline`). Port scans report `open_ports`, `filtered_ports` and `closed_ports`.
- An identical evaluation request returns `200` with `replayed: true` and the stored record.

**Origin observation semantics (PV-01).** Edge-detection `network_firewall.direct_origin_reachability` adds `outcome` (`response_observed`, `application_identity_confirmed`, `explicit_denial_observed`, `no_response`, `transport_error`, `not_tested`), `label`, `explicit_denial_observed`, and `application_bypass_suspected`; its `status` can be `denied`. `protection.origin_lockdown_basis` is `explicit_denial_observed` or `null`, and lockdown is shown only with that basis. The five origin/WAF checks that use these executors are version `1.1.0`; historical verdicts are not rewritten. A `host_sni_bypass` explicit denial earns the readiness verdict `edge_protected` only when the observation also confirms origin lockdown (healthy permitted-path baseline); without a baseline the verdict is `inconclusive` and no protection credit is given. In bound WAF validation runs, every direct-origin result is recorded in the `origin_bypass` scenario family (`observed_action` `deny`, `origin_response`, or `inconclusive`) and never counts as an edge marker failure; only a nonce-confirmed application bypass sets `origin_bypass_confirmed`.

**Status-code semantics (`external-observation-v2`, 2026-10-06).** A bare HTTP status is never a denial. `direct_origin_reachability.outcome` adds `misdirected_request` (421), `probe_path_error` (407) and `not_applicable` (a CDN or WAF edge answered; `not_applicable_reason: "cdn_edge_ip"`, `edge_signal`). Observations add `denial_signature` (`{ kind: "vendor" | "declared", id, vendor }` or `null`), `response_reason` (`authentication_challenge` for 401, `unattributed_denial` for other unsigned 4xx, `generic_error_response` for 5xx) and `error_reason` (`connection_refused`). `origin_lockdown_confirmed` needs a customer-declared lockdown signature (status plus header or body hash, or a declared mTLS rejection) over a healthy baseline. Stored v1 observations are re-read under these rules and never edited.

Marker probes (`waf_class_marker_probe`, `waf_evasion_marker_probe`, `waf_enforcement_probe`, `waf_inspection_limit_probe`, `outside_in_waf_scan`) grade a marker as blocked only with a vendor or declared signature, read from headers and a bounded body prefix (at most 8 KB, never stored). A block page served with HTTP 200 (for example F5 ASM) counts as blocked. Without a signature: 2xx/3xx is allowed; 401 is inconclusive (`authentication_gate_precedes_inspection`); another 4xx that differs from the baseline is `block_suspected` (neither enforcement nor gap); 421, 407, 5xx and drops are inconclusive. Grading needs a healthy, unsigned permitted baseline. Marker rows add `blocked`, `allowed`, `inconclusive`, `block_suspected`, `reason`, `denial_signature` and `waf_product_hint`. Evasion results add `permitted_baseline` (`{ status_code, health, denial_signature }`), `permitted_baseline_health` and `inconclusive_reason` (`permitted_baseline_not_healthy`, `baseline_marker_not_blocked`, `baseline_marker_not_graded`, `transformed_marker_not_graded`). The WAF enforcement probe sends one GET (previously HEAD) so body signatures are visible. A signed denial on the permitted baseline of a marker leg is recorded as `explicit_denial_observed`, so a `must_not_be_reachable` login or API path that the edge blocks is `consistent_enforcement`. Version bumps: the 41 `waf.evasion_*.safe` checks and `l3.firewall_exposure_scan.safe` are `1.1.0` (this round); the host/SNI checks and `waf.fingerprint.safe` are `1.2.0`; WAF enforcement, inspection-limit and class-marker checks are `1.1.0`.

Other correlation rules from the 2026-10-06 staging run: a completed TLS handshake (`tls_audit`) is a TLS-profile result (`protected`, or `exposed` with the listed profile issues), never "blocked at the edge"; a bounded port scan whose only open ports are 80/443 is `allowed_as_expected` with no finding; WAF effectiveness ignores inconclusive marker rows instead of voiding the definitive ones. `l3.forbidden_tcp_port.safe`, `l3.forbidden_udp_port.safe` and `l3.ipv6_reachability.safe` also accept `tcp` (`host:port` or `[IPv6]:port`) targets; an unbracketed IPv6 literal is never split into host and port.

**Source perspectives.** A run's source perspective is resolved on the server from the signed worker id, never from worker-submitted metadata. With `ASTRANULL_APPROVED_PROBE_SOURCES` (JSON object of perspective to worker ids), only registered workers have a source; unknown workers are `source_missing`. Without it, every signed worker belongs to the shared pool `astranull-signed-public-worker`.

**Matrix.** `GET /v1/targets/:targetId/protection-validation` lists active paths anchored on the target. Rows add `entry_target_value`, `scenarios[]` (current item per scenario with `evaluation_id` and `freshness`), and `layers[].configuration`. `configuration` is explanation-only connector evidence (`evidence_role: "explanation_only"`, `absence_means: "unknown"`); it never changes `vendor_detection` or `observed_enforcement`. The response adds `counts`, `exclusions`, and `configuration_access` (`granted`, `redacted`, or `disabled`). Configuration uses the same gate as connector snapshots: `ASTRANULL_WAF_POSTURE_ENABLED`, tenant connectors, and the `waf:connector_read` permission (and API-key scope). When access is `redacted` (for example `viewer` or `soc`), rows omit `layers[].configuration` and `GET /v1/targets/:id` attaches only `protection_profile.configuration: { "configuration_access": "redacted" }`. A layer's `observed_enforcement` is set only when the driving check measures that layer (WAF/edge markers and direct-origin or HEAD checks measure `waf` and `cdn_edge`; bounded port checks measure `network_firewall`; nothing measures `ddos`). Other declared layers stay `not_tested` with the `layer_not_measured_by_scenario` limitation.

**Report.** `GET /v1/reports/protection-validation` (`report:read`; `?format=json|csv`, `?anchor_target_ids=a,b`) is a passive projection over the same predicates as the matrix (`report_kind: "protection_validation"`, `passive: true`, `executes_checks: false`, `sends_notifications: false`). Units are counted separately (applications, hosts, entry paths, target/check pairs, firewall expectations); vendor detection is reported apart from enforcement. CSV cells are escaped against spreadsheet formula injection. Each conclusion has `ignored_for_findings`, and the CSV has a matching `ignored_for_findings` column after `readiness_eligible`. The `unknowns` section adds `ignored_for_findings`, `creates_findings: false`, `counts_as_validated: false` and a `statement`. A passing result without finalized evidence reports as `unknown` (`inconclusive` for firewall) under reason `evidence_not_finalized`. For each firewall expectation the report uses the newest evaluation that sampled it; a later partial comparison that did not sample an expectation does not hide an earlier sampled result.

**Findings.** Every newly recorded evaluation (firewall comparison or finished entry-path comparison) derives deduplicated findings. Results with missing evidence create no finding and never update, escalate, close or reopen an existing one: path outcomes `inconclusive`, `not_tested`, `skipped`; firewall statuses `inconclusive`, `not_tested`, `stale`, `not_comparable`; and any item without a finalized evidence reference. Findings carry `source: "protection_validation"`, `dedupe_key` (`pvf_<sha256>`), `finding_class` (`confirmed_exposure`, `observed_enforcement_gap`, `observed_availability_gap`, `suspected_bypass`; stored legacy `unavailable_evidence` rows stay readable), `priority` (`p1`–`p4`), and `protection_validation` (comparison context, evidence references, limitations, candidate explanations marked not corroborated). A replayed evaluation creates nothing. Passing items never close a finding or its siblings; closing stays an explicit lifecycle action. Ordinary verdict findings never attach to a protection finding. In Postgres these columns come from migration `0069_protection_findings.sql`.

**Retests.** `POST /v1/test-runs` with `retest_of_finding_id` for a protection finding rechecks current execution authorization first: the active relation or expectation with the same scope, active same-tenant targets, an intact declaration digest, and current ownership. A failure returns `409 retest_not_authorized` with `reason` (for example `entry_path_archived`, `expectation_not_active`, `retest_scope_mismatch`, `target_not_authorized`) and starts nothing. The retest lineage stores `comparison_context`.

### Protection-validation review corrections (2026-10-07)

- Matrix responses add `scope_complete` and `source_truncation` for capped entry-path, evaluation, and expectation inputs. Counts describe the returned scope; a truncated view never represents the complete estate. The portal displays the partial-view state.
- Protection-validation JSON reports add `scope.source_records_complete` and `scope.source_truncation`; `incomplete_scope.reasons` includes `source_records_truncated` when needed. CSV includes `source_records_complete`. Unique-host counts deduplicate hostname and URL records by normalized hostname; target/check and entry-path units remain separate.
- A path evaluation uses its captured `expectation_id` to explain layer intent, not the latest expectation for the same scenario.
- Origin protection-finding retests with a missing or different `origin_binding_id` return `409 retest_not_authorized` with `retest_scope_mismatch` before dispatch. Mapped firewall findings and retests bind to the declared post-change target.
- A malformed or explicitly empty `ASTRANULL_APPROVED_PROBE_SOURCES` admits no workers; conflicting assignments give that worker no perspective. An unset registry alone uses the shared public pool. Explicit false tenant feature overrides also apply to demo tenants.

### Provider detection and live activity correction (2026-10-08)

`POST /v1/waf/edge-detection` retains its exact target-ID request shape and asynchronous response. It now starts `waf.fingerprint.safe` version `2.1.0`, kind `waf_fingerprint_observation`: one ordinary pinned GET and up to three counted CNAME lookups, with a five-second deadline. Detection is observation-only and outside readiness coverage; it never starts marker, POST, evasion, or origin-bypass requests. Historical versions remain retained.

`GET /v1/test-runs/:id/activity?limit=256` uses the existing bounded passive read. Final result items add safe protocol primitives in `observations` and `port_observations` with at most 15 valid port numbers per array (`open_ports`, `filtered_ports`, `closed_ports`). These fields do not enter correlation as new evidence. All existing tenant, provenance, preview redaction, and execution bounds remain unchanged.

`GET /v1/checks?scope=all` exposes the full authenticated static catalog, including `requires_additional_input`. The default remains the plain-selection catalog. Reading the complete catalog does not authorize dispatch: target compatibility, additional-input validation, subscription, ownership, SOC, and safe-run limits still apply. A full target assessment can include E2 observation checks; E2 results remain excluded from conclusive readiness coverage.
