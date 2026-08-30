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
| GET | `/metrics` | — | Metrics endpoint. The in-process route is unauthenticated; production deployments must restrict scrape access at the gateway/network layer per observability policy. |
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

### `POST /v1/auth/reset-password`

Unauthenticated, feature-gated. Request: `{ "token": "pwr_<one-time-secret>", "password": "a policy-compliant password" }`.

| HTTP | Response | Condition |
|---|---|---|
| `200` | `{ "status": "password_reset" }` | Token consumed atomically, verifier replaced, failed-attempts/lock/forced-change cleared, and session generation incremented so existing password sessions are invalidated. **No identity fields or bearer token are returned.** |
| `400` / `401` / `410` | `validation_failed` / `weak_password` / `invalid_reset_token` / `reset_token_expired` | Same shapes as the invite-setup route; reset tokens are single-use and expire after 30 minutes. |
| `429` | `{ "error": "rate_limited", … }` | Reset-set client limiter (10/minute per client key). |

### `POST /v1/auth/mfa/enroll` · `/v1/auth/mfa/verify` · `/v1/auth/mfa/disable`

Authenticated TOTP conditional access under the `profile:mfa` permission (every customer role). Enrollment generates a base32 RFC 6238 secret (SHA-1, 30 s, 6 digits) and returns `{ "status": "mfa_enrollment_started", "secret": "<base32>", "otpauth_uri": "otpauth://totp/…" }` exactly once; `verify` activates it after the user proves possession (`{ "totp": "<code>" }` → `{ "status": "mfa_enabled" }`); `disable` requires a currently valid code (`{ "status": "mfa_disabled" }`). Error shapes: `400 mfa_enrollment_not_started` / `409 credential_required` / `409 mfa_not_enrolled` / `401 mfa_invalid`. Logins for enrolled accounts require a non-replayed code (`mfa_required` / `mfa_invalid`); last accepted step is persisted to reject replay within the acceptance window. Audits `auth.mfa.enrollment_started`, `auth.mfa.enabled`, `auth.mfa.disabled`. Postgres persistence: migration `0043_password_resets_and_mfa.sql` (tenant-RLS `user_password_resets` with pre-tenant token-lookup policy; MFA columns on `user_credentials`).

## Tenant and environments

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| GET | `/v1/tenants/current` | `tenant:read` | — | Tenant object incl. `privacy_settings`. |
| PATCH | `/v1/tenants/current` | `tenant:write` | `{ privacy_settings?, name? }` | Updated tenant. `privacy_settings.metadata_retention_days`, `evidence_retention_days`, and `audit_retention_days` are normalized/clamped on read and write (defaults **365** / **1825** / **2555** per migration `0034`); changing privacy settings runs an immediate metadata retention purge for the current tenant (see [Privacy retention](#privacy-retention-metadata)). |
| GET | `/v1/environments` | `environment:read` | — | `{ items: Environment[] }`. |
| POST | `/v1/environments` | `environment:write` | `{ name, timezone? }` | `201` environment. |
| PATCH | `/v1/environments/:id` | `environment:write` | partial fields | Environment or `404`. |

## Target groups

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| GET | `/v1/target-groups` | `target_group:read` | `?archived=true` lists soft-deleted groups only | `{ items, count }` active groups by default (`deleted_at` / `archived_at` null). Each item carries the group row plus summary keys `target_count` (active declared targets in the group) and `loa_state` (`signed` when an active LOA signature exists, else `required`). The heavier detail fields stay on `GET /v1/target-groups/:id`. |
| GET | `/v1/targets` | `target_group:read` | — | `{ items, count, meta }` tenant-scoped inventory across active groups and targets. Verification, provenance, and eligibility are derived from authoritative server records, never target metadata. It performs no automatic inventory discovery. |
| POST | `/v1/target-groups` | `target_group:write` | `{ name, environment_id?, description?, timezone?, safe_test_windows?, safety_policy? }` | `201` group with server-owned `ownership_status: "unverified"` and `dns_ownership: null`. Active names are unique per tenant/environment, case-insensitively. Client ownership fields are ignored. |
| GET | `/v1/target-groups/:id` | `target_group:read` | — | Active group with active `targets[]`, `target_count`, LOA data, six recent runs (including persisted `policy_id` when scheduled), finding summaries, and empty-state `meta`. Archived target rows remain in history but are not returned. |
| PATCH | `/v1/target-groups/:id` | `target_group:write` | partial group fields | Updated group or `404`; changing either name or environment rechecks the active tenant/environment/name uniqueness scope. |
| DELETE | `/v1/target-groups/:id` | `target_group:write` | — | Soft-archives the group (`deleted_at`, `deleted_by`) or returns `409 target_group_active_run` while an active run still references it. |
| POST | `/v1/target-groups/:id/restore` | `target_group:write` | — | Clears `deleted_at` / `deleted_by` and returns `{ target_group }`; returns `404 not_archived` or `409 target_group_exists` when restoration would collide. |
| POST | `/v1/target-groups/:id/targets` | `target_group:write` | `{ kind?, value, expected_behavior?, metadata? }` | `201` canonical target, `400 invalid_target` for malformed values (including `IP:port` with kind `ip`), or `409 duplicate_target`. |
| POST | `/v1/target-groups/:id/targets:bulk-import` | `target_group:write` | `{ items: Target[], source?, connector_id? }` | `201 { imported, skipped, count }`. With `connector_id`, only canonical values present in that tenant-owned connector's latest inventory may be imported; otherwise source labels are customer declarations and are not trusted provenance. |
| PATCH | `/v1/target-groups/:id/targets/:targetId` | `target_group:write` | partial target fields | Updated canonical target, `404`, or scoped validation/dedupe error. |
| DELETE | `/v1/target-groups/:id/targets/:targetId` | `target_group:write` | — | Soft-deletes the target (`deleted_at`, `deleted_by`) while retaining verification, run, and audit history. |

Canonical target kinds are `fqdn`, `ip`, `url`, `tcp`, `dns_zone`, and `canary` (`domain`/`hostname` normalize to `fqdn`; omitted kind remains `fqdn`). FQDNs are lowercase without a trailing dot, URLs are credential-free HTTP(S) URLs without fragments, and TCP values use `host:port` or `[IPv6]:port`. Active target uniqueness is tenant/group/kind/canonical-value scoped. Every successful mutation is audited; Postgres mutation and audit rows share the same tenant transaction. Client ownership, verification, eligibility, source/provenance, audit, and internal provenance metadata fields are stripped rather than trusted.

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
| POST | `/internal/admin/approval-requests/:id/decision` | `staff:approval:decide` | decision payload | Approval decision or lifecycle conflict. |
| GET | `/internal/admin/audit-log` | `staff:audit:read` | `tenant_id?, staff_id?, action?, limit?` | `{ items }` internal audit rows. |

## WAF posture add-on

**OpenAPI:** [`docs/api/waf-posture-openapi.json`](api/waf-posture-openapi.json) — OpenAPI 3.1 artifact for WAF assets, coverage analytics, safe validations, orchestrator execute/retest/cancel paths, CVE playbooks, action items, RBAC, and metadata-only safety notes. Check locally with `npm run api:waf:openapi:check`. This artifact does **not** close staging/live orchestrator, provider, or security/release signoff gates.

Disabled by default. `ASTRANULL_WAF_POSTURE_ENABLED=1` enables the current route family; when disabled, `/v1/waf/*` returns `404 { "error": "waf_feature_disabled" }`. The add-on does **not** require cloud/WAF credentials for core no-access mode. PostgreSQL schema, migration support (`0008_waf_posture`), repository primitives, and `runtime.services.wafPosture` adapters exist for the WAF asset/coverage/validation/drift routes; in custom Postgres servers without an injected WAF service the API still fails closed with `503 { "error": "postgres_route_not_wired" }`.

WAF evidence is metadata-only. WAF validation contracts reject raw payload/body/header/packet fields, secrets, exploit material, SOC-gated profiles, prohibited profiles, automatic discovery approval, and protected-posture finalization without bound safe test-run evidence or explicit metadata-only scenario evidence.

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| POST | `/v1/waf/edge-detection` | `waf:run` | `{ target_group_id, target_id }` — both required opaque identifiers for an existing tenant-owned declared target. Raw `hostname`, URL/IP destinations, timeout overrides, and arbitrary probe fields are rejected (`400 raw_hostname_not_allowed`, `invalid_target_group_id`, `invalid_target_id`, or `unsupported_fields`). | `202 { detection_request }` only after the shared `testRuns.startTestRun` boundary durably accepts fixed check `waf.fingerprint.safe` for the exact group/target binding. The request includes `status: "queued"`, `test_run_id`, target ids, `check_id`, `run_status`, `test_run_url`, and `events_url`; response headers set `Location` to `test_run_url` and `Retry-After: 2`. Poll the returned test-run and events URLs for signed-worker evidence and the eventual verdict. The control plane performs no caller-directed DNS/HTTP egress; ownership, safe-window/rate, kill-switch, audit, and signed-worker dispatch gates are inherited from test-run start. Missing test-run wiring fails closed with `503 edge_detection_test_runs_unavailable`; governed start denials pass through. |
| GET | `/v1/waf/assets` | `waf:read` | — | `{ items }` tenant-scoped declared WAF assets. |
| POST | `/v1/waf/assets` | `waf:write` | `{ target_group_id, canonical_url? \| hostname?, target_id?, owner_hint?, expected_waf_required? }` | `201 { asset }`. Discovery candidates cannot be auto-approved through this route. |
| GET | `/v1/waf/assets/:id` | `waf:read` | — | `{ asset, current_posture? }` or `404`. |
| PATCH | `/v1/waf/assets/:id` | `waf:write` | metadata fields only | `{ asset }`; unsafe/raw fields are rejected. |
| POST | `/v1/waf/assets/:id/exception` | `waf:write` | `{ owner, reason, expires_at, scope_hash? }` | `201 { exception, posture }`; approved metadata-only exception is tenant-scoped, future-expiring, audited, and available to compliance exports. |
| GET | `/v1/waf/exceptions` | `waf:read` | — | `{ items }` active, non-expired tenant-scoped WAF exceptions. |
| GET | `/v1/waf/coverage` | `waf:read` | `window_days?` | Status counts, `percentages`, aggregate `coverage_ratio`, and `trend[]` rollups when available. |
| GET | `/v1/waf/coverage/summary` | `waf:read` | — | Dashboard summary from `waf_coverage_summary` matview (dev-json parity via rollup refresh): `{ assets_total, protected, underprotected, unknown, coverage_pct, by_vendor, connectors_active, connectors_degraded, connectors_disabled, refreshed_at }`. |
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
| POST | `/v1/connectors` | `waf:connector_write` | `{ provider, name, secret_id?, config, status? }` | `201 { connector }`; `config` is reduced to allowlisted metadata such as `read_only`, resource hashes, owner hints, tags, and polling interval. |
| POST | `/v1/connectors/:id/validate` | `waf:connector_write` | — | `{ status, capabilities, redacted_errors?, connector? }`; validation is local-only and requires `config.read_only=true`. |
| POST | `/v1/connectors/:id/poll` | `waf:connector_write` | `{ snapshots?: [...] }` | `202 { poll_job, snapshots }`; this ingests normalized metadata snapshots only. |
| GET | `/v1/connectors/:id/snapshots` | `waf:connector_read` | — | `{ items }` normalized metadata snapshots. |
| GET | `/v1/connectors/:id/inventory` | `waf:connector_read` | `?cursor=&limit=` | Credential-free, canonical, deduplicated target candidates from the tenant-owned connector's latest snapshot: `{ provider, account, scope: "read_only", discovered_at, items, count, next_cursor? }`. Missing, disabled, or revoked connectors fail closed. |
| POST | `/v1/connectors/:id/disable` | `waf:connector_write` | `{ reason? }` | `{ connector }`. |

## Bootstrap tokens

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| POST | `/v1/bootstrap-tokens` | `bootstrap_token:create` | `{ name, target_group_id?, max_registrations?, expires_at?, prebind_fqdn?, deployment_packaging? }` — optional `prebind_fqdn` (string) pins the FQDN an agent may report on heartbeat `probe_endpoint.declared_fqdn`; optional `deployment_packaging` is `image`, `standalone`, or `helm` (stored on token metadata). | `201` metadata + **`secret` once** (`ast_v1.…` tenant/token id hints; salted hash stored only; legacy opaque tokens still verify in dev store). |
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
| POST | `/v1/secrets` | `secret:write` | `{ purpose, name, plaintext, metadata? }` | `201` `{ secret }` metadata + redacted envelope (no plaintext). `503` `{ error: "encryption_not_configured" }` when `ASTRANULL_SECRET_ENCRYPTION_KEY` is unset. |
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
| GET | `/v1/agent-updates` | `agent_update:read` | — | `{ items: Release[] }` for caller tenant. |
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
| GET | `/v1/test-policies` | `test_policy:read` | — | `{ items }` active, non-archived per-group rules enriched with active target-group and check metadata. Policies for archived groups are omitted. |
| POST | `/v1/test-policies` | `test_policy:write` | `{ target_group_id, check_id, cadence?, expected_verdict?, safe_windows?, timezone?, enabled?, max_concurrent_runs? }` | `201` policy. Exactly one active rule is allowed per tenant/group/check. Only customer-runnable safe checks can be bound; SOC-gated/high-scale checks return `403 soc_gated_check`. |
| PATCH | `/v1/test-policies/:id` | `test_policy:write` | `{ cadence?, expected_verdict?, safe_windows?, timezone?, enabled?, max_concurrent_runs?, state? }` | Updated rule or `404`; `state` is `active` or `paused`, `enabled` is strictly boolean, and scheduling fields are recalculated server-side. |
| DELETE | `/v1/test-policies/:id` | `test_policy:write` | — | Soft-archives the rule and returns the archived record or `404`. |

Cadence is one of `manual`, `daily`, `weekly`, or `monthly`; timezone must be an IANA name. Safe windows accept at most 14 `{ day, start, end, timezone? }` entries, with `Mon`–`Sun` days, strict 24-hour `HH:MM`, and same-day `start < end`. Event-triggered policies are not exposed because no durable event consumer is configured; `event_driven` or `event_trigger` input fails closed. `expected_verdict` is `pass`, `warn`, `fail`, or `manual_review`. The current safety and active-run invariants cap `max_concurrent_runs` at exactly `1`.

Developer JSON and Postgres both persist due time, schedule revision, lease state, last dispatch/run, and durable occurrence records. Runtime-internal scheduling (not a public lease endpoint) queries due rules by tenant, acquires expiring tenant-scoped leases, and derives a stable tenant/policy/scheduled-time idempotency key. In Postgres deployments, schedule `npm run test-policy:runner -- --tenant-id <tenant>` (or `--tenant-ids-file <path>`) from cron/Kubernetes CronJob; it requires signed-worker configuration, never enumerates tenants, supports metadata-only `--dry-run`, and does not auto-migrate. Before each probe/agent dispatch, run creation re-reads the active group, active target, ownership evidence, enabled rule binding, and live lease; failures cancel a just-persisted run. Successful scheduled runs retain `policy_id`. Policy mutations and dispatch transitions are audited transactionally in Postgres.

## Test runs

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| POST | `/v1/test-runs` | `test_run:start` | `{ check_id, target_group_id, target_id?, probe_profile? }` | Starts a manual run. HTTP callers cannot fabricate trusted policy dispatch context or a scheduled `policy_id`; scheduled runs enter through the runtime-internal leased dispatcher. Returns `201` run + correlation nonce, with simulation/probe-job details by configured mode. Safety denials include `429` window/rate/cooldown errors, `403 soc_gated_check`, `409 concurrent_run_blocked`, and signed-worker Host/SNI `400 missing_target_bound_direct_address` unless the verified target itself is an IP or IP-literal URL. |
| GET | `/v1/test-runs` | `test_run:read` | — | `{ items }`. |
| GET | `/v1/test-runs/:id` | `test_run:read` | — | Run detail + verdict when present. |
| GET | `/v1/test-runs/:id/events` | `test_run:read` | — | Timeline events. |
| POST | `/v1/test-runs/:id/finalize` | `test_run:read` | — | Verdict after collection window. |
| POST | `/v1/test-runs/:id/cancel` | `test_run:start` | — | `200` cancelled run when status is `planned`, `running`, or `collecting`; `409` `{ error: "not_cancellable" }` for terminal runs. |

In `postgres` mode, `runtime.services.testRuns` backs the safe validation loop: `POST /v1/test-runs` and `POST /v1/test-runs/:id/cancel` enforce target declaration, customer-runnable check gating, prerequisites, safe windows, tenant rate/cooldown limits, concurrent-run blocking, tenant kill switch, audit logging, agent job dispatch, and signed probe-job creation in `signed-worker` mode; probe results ingest through `runtime.services.probeJobs`; agent `POST /v1/agents/:id/observations` uses exact-once job transition before observation evidence is written; probe/agent events correlate; automatic verdict publication runs when both sides correlate; `POST /v1/test-runs/:id/finalize` forces bounded no-observation finalization after the observation window; findings upsert from verdicts; audits cover starts, cancellations, probe jobs, observations, verdict publication, no-observation finalization, findings, denials, and rejected observations; raw packet/payload/header fields are rejected for metadata-only evidence. Guarded high-scale/SOC routes are backed by `runtime.services.highScale` in Postgres mode. **Release blockers** remain live/staging Postgres acceptance and tenant unit-of-work/concurrency hardening under load, not rewiring these route families.

## Findings

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| GET | `/v1/findings` | `finding:read` | — | `{ items }`. |
| GET | `/v1/findings/:id` | `finding:read` | — | Finding. |
| PATCH | `/v1/findings/:id` | `finding:write` | `{ status?, notes? }` | Updated finding. |
| POST | `/v1/findings/:id/export` | `finding:read` | — | Redacted export JSON: existing finding fields plus top-level `custody` (digest manifest; see **Export custody** below). |

## Reports

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| GET | `/v1/reports` | `report:create` | `limit?` | `{ items, capabilities }`. `items` is generated report metadata for the tenant, newest first; each item carries `period` (`null` when the report was generated without a declared window). `capabilities` is the authoritative builder enum set — `{ default_kind, default_format, default_period, kinds: [{ value, label }], formats: [{ value, label }], periods: [{ value, label }] }` from `src/contracts/complianceReports.mjs`; clients must render report kind/format/period pickers from it instead of hardcoding enum copies. |
| POST | `/v1/reports` | `report:create` | `{ kind?, title?, period? }` | `201` report with summary. `period` is optional and must be one of `last-7-days`, `last-30-days`, `quarter`, `all-time`; anything else returns `400 { error: 'unsupported_period', supported_periods }`. Omitted or empty stores `period: null`. |
| GET | `/v1/reports/:id` | `report:create` | — | Report metadata, including `period`. |
| GET | `/v1/reports/:id/export?format=json\|markdown\|html` | `report:create` | — | `format=json`: `{ payload, custody }`. `format=markdown` or `html`: redacted report text with an embedded **Custody** section (artifact id, `content_sha256`, canonicalization, `created_at`, optional `previous_audit_hash`). Self-contained HTML has no external scripts. |

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
| POST | `/v1/events` | `event:ingest` | `{ event_id, signal_type?, metadata?, test_run_id?, evidence? }` | `201` or `200` duplicate; rejects cross-tenant `tenant_id` and packet fields. |
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
| GET | `/v1/notifications` | `notification:read` | — | `{ rules, events }` for the caller’s tenant. Rules expose `destination_preview` only; events include `delivery_attempts` (channel, `destination_preview`, status, timestamps). No cross-tenant data and no full provider destinations. |
| POST | `/v1/notifications` | `notification:write` | `{ channel?, destination?, triggers?, enabled? }` | Created rule on success with `destination_preview` only in the HTTP response. Validates `channel` (`in_app`, `webhook`, `email`, `slack`, `teams`), `triggers` (allowed set), and webhook `destination` (`https://` or dev-only `http` hosts). Non-`in_app` rules require a non-empty `destination`. Invalid input returns HTTP `400` with `{ error, status: 400 }`. **Default:** external channels record `queued_provider_not_configured` (no outbound send). **Opt-in:** set `ASTRANULL_NOTIFICATION_DELIVERY_MODE=webhook` to POST redacted event JSON to webhook rules only (`delivered_provider` / `provider_retry_scheduled` / `provider_failed_dlq`); email/Slack/Teams remain metadata-only. |
| POST | `/v1/notifications/retries/process` | `notification:write` | `{ dry_run?, as_of? }` | Processes due `provider_retry_scheduled` attempts in forced metadata-only mode. Returns safe retry summary without internal `delivery_record`, full destinations, provider URLs, request/response bodies, logs, tokens, or secrets. Production still uses an externally scheduled runner plus provider/staging evidence. |
| POST | `/v1/notifications/dlq/redrive` | `notification:write` | `{ dry_run?, attempt_ids?, rule_id? }` | Requeues selected `provider_failed_dlq` attempts through the HTTP/UI metadata-only path. Client-supplied provider-delivery overrides are ignored; response strips internal `delivery_record`, full destinations, provider URLs, request/response bodies, logs, tokens, and secrets. |

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

Authenticated with `x-probe-worker-id`, `x-probe-timestamp`, and `x-probe-signature` (HMAC over method, path, timestamp, raw body, and optional tenant id). Requires `ASTRANULL_PROBE_MODE=signed-worker` and `ASTRANULL_PROBE_WORKER_SECRET` (≥32 characters). In `ASTRANULL_PERSISTENCE_MODE=postgres`, workers must also include signed `x-probe-tenant-id` (the reference worker accepts `--tenant-id` / `ASTRANULL_PROBE_TENANT_ID`) so `/internal/probe/*` routes can use tenant-scoped Postgres repositories. Human OIDC JWTs, signed-session tokens, and dev headers are **not** accepted on these routes.

| Method | Path | Auth | Response |
|---|---|---|---|
| GET | `/internal/probe/jobs` | Probe worker HMAC | `{ jobs: SignedProbeJob[] }` — pending jobs are leased to the worker on fetch. |
| POST | `/internal/probe/jobs/:id/result` | Probe worker HMAC | `{ external_result, safety_attestation, metadata? }` metadata only. **`safety_attestation`** (alias **`execution_summary`**) is required: `{ requests_sent, duration_ms, worker_version?, region?, completed_at? }` must be within the signed job `constraints.max_requests` and `constraints.timeout_ms`. Errors: `400` `missing_safety_attestation` / `invalid_safety_attestation`; `422` `safety_attestation_exceeded`. Rejects `packet_payload` / `raw_packet`. Accepted results create probe timeline event and evidence including sanitized attestation. |

`POST /v1/test-runs` in `signed-worker` mode returns `probe_job` metadata (including `job_signature`) and leaves the run in `running` until the worker posts a result, then `collecting` for agent correlation.

In Postgres mode, probe worker leasing and result ingestion are wired through `runtime.services.probeJobs`, and customer `POST /v1/test-runs` / finalize orchestration is backed by `runtime.services.testRuns` in the same persistence boundary. **Release blockers** remain staging/live multi-region signed-worker fleet matrix evidence (`probe_fleet_matrix`), gateway load/abuse and concurrency isolation under realistic probe load (`gateway_load_abuse`, `postgres_concurrency`), and operator-attested acceptance of customer-declared targets by vector — not missing internal poll/result or test-run route wiring.

## Audit and observability

| Method | Path | Permission | Response |
|---|---|---|---|
| GET | `/v1/audit-log` | `audit:read` | Tenant audit entries (production: paginated, durable store). |
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
