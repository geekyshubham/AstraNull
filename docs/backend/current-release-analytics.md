# Declared-host analytics

Current-scope list and rollup for active declared targets. The routes are mounted. Dev rows and Postgres call the same predicate.

## Routes

| Method | Path | Permission | Unit default |
| --- | --- | --- | --- |
| GET | `/v1/analytics/declared-hosts` | `target_group:read` | `hostname` (`normalized_hostname` in `unit`) |
| GET | `/v1/targets` with any query string | `target_group:read` | `target` |
| GET | `/v1/targets` with no query string | `target_group:read` | Unpaged legacy `{ items, count, meta }` |
| GET | `/v1/targets/:id/compatible-checks` | `target_group:read` | Read-only catalog projection |
| GET | `/v1/checks/:id` | `check:read` | Exact catalog row |
| GET | `/v1/audit-log` | `audit:read` | Filtered envelope |
| GET | `/v1/audit-log/:id` | `audit:read` | Exact own event |

Postgres without the matching reader returns `503 postgres_route_not_wired`. The dev store is not a fallback in Postgres mode. Compatible checks and check reads do not start a run. `runtime_launch_gates` and `launch_block_reason` are `not_evaluated`.

## Modules

| File | Role |
| --- | --- |
| `src/lib/declaredHostAnalytics.mjs` | Shared predicate, pagination, rollup |
| `src/services/declaredHostAnalytics.mjs` | Payload builders and `deriveProtectionProfile` projector |
| `src/persistence/postgres/declaredHostAnalyticsRepository.mjs` | Repeatable-read batch read |
| `src/services/targetGroups.mjs` | Dev `listDeclaredAnalyticsRows` and `getTarget` |
| `src/persistence/postgres/runtime.mjs` | Injects the pool reader and `getTarget` |

`readDeclaredHostAnalytics` on a pool opens one `REPEATABLE READ` transaction for every batch. A caller-owned client keeps its transaction.

## Query

Allowlist: `q`, `target_group_id`, `verification_state`, `kind`, `tag`, `service_role`, `criticality`, `owner_status`, `owner`, `family`, `family_status`, `freshness`, `has_open_finding`, `unit`, `cursor`, `limit`, `as_of`, `cohort_version`.

Aliases, and only these: `search`, `group`, `verification`, `role`. Unit tokens: `hostname`, `target`, `normalized_hostname`, `declared_target`. A conflicting alias is `invalid_query_value`. `origin_status` is not accepted.

Unknown names and unknown enums are `400`. `family_status` or `freshness` without `family` is `family_required`. `limit` is an integer from 1 to 200 (default 50). There is no default row cap. An explicit service `rowBound` that stops early returns `complete: false`, `unavailable_reason: read_bound_exceeded`, `total: null`, and `items: []`. The bound is never `total`.

Cursor v2 is `{ v, unit, k, id, fp, as_of, cv }`. A v1 cursor is `invalid_cursor`. Filter fingerprint mismatch is `409 cursor_filter_mismatch`. Clock mismatch is `409 cursor_clock_mismatch`. `cohort_version` or cursor `cv` mismatch is `409 cohort_changed` with the same `filters` and no substitute total.

`as_of` is the caller clock (`caller_evaluation_clock`) or `not_recorded`. It does not select a past estate. The first page with no `as_of` and no cursor uses the server clock. A later page with only a cursor keeps the cursor clock.

## Counts

`units.target_records` and `units.normalized_hosts` both come from one snapshot. `denominator` is the requested unit. Hostname and URL values collapse (`example.com` and `https://Example.com/login`). IP, CIDR, and IP-literal URLs stay in the target unit only.

`segments` on the analytics route is the family array for `rollup.segments.all[family]` when `family` is `waf` or `cdn`. Keys omit `unknown`. `unknown_count` is that unknown bucket only. `stale_count` repeats the stale segment. `list_query.query` is the echoed filters, with canonical `unit`. `role_segments` is the role object.

Filtered targets keep `items`, `count`, and `meta`, and add `total`, `page`, `units`, `list_query`, and `cohort_version`. `segments` on that route is the role object.

`rollup.freshness_policy.applied` is false. The projector calls `deriveProtectionProfile` with `edge_observed_at` mapped to `observed_at`, independent `waf_*` and `cdn_*` columns, `catalog: []`, and the same clock. `conflicting_vendor_signals` is copied onto WAF after derivation. `conflict` wins over `stale`. Raw `evidence_json` and non-tag metadata are not selected.

`verification_state` is the effective state from `target_verification_current` (dev: `effectiveTargetVerifications`). A stored `provider_verified` row is `pending` when the connector feature is disabled or the provider source is not current. The payload carries that status only, not `source_ref` or connector config. A missing row stays null (`unknown` in the predicate), not `unverified`.

The Postgres read is `ORDER BY t.id` keyset batches of 200 inside the one repeatable-read snapshot. A row committed on another connection after the snapshot starts is not part of `total`. The next request sees it and returns a new `cohort_version`.

## Audit reads

`queryAuditEntries` is the filtered envelope in both stores. `listAuditEntries` stays the newest-window array. A filtered request does not call that window. The Postgres cursor uses `to_char(..., 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`, not `Date.toISOString()`. `GET /v1/audit-log/:id` is the exact row; a cross-tenant id is `404`.

## Tests

`tests/unit/current-release-backend-analytics.test.mjs` covers the predicate, aliases, cohort and cursor mismatches, the explicit row bound, and a 10000-row exact total.

`tests/integration/postgres-current-release-analytics.test.mjs` covers RLS, the projector, a repeatable-read snapshot that ignores a concurrent insert, and a provider proof that is `pending` while the connector feature is disabled or the connector is revoked.

`tests/integration/current-release-backend-analytics-api.test.mjs` covers the routes in dev and, when the local harness is already up (`tryDocker: false`), through the app role.
