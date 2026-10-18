# Privacy and Data Retention

## Current outside-in capture contract (2026-10-15)

There are no customer agents or environments in the current product (ADR-0008); older references below are historical. `http-exchange.v1` adds bounded sanitized HTTP header entries and explicitly correlated metadata, not raw header/packet storage. Credential, cookie, authentication and unknown header values are withheld; Location userinfo/fragments/query values and credential-shaped URL paths are redacted. Binary/invalid UTF-8 and incomplete/truncated response samples are withheld rather than made readable through base64. Multipart/XML and form- or script-bearing HTML previews are also withheld because this capture path has no structure-aware sanitizer for them; ordinary small redirect HTML remains inspectable. Payload observations consume no additional response bytes. Raw public event ingestion remains prohibited.

Mandatory capture redaction cannot be disabled by `redact_headers_by_default: false`, and `store_packet_payloads: true` does not authorize raw packet capture. These existing flags must not be advertised as a new safe-preview opt-in or as proof that historical previews were disabled. The capture contract enforces conservative metadata-only behavior for either value without mutating tenant settings. Events and vault records use existing metadata retention and tenant legal holds; no new independent capture store or retention policy is introduced.

The implemented `DEFAULT_PRIVACY.metadata_retention_days` is **365 days**, not the historical suggested 90-day value below. This documentation correction does not change any tenant's configured retention.

## Data minimization

AstraNull should collect the minimum evidence needed to prove readiness.

| Data type | Default handling |
|---|---|
| Packet payload | Do not upload. Agent observation ingest rejects `packet_payload`, `raw_packet`, `payload`, `body`, `headers`, `raw_log`, `log_line`, and similar keys (case-insensitive) in body or metadata. |
| Packet metadata | Upload only fields needed for correlation. |
| HTTP headers | Redact sensitive headers. |
| Nonce | Store hash/fingerprint. |
| Agent logs | Operational logs only unless user opts in. |
| Authorization docs | Store encrypted with restricted access. |
| Reports | Tenant-controlled retention. |

## Retention settings

| Evidence | Suggested default |
|---|---|
| Safe run events | 90 days. |
| Findings | Until closed + retention period. |
| Reports | 1 year or tenant setting. |
| High-scale authorization | 3-7 years depending customer policy. |
| Audit logs | 1-7 years depending plan/regulatory need. |
| Agent health metrics | 30-90 days. |

### Tenant evidence retention (implemented)

`privacy_settings.evidence_retention` is normalized on dev-store migration and whenever tenant or environment privacy settings are patched. Defaults and clamps:

| Field | Default | Valid range |
|---|---|---|
| `audit_log_days` | 2555 (~7 years) | 365–3650 |
| `high_scale_artifact_days` | 2555 | 365–3650 |
| `report_days` | 365 | 30–3650 |
| `legal_hold` | `false` | boolean |

Legacy tenants without `evidence_retention` receive these defaults automatically. The day fields govern **policy documentation and future enforcement** for governance collections; they do not delete audit or high-scale records in the current dev-store slice.

### Retention policy snapshot (implemented)

`buildRetentionPolicySnapshot(tenant)` returns a redacted manifest suitable for audits and compliance review:

- `tenant_id`, `metadata_retention_days`, and normalized `evidence_retention`
- `protected_collections`: `auditLog`, `highScaleRequests`, `highScaleAuthorizationArtifacts`, `socNotes`, `socReports`, `findings`, `testRuns`
- `deletion_collections`: per-collection **effective** retention days for metadata purges (`events`, `evidenceVault`, `reports`, `notificationEvents`)

Snapshots and retention audit metadata include policy fields only—never customer document bodies, authorization file content, or secrets.

### Enforced metadata retention (implemented)

Tenant `privacy_settings.metadata_retention_days` controls automatic purging of **tenant-owned metadata** in the dev store. The default is **365** days; valid values are clamped to **1–3650** days during dev-store migration and when tenants or environments patch privacy settings.

When retention runs, the service removes records for **that tenant only** that are older than the retention window:

| Collection | Age field | Effective window |
|---|---|---|
| `events` | `timestamp` | `metadata_retention_days` |
| `evidenceVault` | `created_at` | `metadata_retention_days` |
| `reports` | `created_at` | `max(metadata_retention_days, evidence_retention.report_days)` |
| `notificationEvents` | `created_at` | `metadata_retention_days` |

Records without a parseable timestamp are **not** purged. Other tenants’ rows in those collections are never removed.

Purges do **not** apply to `auditLog`, `highScaleRequests`, authorization artifacts, `socNotes`, `socReports`, `findings`, `testRuns`, or target/agent identity records.

Implementation status:

- Dev store: immediate purge on tenant privacy-settings update and explicit `enforceMetadataRetentionForTenant(tenantId)`
- Postgres mode: tenant-scoped transactional enforcement via `runtime.services.retention.enforceMetadataRetentionForTenant(ctx, tenantId?)`
- Postgres dry-run/reporting: `runtime.services.retention.previewMetadataRetentionForTenant(ctx, tenantId?)` returns candidate delete counts without deleting rows or writing retention audits
- Postgres operator runner: `scripts/postgres-retention-runner.mjs` invokes preview or enforce for an **explicit** tenant id or JSON tenant list (`--tenant-id` or `--tenant-ids-file`), supports `--dry-run` and metadata-only `--out` summaries, requires `ASTRANULL_DATABASE_URL`, redacts database URLs in errors/output, and delegates all deletes to `runtime.services.retention` (governance collections are never purged by the runner itself). The script is **not** an in-repo cron daemon—operators schedule it externally.

Example operator schedule (external cron; adjust paths and tenant list file):

```bash
export ASTRANULL_DATABASE_URL='…'   # from vault/secret manager, never committed
node scripts/postgres-retention-runner.mjs \
  --tenant-ids-file /etc/astranull/retention-tenant-ids.json \
  --dry-run \
  --out /var/log/astranull/retention-$(date -u +%Y%m%d).json
# After review, run enforce on the same explicit list and attach --out JSON as staging evidence.
```

Postgres enforcement normalizes stale `privacy_settings`, evaluates the same collection set/window rules, deletes only tenant-owned metadata rows, and appends the corresponding retention audit event in the same tenant transaction.

#### Legal hold

When `evidence_retention.legal_hold` is `true`, the service **does not delete** any rows in the metadata collections above, even if they are past the retention window. The run returns zero delete counts. If rows would otherwise have been removed, the platform appends `privacy.retention_legal_hold` with `blocked_deletions` counts and the policy snapshot.

Legal hold in both dev-store and Postgres mode is **metadata-only**: it blocks deletion from `events`, `evidenceVault`, `reports`, and `notificationEvents`, while governance collections remain protected from automated purge entirely. Audit logs, high-scale requests, authorization artifacts, SOC notes, SOC reports, findings, and test runs are not deleted by this retention slice, and `audit_log_days` / `high_scale_artifact_days` remain policy fields until SOC/legal deletion workflows are defined.

#### Audit events

When metadata rows are deleted, the platform appends `privacy.retention_purged` with per-collection delete counts, effective metadata retention days, and the policy snapshot. If retention runs only to clamp or normalize stale `privacy_settings` and no rows are removed (and legal hold does not block deletions), normalized settings are persisted without a purge or legal-hold audit entry.

### Immutable evidence snapshot manifest (developer validation)

Operators can validate **metadata-only** JSON batches that describe immutable evidence snapshots (custody manifest digests, external storage references, retention/legal-hold policy fields, signer/key references, snapshot hash chain linkage, and operator signoff). `scripts/evidence-snapshot-manifest.mjs` reads a batch document, rejects raw evidence payloads, logs, tokens, secrets, database URLs, and ciphertext material, and writes a redacted manifest with an explicit **gaps** list when chain linkage or required policy metadata is incomplete.

```bash
node scripts/evidence-snapshot-manifest.mjs --input staging/evidence-snapshot-batch.json --validate-only
node scripts/evidence-snapshot-manifest.mjs --input staging/evidence-snapshot-batch.json --out output/evidence-snapshot-manifest.json
```

Unit tests: `tests/unit/evidence-snapshot-manifest.test.mjs`.

This utility is **manifest evidence only**. It does not upload to external object storage, does not perform KMS/HSM signing, and does not replace durable immutable archives or legal-hold enforcement in the runtime store.

## Origin-clue lifecycle (2026-10-17)

Origin source associations use the existing normalized `privacy_settings.metadata_retention_days` (default **365**, range **1–3650**) and existing `evidence_retention.legal_hold`; there is no separate origin retention setting. Tenant privacy PATCH and the explicit-tenant PostgreSQL retention runner include `originClues` / `origin_clues` and `originClueBatches` / `origin_clue_batches`. Clue age is `retrieved_at`, batch age is `created_at`, and the comparison is strictly older than the captured cutoff. Nullable/untrusted source observation time does not govern deletion. Dev rows with invalid/missing age fields are retained conservatively.

New batches can copy older deduplicated clues. Expiry therefore removes expired clue rows and batch payloads, and replaces an affected newer batch's **entire** saved response with a payload-free terminal expiry marker. This clears copied items and source coverage without deleting its fresh clue children or breaking their same-tenant/target FK. The minimum replay/FK envelope remains until the batch itself expires and has no retained children. A replay of that retained key returns `410 origin_clue_response_expired`, never DNS collection or implicit reimport. Deduplication does not refresh the original clue retrieval time. Fully expired/deleted keys no longer provide replay; a separately authorized new collection/import is new work.

`POST /v1/tenants/current/origin-clues/erase` provides **origin-source-only** erasure, using authenticated `tenant:write` (owner/admin plus token scope), explicit typed tenant confirmation and a bounded reason. Both preview and execute are permission-gated. It works with collection disabled and includes archived/deleted targets. Preview is read-only; execution deletes all tenant clue rows, then all tenant batches/markers/responses, atomically with a chained audit and returned audit entry ID. It does not delete targets, bindings, ownership, signed observations, findings, runs, reports, authorization artifacts, or governance/audit records. Target archival remains distinct from erasure.

Legal hold blocks ordinary expiry, response scrubbing, and explicit erasure. Preview returns blocked counts without writes; held erasure returns `409 origin_clue_erasure_legal_hold` with zero deletions, blocked counts, and a retained `privacy.origin_clues_erasure_blocked` audit. Successful erasure, including an empty repeated request, records `privacy.origin_clues_erased`. Audit/summary data contains counts, policy and bounded authorization metadata, not clue/source/response bodies.

Migration `0084` retains FORCE RLS and ordinary app UPDATE/DELETE rejection. Only a narrow `SECURITY DEFINER` lifecycle function owned by a dedicated `NOLOGIN`/`NOBYPASSRLS` role can remove rows or write the exact terminal marker. It pins `search_path`, schema-qualifies objects, has no PUBLIC execution or application-role membership, rechecks tenant context/current policy/legal hold, and validates an exact plan and audit inserted in the **same transaction** before mutation. Lifecycle audits reject UPDATE/DELETE, including attempts to erase an audit in the same transaction as the data. No caller-settable GUC bypass exists. Lock ordering is tenant advisory lock before tenant row lock. Role provisioning explicitly grants only execution of the lifecycle/plan functions.

Authenticated service RBAC is the human authorization boundary: the shared application DB login already inserts audits for all product roles. The database enforces bounded, audited lifecycle consistency; it does not cryptographically authenticate a human role or defend against a fully compromised application fabricating a well-formed authorized audit. Dev operations stage privacy/rows/audit and persist by fsynced temporary-file replacement before publishing memory changes; generation fencing rejects an in-flight collection after a committed lifecycle/policy change. This remains a single-process developer store, not a multi-process transactional database or backup-erasure guarantee.

See [ADR-0033](../adr/0033-origin-clue-lifecycle.md). Local tests and default-off status do not establish deployed retention, staging cadence/runbook acceptance, backup/archive erasure, strict catalog fault coverage, or operational/human signoff. Whole-tenant/governance destruction is not introduced.

## Production blockers (not yet implemented)

| Gap | Impact |
|---|---|
| Staging scheduled retention evidence | Operator CLI exists for explicit tenant lists; production still needs external scheduler deployment, cadence/runbook signoff, and retained dry-run/enforce JSON summaries from staging. |
| Regional data residency | No tenant-region pinning or export controls in storage layer. |
| KMS / HSM for envelope keys | Dev store holds AES-256-GCM envelopes keyed by `ASTRANULL_SECRET_ENCRYPTION_KEY` (32-byte base64 or hex); production startup is fail-closed without a valid key. External KMS/HSM, per-tenant keys, and automated rotation jobs remain open. |
| Governance collection purge | `audit_log_days` and `high_scale_artifact_days` are policy fields only until SOC/legal workflows define safe deletion. |

## Redaction

Redact by default:

- authorization headers,
- cookies,
- API keys,
- bearer tokens,
- session IDs,
- PII-like headers/fields,
- raw payloads.

## Completion criteria

Privacy is complete when customers can prove readiness without exposing unnecessary sensitive traffic data.
