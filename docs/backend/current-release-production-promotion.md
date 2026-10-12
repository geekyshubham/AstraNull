# Passive production promotion prerequisites

Date: 2026-10-09. Engineering contract only; **no operational acceptance or deployment is performed**.

## Purpose

`npm run production:promotion:attest -- …` now validates explicitly retained candidate artifacts. It no longer selects a historical release, executes tests or live drills, collects fixture-derived signoffs, attaches verification markers, closes documentation gates, changes process configuration or deploys. Existing hosted collectors and rehearsal outputs must not be mistaken for genuine current-candidate operator acceptance.

This is platform release tooling, not a customer integration or new SOC workflow. Existing high-scale authorization gates remain mandatory.

## Inputs

All identity/artifact inputs are mandatory. No release or candidate identity comes from environment variables or a previous release.

```sh
npm run production:promotion:attest -- \
  --release-id CURRENT_RELEASE_ID \
  --candidate-sha EXACT_40_HEX_SOURCE_SHA \
  --image-digest sha256:EXACT_64_HEX_IMAGE_DIGEST \
  --schema-digest EXACT_64_HEX_SCHEMA_SHA256 \
  --evidence /owned/path/records.json \
  --evidence-digest EXACT_64_HEX_FILE_SHA256 \
  --manifest /owned/path/external-verification.json \
  --manifest-digest EXACT_64_HEX_FILE_SHA256 \
  --profile safe-validation-ga
```

The example uses placeholders, not an accepted candidate. Supported profiles are `full` (default), `safe-validation-ga` and `high-scale-ga`. Unknown, duplicate and missing-value arguments fail. Legacy `--base-url` is accepted for caller migration but unused: it grants no network operation.

Both artifacts must already exist as regular UTF-8 JSON object files, at most 16 MiB each. Files are opened once, size-checked before bounded allocation, and their exact read bytes checked against the externally supplied SHA-256. Non-regular, unreadable, growing/shrinking, invalid JSON and mismatched-digest inputs fail before aggregation. Pinning bytes prevents accidental substitution; it does not establish who created or approved the bytes.

Both artifact objects must declare the exact requested `release_id` and identical:

```json
{
  "candidate_binding": {
    "candidate_sha": "EXACT_40_HEX_SOURCE_SHA",
    "image_digest": "sha256:EXACT_64_HEX_IMAGE_DIGEST",
    "schema_digest": "EXACT_64_HEX_SCHEMA_SHA256"
  }
}
```

Evidence must declare `staging` or `production`, contain nonempty records, and every record must bind the same release, be `accepted`, non-rehearsal and operational. Local simulations, metadata-only fixtures and mixed releases are rejected or fail the downstream readiness contracts. Adding candidate fields to a rehearsal does not make it operational evidence.

## Evaluation and failure behavior

The command consumes the same in-memory bundle/manifest in the readiness aggregation API. Standalone gap-audit and external-verification commands also no longer generate missing manifests, including validate-only and legacy auto-attach calls. Template generation stays an explicit separate operator action and never constitutes acceptance. External qualification fails closed for invalid manifest schema/forbidden fields or mismatched/missing release identity across the requested release, manifest and evidence records. A result must match the exact release/profile and explicitly contain all three:

- `production_ready: true` — required inventory/documentation prerequisites;
- `customer_production_ready: true` — additional external verification prerequisites;
- `external_verification.complete: true`.

Missing/false values, invalid contracts and thrown verification errors fail with nonzero exit status. Local metadata inventory alone cannot succeed. A dependency-injected complete report in a unit test verifies wrapper behavior only, not real acceptance.

Success prints `prerequisites_valid=true`, exact release and candidate, and **passive validation only, not deployment approval**. Programmatic output retains candidate/input digests plus `passive: true`, `executes_drills: false`, and `grants_deployment: false`.

## Operator acceptance remains separate

This command does not authenticate human approvers, fetch referenced retained artifact contents, check the running deployed image, perform signer/IdP/retention/restore/fleet acceptance, execute tests, change firewall rules, inject outages or authorize deployment. Current candidate provenance, explicit owned target scope, approved execution window, rollback owner, genuine independent acceptance artifacts and applicable human approvals are still required before outward-facing operations. Historical hosts and release ledger entries supply no new authorization.

No successful local run of this prerequisite validator against genuine production acceptance artifacts is claimed. See the [expanded implementation ledger](../implementation/missing-capabilities-production-acceptance.md) for local tests and open production boundaries.
