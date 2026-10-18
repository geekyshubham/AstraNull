# ADR-0033: Origin source metadata lifecycle

Date: 2026-10-17
Status: Accepted for local implementation; staging/operational acceptance remains separate

## Context

ADR-0032 introduces optional append-only unverified origin source records. Their batches save complete idempotent responses, including copies of older deduplicated clues. Migration 0083 rejects UPDATE/DELETE, so existing metadata retention cannot erase them. Target archival and disabling collection are not erasure.

## Decision

1. Use existing normalized tenant `metadata_retention_days` (default 365, clamp 1–3650) and `evidence_retention.legal_hold`; introduce no new retention-duration policy. Clues age from retrieval, batches from creation. Deduplication never refreshes clue age.
2. Expiry deletes expired clue rows and batches, and clears entire saved responses containing expired clue copies. A newer batch with fresh children keeps its minimum FK/replay envelope and a payload-free terminal marker until its own expiry. Retained expired-key replay returns 410 without refetch/reimport. A batch whose still-retained children need its FK envelope is not deleted; its response is terminalized.
3. Add explicit **current-tenant, origin-source-only** erasure with existing authenticated `tenant:write`, token scope, exact typed tenant confirmation and bounded reason. Preview is read-only. Execution deletes all clue rows then all batches/responses/markers, including archived-target records. Hold blocks expiry, scrubbing and explicit erasure; no force override exists. Empty repeated erasures still audit. This is not whole-tenant or governance destruction.
4. PostgreSQL keeps FORCE RLS and ordinary UPDATE/DELETE rejection. Migration 0084 adds a dedicated NOLOGIN/NOBYPASSRLS role without application membership and a narrowly granted SECURITY DEFINER function with pinned safe search_path. It rechecks current tenant/policy/hold, validates a transaction-fresh exact audit plan/counts, and permits only lifecycle deletion or an exact response-to-terminal-marker transition. No caller-settable GUC is deletion authority. Lifecycle audit rows reject UPDATE/DELETE, including within the deleting transaction.
5. Acquire tenant advisory lock before tenant row lock. Plan, existing metadata deletion, chained audit, origin response scrubbing and deletion share one transaction; any audit, plan/count, constraint or mutation failure rolls back all. PostgreSQL collection shares the same lock order. Dev operations stage privacy/data/audit and persist via fsynced temporary-file replacement before publishing memory changes. A store-bound generation fence rejects in-flight append **or replay** after a committed tenant lifecycle/policy change.

## Boundaries

The shared application DB login represents all authenticated roles and can insert audits. Service RBAC is human authority; the SQL function proves bounded audited transition consistency, not cryptographic identity of a human owner. Fully compromised application authority is outside that guarantee. No superuser/owner migration process can be made incapable of changing its own database. Dev JSON remains single-process; atomic replacement is not a multi-process database, backup-erasure guarantee or parent-directory-fsync/power-loss durability claim.

Governance records, signed evidence, targets, bindings, ownership, findings and runs are not erased by this operation. Durable archive/backup erasure, whole-tenant destruction and governance legal retention need separate workflows. Existing source-bound fault coverage, strict delivery receipts, staging retention scheduling, owned live acceptance and operational/human approvals remain unchanged.

## Verification

`origin-clue-retention.test.mjs` covers retrieval/cutoff semantics, newer copied responses with fresh children, terminal replay, scoped/held/confirmed erasure, persistence rollback, and deterministic dev append/replay races. `origin-clues-api.test.mjs` exercises the actual authenticated endpoint including default-off and held states. `postgres-origin-clue-retention.test.mjs` uses an owned loopback non-owner application login to exercise FORCE RLS, denied ordinary mutations/GUC/role assumption, transaction-fresh audit checks, immutable lifecycle audits, rollback and concurrent collection/hold/erasure. Migration/schema parity, additive 0083→0084 upgrade preserving preexisting rows/responses, idempotent reruns, explicit role execution re-provisioning and real PostgreSQL runtime/HTTP erasure plus privacy-PATCH expiry are also asserted. Actual command outcomes are recorded in PROGRESS; local tests are not production acceptance.
