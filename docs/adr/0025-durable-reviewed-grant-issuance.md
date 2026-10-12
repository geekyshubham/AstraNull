# ADR-0025: Durable at-most-once reviewed grant issuance

Date: 2026-10-10

Status: Proposed implementation contract; local implementation and acceptance are in progress. Reviewed execution remains disabled.

## Context

[ADR-0023](0023-reviewed-inert-operation-preflight.md) provides passive exact-scope review, immutable original binding, detached independent grant cryptography and an internal current-authority loader. None establishes a durable unique signing opportunity. Hashing an original HMAC signature does not authenticate it. A successful authority callback can still run inside an enclosing uncommitted transaction; signing there could outlive rollback and leave another signing opportunity available.

The current platform cannot create a reviewed execution reservation through its ordinary reservation path. This prerequisite must consume actual server-stored reservation records or fail unavailable. Test-seeded records are not a delivered reservation or execution lifecycle.

## Decision contract

Add an internal, unregistered issuance ledger and orchestrator. Accept job/reservation identifiers and authenticated worker context only; never accept caller jobs, approvals, reservations, clocks, grants, verification booleans or transaction clients. Preserve the original canonical signed job payload, HMAC signature and constraints unchanged. Authenticate the actual original HMAC with configured server verification material.

Enforce one permanently consumed opportunity per tenant/job, tenant/run and tenant/reservation. Use same-tenant job/run/review foreign keys, FORCE RLS, bounded typed integrity constraints and immutable history. Store exact prepared envelope, original payload/signature and digests, actual reservation, current assurance-v3 scope, direct DNS-v2 proof/complete-history provenance and a cryptographically random completion-token hash. Never store private signing keys, bearer/worker secrets or plaintext job nonces.

The state machine is:

| State | Meaning | Permitted next state |
|---|---|---|
| `signing_unknown` | Opportunity consumed durably; signer outcome can be uncertain | Once to `issued` or `closed_unknown` |
| `issued` | Exact independently verified signature and completion audit committed | None |
| `closed_unknown` | Grant withheld; external signing may still have occurred | None |

There is no retry/reclaim/refund/renewal state. Expiry, process death, key retirement or lost response never frees a uniqueness slot. Terminal rows cannot be deleted, overwritten or reopened. Database integrity checks do not substitute for HMAC or Ed25519 verification.

## Commit and signing boundaries

1. Reject any enclosing active managed transaction. The orchestrator owns its commit boundary; an inner callback returning is insufficient.
2. Prepare inside a tenant transaction: acquire audit-first/run/kill-switch locks, reread actual job/run/reservation, authenticate HMAC and exact signed identity/lease/budgets, and compare current authority through the held managed-client loader. Require current assurance v3, exact direct DNS v2, an active run and unexpired original authority. Sample fresh database time after waits.
3. Build the exact immutable grant envelope using active pinned purpose-specific trust. Insert `signing_unknown` and preparation audit atomically. Commit before any signer invocation. Preparation rollback or an ambiguous commit acknowledgement invokes the signer zero times.
4. Only the newly claiming process signs, once, outside transactions. Sign the persisted envelope bytes without rebuilding its issuance time, budgets, key or deadlines. Check real current time and active trust before and after bounded signer I/O; verify the returned actual Ed25519 signature. Do not fake the clock to reproduce old issuance labels.
5. Finalize in another audit-first transaction. Require the original completion-token hash and still-unknown state; reauthenticate unchanged original HMAC/payload, actual lease/reservation, active run/kill switch, current material/review/ownership and fresh time. Verify exact envelope, active trust and independent signature. Commit `issued` plus completion audit before releasing a grant.
6. Failures close conservatively to `closed_unknown`; failed closure leaves the original opportunity consumed. A late response cannot reopen it. A committed issued replay returns the identical stored grant only after current revalidation, without signer I/O.

Authority clocks require canonical milliseconds. Project database lease/deadline clocks losslessly before validation; only exact `.ddd000Z` may become `.dddZ`. Genuine sub-millisecond history or authority is not rounded into permission. Complete history provenance is deterministically ordered; equivalent duplicate query order alone must not create a different authority winner. Conflicting/malformed history remains invalid.

## Execution boundary

Do not register a public route, construct a live signer by default, enable reviewed admission/reservation/worker/result ingestion, or remove runtime denial guards. An issued internal grant is a prerequisite for a later dual-authority lifecycle, not a protection verdict or an enabled execution path. Dev issuance remains unavailable without an equivalent durable backend.

No new cloud/read-only integrations, SOC workflow, customer agent/environment, discovery or unmanaged traffic is introduced. Existing high-scale SOC gates remain mandatory.

## Acceptance requirements

Local tests must exercise actual PostgreSQL application-role isolation and immutable constraints, real HMAC/Ed25519 verification, competing/replacement issuers, unknown/crashed/timed-out/lost outcomes, audit rollback and ambiguous commits, expiry while waiting, post-signing revocation/material/ownership/lease/run/kill-switch drift, key retirement, wrong completion ownership/envelope, exact stored replay and nested-transaction rejection. Signer responses are injected; no destination, public DNS or real signer I/O is required or authorized.

The implementation ledger must record actual passed/failed/skipped counts and the final source boundary before this status is accepted. Fixture success is not production migration, signer availability, reservation lifecycle, worker execution or human/operational acceptance. Historical HMAC-secret rotation requires explicit verification material; do not re-sign old jobs or silently substitute independent verification.
