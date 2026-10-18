# ADR-0030: Verdict proof and correlated exchange evidence

Date: 2026-10-15
Status: Accepted for local implementation, not deployed

## Context

A validation result could cite informational activity events, then fail the stricter live-readiness verifier. The UI conflated invalid references with no recorded evidence and could show a historical gap as current. Transport activity lacked exchange identity and sanitized header values; logical operation totals were labeled as HTTP requests. A custom inert-token GET check also looked like an actual HTTP-method test.

## Decision

1. Verdict publishers cite only the authoritative result consumed by their evaluator. Current external assurance continues to require explicit signed, same-tenant/run, nonce-bound, temporally available proof. Activity remains inspectable telemetry, never verdict proof. Missing, invalid/unresolved, stale and out-of-scope proof have distinct explanations. Both persistence paths follow the same contract.
2. Preserve immutable historical verdicts, evidence, exports and custody digests. Existing bad citations are diagnosed, not silently repaired or accepted at read time. Current proof needs an explicitly authorized new run. This decision introduces no correction lineage or automatic retest.
3. Extend existing bounded activity JSON with `http-exchange.v1`, local operation/attempt/exchange IDs, actual protocol facts and sanitized header entries. Correlation uses the original job/lease plus explicit exchange ID, never URL/time proximity or a newer run. Old records are not assigned invented IDs or headers.
4. Header values use a small allowlist with mandatory credential/unknown-value redaction and URL-aware Location sanitization. Response samples are observed only as the existing consumer reads them. Binary/invalid UTF-8, incomplete and sample-truncated versioned bodies are withheld rather than exposed through encoding or incomplete secret scrubbing. Multipart/XML and form- or script-bearing HTML are withheld without a bounded structure-aware sanitizer. Existing activity and signed-message limits do not increase.
5. Preserve legacy safety accounting; expose source-labeled nullable logical probe/DNS/total operations separately. A reserved or started operation does not establish an HTTP send.
6. Keep friendly names and purpose/limits in presentation metadata keyed by stable check ID, outside executable definition digests. True evaluator changes still require version changes and retest. Verdict production, finding eligibility, protection assurance and readiness credit remain separate capabilities. Custom-token observations do not establish a customer-installed rule or broad managed-rule coverage.
7. Keep result explanations and Request/Response details in the existing Inspector/activity experience, with inert escaped bodies, explicit unavailable states, exact run identity and existing passive reads/Stop controls.
8. Existing on-demand verdict replay keeps published history separate from current correlation. When old response features are insufficient, reapply current logic to original recorded outcomes and return original placements; do not copy the stored verdict into a projection with a contradictory explanation. Replay publishes nothing and starts no traffic.

## Consequences

- New worker fields require compatible server acceptance first. No new storage table or production migration is introduced by the additive activity format.
- Safe previews are not packet capture. Existing packet-storage/header-preference flags cannot disable mandatory sanitization or authorize raw capture. Event retention/legal holds and tenant access remain unchanged.
- Some historical results remain unverifiable, and some body samples are intentionally withheld. The UI must explain these limitations, not fabricate bytes or infer protection.
- All current definitions remain in the audit denominator, including unsupported/governed/declaration entries. Executed definition receipts do not prove all fault branches or independent mechanisms.
- The passive full-catalog evidence generator uses artifact schema 4 / generator v3 for the corrected default-FQDN matrix: 165 unique safe checks and 721 vector rows (364 safe-runnable, 10 needing input, 254 SOC-gated, 49 monitor-only, 44 not runnable). Historical schema 2/3 artifacts and prior captured inputs are not upgraded or rewritten; stale totals are rejected. This metadata-only generator neither runs probes nor confers live-readiness eligibility.
- No new target traffic, attack tooling, cloud access, discovery, customer agents/environments, redirect following, stopped mechanism or reviewed execution capability is enabled.

## Verification

Deterministic loopback transport, sanitizer/size, strict proof, adapter/PostgreSQL RLS, exact catalog, and UI/browser/accessibility regressions are required. Test outcomes and unresolved acceptance gates are recorded in PROGRESS and the existing audit ledgers. Local test success is not production or human acceptance.
