# ADR-0022: Independent signing verification and passive firewall proof

Date: 2026-10-09

Status: Accepted for local implementation; operational acceptance remains unperformed.

## Context

An asynchronous signer receipt could previously become signed custody metadata without verifying its signature against operator-pinned trust. A firewall comparison could retain a normalized outcome but could not independently establish both performed sides, their accepted execution lineage, and their current material scope. Neither retained labels nor configuration readiness establish operational acceptance.

This decision extends ADR-0021 without adding customer cloud integrations, agents, discovery, high-scale execution, or a new SOC workflow.

## Decision

### Signing

- Verify the exact canonical, tenant-bound `astranull.evidence_signing.v1` envelope before returning signed metadata or auditing signing success. Do not sign or verify only the raw content digest.
- Resolve tenant/key trust independently of adapter responses. Bind algorithm, key reference, SPKI fingerprint, canonical base64, and signature length.
- Reject small-order, noncanonical, off-curve, or mixed-torsion Ed25519 public trust. Use the pinned `@noble/curves` public-point validator for canonical decoding and nonidentity prime-order subgroup checks; retain Node's native cryptographic signature implementation. DER import alone is insufficient.
- Require asymmetric issuance when either the deployment profile or `NODE_ENV` is production; invalid deployment profiles fail closed. Historical HMAC verification remains available. `signing_enabled: false` retires issuance, not historical verification.
- Use one bounded signer deadline for headers and body. Authenticate real-mode HTTPS requests to explicitly approved origins, do not follow redirects, and bound streamed response bytes. Cancel late responses even when an injected fetch implementation ignores abort.
- Never forward arbitrary adapter diagnostics or structured receipt source fields. Failure audits contain metadata-only rejection status, not credentials, signatures, submitted bodies, or dependency messages.
- Expose configuration readiness separately from `operationalAcceptance: not_verified`. Optional unsigned/degraded boot is not a production acceptance. `ASTRANULL_REQUIRE_EVIDENCE_SIGNING=1` requires usable configured material at startup, but still does not prove the real signer is online or retention is accepted.

### Firewall comparisons

- Keep existing immutable evaluation and baseline contracts. The evaluation's digest-covered `baseline_id`/`baseline_digest` binds the existing normalized, digest-covered pre-side references; its digest-covered item references bind the post side. Do not use optional provenance summaries as proof.
- Load exact baseline captures and the union of pre/post run evidence. Exact-run PostgreSQL qualification reads include jobs, events, vault links, nonce, immutable ingestion times, original lease, constraints, reservation, and completed status. Display feed caps are not completeness.
- Stamp `accepted-probe-execution.v1` into accepted result events after ingestion validates the lease and reservation. Its canonical digest binds the original job signature, destinations, profile, nonce, constraints, reservation, worker/lease, exact attestation, and actual external result.
- This receipt is a **server custody binding**, not a standalone worker digital signature and not permission to execute again. It does not establish packet-level observations or survive arbitrary simultaneous tampering with the trusted database and its audit/custody records. Reads never reopen a job, refund a reservation, or create traffic.
- Reject worker-supplied job IDs, source labels, and receipts; stamp those fields server-side. Read-time qualification uses the approved worker-to-source resolver, not an arbitrary stored source label.
- Reconstruct pre-side observations and the baseline digest from actual accepted samples, then rerun compatibility and classification on the complete post side. Compare the derived states, result, gap, reasons, and references with the immutable evaluation.
- Missing lineage, pre/post reuse, omitted contradictory events, later ingestion, wrong tenant/worker/nonce, incompatible versions/material scope, incomplete samples, and altered retained observations withhold current qualification. Historical records lacking the new receipt remain readable and require retest; do not backfill synthetic receipts.
- Normalize the persisted PostgreSQL lease timestamp to the original ISO instant before receipt comparison; never rewrite signed constraint timestamps. Exact-run capture/evaluation reads have no presentation limit that can omit a contradictory sample.
- Pass the configured worker-to-source resolver through accepted ingestion and passive report projection. Invalid/empty registries deny current source qualification; process environment never silently overrides an explicitly supplied runtime registry.
- Required freshness uses the shorter baseline/report window from the oldest required actual sample. Expired samples are stale with `actual_firewall_sample_expired`; reference timestamps cannot renew actual observations.
- Finite TCP, UDP, bounded-port, host/SNI and TLS observations explicitly report completion and actual endpoint facts. Finite observation completion is not a completed multi-leg protection comparison; missing/false completion still withholds qualification.
- A qualified firewall result is `sampled_ingress_only`. It supplies no DDoS readiness, rule-table, layer attribution, routing, east-west, or capacity assurance. TLS completion describes the finite handshake sample, not protection.

## Impact

No relational migration is required for these additions: receipts and producer context use existing event JSON metadata, while signing configuration is validated before runtime startup. Control-plane Compose forwards signer trust/auth/deadline settings and MFA customization, with a read-only signing-file mount. No deployment, production migration, live provider call, or real-fleet acceptance has been performed by this decision.

Focused local cryptographic, transport, complete-input, lifecycle, PostgreSQL-shape, and passive report regressions accompany the implementation. Broader release gates must be rerun against the final expanded source; the earlier ADR-0021 acceptance applies only to its historical snapshot.
