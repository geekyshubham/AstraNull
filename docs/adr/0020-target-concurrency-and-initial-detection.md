# ADR-0020: Independent target execution and automatic initial provider observations

Status: Accepted, 2026-10-08.

## Problem

The direct-domain workflow retains a shared default policy scope. Legacy run and scan guards,
including database uniqueness, reserved that whole policy scope. Unrelated domains blocked one
another, and the signed probe worker processed leased jobs sequentially. Subdomains were ordinary
targets but inherited ownership could be omitted from the detail-page presentation. Initial
fingerprints required a separate manual request or a client-driven action.

## Decision

- A target has one active safe test-run slot. Different target IDs may execute concurrently while
  retaining the same policy settings. Same-target cooldown is recorded independently; hourly policy
  and tenant subscription allowances stay aggregate and unchanged. Only the subscription allowance
  can still defer a start; cooldowns and safe windows are advisory. Admission is briefly serialized
  per tenant in Postgres so concurrent starts cannot race aggregate budget reads. This lock is
  released after dispatch and is not held during probe execution.
- Active scans reserve their exact selected target sets. A tenant-scoped slot table plus database
  triggers reject overlapping scan sets and independent runs on a reserved target, even when two
  API processes race. Multi-target scans keep their existing sequential step plan. Legacy unbound
  run/scan records retain conservative policy-scope uniqueness until they finish.
- A new FQDN or URL target creates one initial `waf.fingerprint.safe` request as part of target
  creation. This includes manual/direct declarations, CSV, API/bulk imports and discovered child
  declarations. Postgres queues via an AFTER INSERT trigger in the target transaction; dev-json
  queues at each shared creation path. Dedupe key is `(tenant_id, target_id)`.
- The normal scheduler dispatches queued observations through `startTestRun`. No new egress path
  exists. Ownership, valid parent inheritance, suspension, subscription, concurrency and kill
  switch remain enforced; safe windows, cooldowns and hourly policy are recorded but never refuse.
  Missing prerequisites leave the request queued with a reason and a due retry time. An active validation
  scan has priority on that exact target. No page visit is needed to create or dispatch the request.
- Claims have bounded leases and conditional completion. A recovered lease reconciles a newer
  accepted run before retrying so an already-dispatched initial observation is not duplicated.
  A queued request is not probe evidence. Manual Detect remains available for deliberate retests.
- Existing policy-runner/validation-scan ticks dispatch initial observations for their explicit
  tenant scopes. The runner receives the WAF feature flag without requiring API-auth credentials.
  Dev-json uses a five-second, bounded scheduler tick, stopped on server close. Queue reads are
  passive and expose status, reason and accepted run ID on the target page.
- The probe worker processes at most four leased jobs concurrently, keeping duplicate target IDs
  in different batches. Each job retains its signed request/duration/destination limits, reporter,
  cancellation and attestation. No amplification or unmanaged high-scale execution is added.
- Subdomain links use their own target ID and open the same workspace/check catalog. A valid
  inherited proof is presented as such in both storage modes; no child receives broader high-scale
  approval. Import confirmation now states that initial provider detection is queued automatically.
  The job-claim boundary re-checks the signed parent proof and exact active same-tenant child-parent
  relation, including scope, tag and hostname boundary. A removed/revoked relation cannot authorize
  a job. Proof timestamps retain database precision so legitimate inherited jobs can be claimed.
  This supersedes ADR-0015's requirement for a separate initial detection action; later efficacy
  checks and retests remain explicit.

## Persistence and rollout

Migrations `0073` and `0074` replace group execution slots and add the FORCE-RLS initial queue.
The existing target-created and test-run/job/result audits remain authoritative; the scheduler's
`system` actor identifies automatic dispatch. Original signed evidence and verdicts are unchanged.
The Postgres migration queues existing active domain/URL declarations without a current edge
observation; it does not send traffic during migration. Every dispatch still checks current gates.

Validation covers independent and competing starts, overlapping scan sets, inherited child
workspaces, tenant isolation, queue claims/recovery, passive status reads, disabled prerequisites,
CSV/child intake and the fixed worker concurrency cap. Deployment is outside the current request.
