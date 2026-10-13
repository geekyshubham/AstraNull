# ADR-0027: Finding system summary, human notes and dated risk acceptance

Date: 2026-10-13

Status: Accepted

## Context

Findings stored the verdict explanation in `notes`, the same field customers edit during triage. Saving a triage note overwrote the machine text, and every reader that parsed `notes` for reason codes or posture status (the evidence inspector answer, WAF remediation context, action-item reason codes, the finding detail explanation panel) then treated human text as evidence. That breaks "evidence over assumptions": a typed note could change remediation steps or the inspector's explanation.

Risk acceptance was a bare status change. Any `finding:write` role, including engineers, could accept risk without a reason, an owner of the decision or a review date. The portal also described it as "terminal" and displayed it as "Closed", and the Accept and Close buttons discarded unsaved assignee and notes.

## Decision

1. **Two text fields with different owners.** `findings.system_summary` holds the server-written verdict explanation. Every finding creator writes it and leaves `notes` null, in both the dev store and Postgres: verdict publication, WAF posture findings (one shared `buildWafPostureFindingSummary` format, so Postgres reason codes parse the same way as dev), and protection-validation findings. A WAF re-validation refreshes `system_summary` on the open finding and never writes `notes`. `notes` is only what a person typed. A `PATCH` that names `system_summary` is rejected with `400 system_summary_immutable`; "immutable" means not client-writable, not frozen for the server.
2. **Readers use the summary.** Parsers read `system_summary` and fall back to `notes` only for legacy rows that have no summary. The evidence-context answer uses `verdict.explanation ?? finding.system_summary` and never `notes`. Customer projections scrub `system_summary` the same way as `notes` (ADR-0008 wording).
3. **Risk acceptance is a dated, attributable decision.** Setting `status: accepted_risk` requires the new `finding:accept_risk` permission (owner and admin only; API keys also need the scope). The body must carry `risk_acceptance: { reason, review_at }`: a trimmed reason of 20 to 2000 characters and a future ISO review date at most 365 days ahead, otherwise `400 risk_acceptance_required` naming the failing field. The server stamps `accepted_by` (the acting user) and `accepted_at`; clients cannot supply them. Any other status clears the record. A denied attempt is audited through `requirePermission`. The audit action stays `finding.updated` (ADR-0012) and its metadata carries the status and decision.
4. **Storage.** Migration `0080_finding_system_summary_and_risk_acceptance.sql` (version 0079 stays reserved for the held lifecycle source) adds `system_summary TEXT` and `risk_acceptance JSONB` with a shape check, backfills `system_summary` from the linked verdict explanation, and, for findings without a verdict, moves `notes` only when it is unedited server text (the exact WAF posture formats or one of the fixed protection-validation summaries). It clears `notes` only where it held an exact copy of that text. Edited notes stay in the editable Notes field, and those legacy rows keep the `notes` fallback until the next validation writes a summary. `db/schema.sql` carries the same columns; the in-memory dev store writes the same fields.
5. **Exports.** The custody-sealed finding export carries `system_summary` next to `notes` (both scrubbed of agent-placement wording), and the Postgres report finding rows select it, so moving the text out of `notes` drops nothing from exports. Report snapshot items stay reference-only (ids, status, severity), as before.
6. **Portal.** The finding page shows the summary read-only as "Recorded explanation", keeps the Notes box for human notes, offers the full lifecycle (start work, resolve, false positive, accept risk, close, reopen) with required reasons, and shows accepted risk as "Risk accepted by … on …, review by …", never as closed or terminal. Status changes send the current assignee and notes in the same request so nothing typed is lost.

## Consequences

- Saving a note can no longer change evidence answers, remediation steps or action-item reason codes; regression tests in `tests/unit/finding-lifecycle-backend.test.mjs` pin this.
- Engineers can still start work, resolve, close and mark false positives; only owners and admins accept risk, matching the RBAC matrix.
- Older rows without `system_summary` keep working through the legacy `notes` fallback until the migration runs.
- Closure and risk acceptance remain recorded decisions, not proof of a fix. No change touches probe execution, SOC gates or high-scale workflows.
