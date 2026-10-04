# Current-release handoff scope

This file records the user's scope correction. The handoff is documentation only; application code, routes and backend behavior are not changed.

## Included

Customer/public pages and direct bounded checks on declared targets: target inventory/profile, ownership, exact-check previews, target-centered live evidence/results, findings/remediation, compatible direct-check schedules, reports, integrations/notifications, audit, account/settings/support and current public access flows.

28 page review files remain. Direct-check execution is an embedded target workflow, specified separately as a shared flow; it is not an additional standalone page.

## Deferred — no implementation tasks in this handoff

Staff admin, tenant administration, SOC console/request execution, staff sign-in, and related privileged approvals/queue/emergency/program workflows belong to a future release. Their page reviews, task assignments and supporting route entries have been removed.

Standalone Test Runs, single-run detail and scan/session detail are not part of the current UX handoff. Do not replace them with renamed standalone “Validation runs” pages. Results, history and live proof appear against the target/direct check.

## Existing authorization remains

Removing future UI work does not remove product safety rules or backend evidence. Existing recorded execution IDs can remain internal provenance. High-scale execution remains authorized and SOC-gated under AGENTS.md; this handoff assigns no design or implementation work for it.

Direct bounded checks cannot establish volumetric capacity. Do not add a capacity/program widget, request form or privileged executor to make the current release appear more capable.

## Handoff rule

Read this scope before page specifications. Earlier references to deferred pages are superseded. A later explicit user request can define future-release work; do not reconstruct it from removed documentation or backend route names.
