# Reports — UX/UI review

Review: 2026-10-03–04. Status: feedback/proposed work only; no implementation is approved by this file.

## User goal

Prepare a report for a specific audience and scope, preview it, then export a trustworthy evidence snapshot.

## Inspected surface and evidence

Route: `/app#reports`. Observed heading: **Reports**.
Source: `apps/web/react/src/pages/page-components.tsx: ReportsPage`.
Browser evidence: [desktop](evidence/reports-desktop.png), [route observations](evidence/route-observations.json).

This review used local synthetic fixtures. Missing/stale fixture relationships or dates are explicitly separated from verified UI/source problems. No production provider or live external-probe execution is claimed.

## Proposed hierarchy

Audience → scope/period → preview → export/verify; recent reports use human title first with generated time and snapshot scope.

## Prioritized findings

### 1. [P1] Generate & export skips a meaningful preview decision

**Observed / evidence:** Header action creates/exports while form offers many kinds and JSON default.
**User impact:** A nontechnical user can generate the wrong scope or format before understanding content.
**Recommendation:** Provide Generate preview then Export, or a single explicit review step restating audience, targets/groups, period, evidence freshness and exclusions.
**Acceptance check:** Executive and technical reports have a clear scope preview and do not mix current metrics with historical snapshot without labeling.

### 2. [P2] Report-kind list mixes audience and compliance framework

**Observed / evidence:** The existing selector mixes audience and framework choices. Limit this release handoff to current customer audiences/framework mappings; deferred operational audiences are excluded.
**User impact:** Users cannot tell audience from framework or assume regulatory certification.
**Recommendation:** Group Audience and optional Framework separately; explain evidence mapping versus compliance assertion.
**Acceptance check:** No report selection implies certification or legal compliance from metadata alone.

### 3. [P2] Recent report list leads with IDs and empty metadata

**Observed / evidence:** Fixture table shows rpt IDs while period/format are unrecorded.
**User impact:** Users cannot distinguish artifacts without opening each record.
**Recommendation:** Lead with title/audience, exact scope/period if recorded, generated time and export availability; retain ID in detail.
**Acceptance check:** Missing report metadata is shown as Not recorded, not silently defaulted.

## Actions, dialogs, widgets and states

Inspect audience/kind/format/period selectors, recent report links, form validation and preview integrity states. JSON/Markdown/HTML are supported. PDF is a future capability; do not add a fake Download PDF button or equate browser printing with a native report export.

Keep loading, retained/stale data, unavailable, no data, filtered-empty, disabled-by-role, invalid input, saving, error and success states distinct. Use the shared dialog/keyboard/focus contract; destructive confirmations state the exact affected object.

## Data and functionality prerequisites

Report generation/export/custody contracts govern snapshot scope. Any new target/group filter needs backend support and tenant isolation. Report-read roles may differ from generate/export permissions.

## Visual and motion direction

Use the existing theme tokens, restrained orange accents, familiar shared controls and visible 16–24px content insets. Give dense content a clear spacing owner; avoid nested surface borders and unexplained repeated pills. Animate only actual state changes with 90–200ms feedback and 200–300ms surface transitions; do not animate fake work or hide content before a reveal. Follow [motion specification](02-motion-and-interactions.md), including reduced motion and focus preservation.

## Skills for implementation

Use **UI/UX Pro Max**, then **Impeccable shape, clarify, adapt, harden, animate, polish**, plus **interaction-design** for forms, overlays and async feedback. Read [actual skill files and handoff](05-skills-and-handoff.md), [design direction](00-design-direction.md), and [naming](01-naming-and-navigation.md). Live validation pages also require [execution-trace specification](03-live-check-observability.md).

## Page acceptance criteria

Historical report values are labeled snapshot values; unsupported format is clear; export failure preserves report selection; integrity claims come only from explicit verification.

- Test 375/768/1024/1440px, dark/light, 200% text zoom, keyboard, reduced motion and touch targets.
- Validate the exact entity and role with real API behavior; do not synthesize missing provider/evidence/verdict data.
- Compare before/after screenshots and complete the primary workflow, including cancellation and recovery.
- Preserve outside-in-only scope, no default cloud access, and existing execution authorization.
- Update implementation docs/tracker only in a later authorized implementation task; this review does not mark features complete.

## Segmented protection reporting

Report [service-role coverage](07-dashboard-protection-analytics.md), independent provider attribution, [readiness dimensions](06-host-protection-profile.md), maintenance and comparable changes as explicitly labeled sections. Snapshot cohort IDs, units, applicability, freshness, source refs and exact direct-check scope. User-supplied third-party report numbers are design input, never AstraNull tenant results.

## Shared composition and task requirements

Apply [component standard](12-component-visual-specification.md), [content/mobile task budgets](14-content-and-responsive-task-budgets.md), and [feedback/persistence rules](16-feedback-responsiveness-and-daily-use.md). Reuse the appropriate R1–R5 [reference pattern](11-reference-screen-specifications.md), then verify this page’s primary task through [G0–G5 gates](17-design-acceptance-and-handoff-gates.md). No proposed screen, brand choice or usability result is approved/completed merely because this review exists.


## Data-to-decision and cross-page task contract

Source/saved-evidence review added 2026-10-04; proposed UX only, not new live verification.

| Contract | Page requirement |
| --- | --- |
| Decision / intended outcome | Preview intended scope before exporting. |
| Data and interpretation | Audience/kind/period/format, persisted reports and integrity evidence. Framework mapping is not certification. |
| Current path / context | General form audience/format precedes scope content; Generate & export primary. |
| Proposed continuation | Caller scope initialized in preview, explicit estate-wide choice, then review/export; report title leads history. |
| Carry automatically | Target/group/cohort, snapshot/window/source refs and audience, safe preview choices. |
| Back / Close restores | Same originating target/cohort or report list/preview options. |
| Loading / missing / permission | Unsupported format, unavailable scope, read-only export, partial source; no silent estate-wide fallback. |
| Task acceptance | Preview/export reflect caller scope; export is explicit and avoids silently broadening target report. |

Apply [contextual inspector](19-contextual-evidence-inspector.md), [cross-page actions/return-state](20-cross-page-task-flow-contract.md), [data semantics](23-data-meaning-and-workflow-state-contract.md) and [confirmed source links](22-contextual-link-and-source-audit.md). Inspecting never executes; technical record routes remain optional depth. Verify completion using [design acceptance](17-design-acceptance-and-handoff-gates.md), not just route rendering.
