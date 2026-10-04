# Findings queue — UX/UI review

Review: 2026-10-03–04. Status: feedback/proposed work only; no implementation is approved by this file.

## User goal

Prioritize observed gaps, identify affected endpoints and owners, and move to remediation.

## Inspected surface and evidence

Route: `/app#findings`. Observed heading: **Findings**.
Source: `apps/web/react/src/pages/functional-surfaces.tsx`; `apps/web/react/src/pages/refined/findings-refined.tsx`; `apps/web/react/src/lib/finding-groups.mjs`.
Browser evidence: [desktop](evidence/findings-desktop.png), [route observations](evidence/route-observations.json).

This review used local synthetic fixtures. Missing/stale fixture relationships or dates are explicitly separated from verified UI/source problems. No production provider or live external-probe execution is claimed.

## Proposed hierarchy

Open/high-priority/SLA summary → actionable grouped queue → concise filters → selected finding or affected-assets drill-down.

## Prioritized findings

### 1. [P1] Grouped rows need explicit rules versus finding/asset counts

**Observed / evidence:** Page shows one row per rule, one rule across one matching finding, and affected assets, while dashboard counts open findings.
**User impact:** Users can confuse fewer rows with fewer issues or tested assets.
**Recommendation:** Label group/rule counts, finding instances and distinct targets separately; explain grouping in one short helper.
**Acceptance check:** Filters and summaries reconcile with the same underlying findings; grouping never silently merges conflicting outcomes.

### 2. [P2] Technical check names compete with outcome labels

**Observed / evidence:** Origin direct bypass title appears beside an Origin Leak Scan check label in the fixture.
**User impact:** Users cannot distinguish the observed failure from the test method.
**Recommendation:** Lead with the outcome, show plain check method as secondary context, and retain IDs only in technical detail.
**Acceptance check:** Outcome and method remain separately labeled even when a check can produce multiple findings.

### 3. [P2] Filter density and design variants dilute triage

**Observed / evidence:** Open/Closed/Accepted/All, severity/owner/group/sort, row-size options and Classic/Refined occupy a large control area.
**User impact:** A user spends attention configuring the queue rather than resolving gaps.
**Recommendation:** Choose one presentation, lead with Open and urgent items, consolidate advanced sorting/density and show active filters.
**Acceptance check:** Queue can be scanned by severity, impacted service, assignee, deadline and next action at 1024px.

## Actions, dialogs, widgets and states

Inspect lifecycle filters, search, severity/owner/group/sort selectors, pagination, Classic/Refined and grouped-row drill-down. Changing filters should keep clear totals and offer reset for no matches. Group detail opens affected assets rather than implying a bulk risk decision.

Keep loading, retained/stale data, unavailable, no data, filtered-empty, disabled-by-role, invalid input, saving, error and success states distinct. Use the shared dialog/keyboard/focus contract; destructive confirmations state the exact affected object.

## Data and functionality prerequisites

Use actual finding lifecycle, reason/outcome identity, exact-target relationships and reported SLA. Do not invent an SLA when no policy is recorded. Fixture count differences across subscription/dashboard need data-source reconciliation before claiming a UI arithmetic defect.

## Visual and motion direction

Use the existing theme tokens, restrained orange accents, familiar shared controls and visible 16–24px content insets. Give dense content a clear spacing owner; avoid nested surface borders and unexplained repeated pills. Animate only actual state changes with 90–200ms feedback and 200–300ms surface transitions; do not animate fake work or hide content before a reveal. Follow [motion specification](02-motion-and-interactions.md), including reduced motion and focus preservation.

## Skills for implementation

Use **UI/UX Pro Max**, then **Impeccable shape, clarify, adapt, harden, animate, polish**, plus **interaction-design** for forms, overlays and async feedback. Read [actual skill files and handoff](05-skills-and-handoff.md), [design direction](00-design-direction.md), and [naming](01-naming-and-navigation.md). Live validation pages also require [execution-trace specification](03-live-check-observability.md).

## Page acceptance criteria

Rule/instance/target counts are explicit; open and accepted-risk states are distinct; selection/filter survives back navigation; urgent findings show useful deadlines or Not recorded.

- Test 375/768/1024/1440px, dark/light, 200% text zoom, keyboard, reduced motion and touch targets.
- Validate the exact entity and role with real API behavior; do not synthesize missing provider/evidence/verdict data.
- Compare before/after screenshots and complete the primary workflow, including cancellation and recovery.
- Preserve outside-in-only scope, no default cloud access, and existing execution authorization.
- Update implementation docs/tracker only in a later authorized implementation task; this review does not mark features complete.

## Consolidated remediation addition

Use [remediation workflow](08-drift-concentration-remediation.md) to display one actionable proposed change, accountable owner and explicit affected targets. Existing issue grouping is a foundation, not proof that all members share one fix. Display original evidence, current work state and per-target retest status; dashboard top actions consume these same relationships.

## Shared composition and task requirements

Apply [component standard](12-component-visual-specification.md), [content/mobile task budgets](14-content-and-responsive-task-budgets.md), and [feedback/persistence rules](16-feedback-responsiveness-and-daily-use.md). Reuse the appropriate R1–R5 [reference pattern](11-reference-screen-specifications.md), then verify this page’s primary task through [G0–G5 gates](17-design-acceptance-and-handoff-gates.md). No proposed screen, brand choice or usability result is approved/completed merely because this review exists.


## Data-to-decision and cross-page task contract

Source/saved-evidence review added 2026-10-04; proposed UX only, not new live verification.

| Contract | Page requirement |
| --- | --- |
| Decision / intended outcome | Prioritize observed gaps and inspect proof before triage. |
| Data and interpretation | Finding instances versus issue groups versus targets; severity/lifecycle/owner/SLA, original evidence/time and later retest. Missing SLA not guessed. |
| Current path / context | Grouped list → member/detail → evidence/artifact routes; filters/row context useful. |
| Proposed continuation | Finding action opens outcome/evidence inspector; group selects member beside list; scoped triage/retest. |
| Carry automatically | Finding/group/member target, original run/artifact, queue filters and safe notes. |
| Back / Close restores | Same lifecycle/severity/owner/cohort/sort/page/selection. |
| Loading / missing / permission | No matches, no open findings, stale/partial source, accepted risk distinct from resolved. |
| Task acceptance | Finding row primary proof one action; group counts reflect exact current filter and membership. |

Apply [contextual inspector](19-contextual-evidence-inspector.md), [cross-page actions/return-state](20-cross-page-task-flow-contract.md), [data semantics](23-data-meaning-and-workflow-state-contract.md) and [confirmed source links](22-contextual-link-and-source-audit.md). Inspecting never executes; technical record routes remain optional depth. Verify completion using [design acceptance](17-design-acceptance-and-handoff-gates.md), not just route rendering.
