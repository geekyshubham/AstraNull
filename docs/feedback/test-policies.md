# Test policies / validation schedules — UX/UI review

Review: 2026-10-03–04. Status: feedback/proposed work only; no implementation is approved by this file.

## User goal

Create and manage when checks run, on which exact targets, and under what windows and expectations.

## Inspected surface and evidence

Route: `/app#test-policies`. Observed heading: **Test policies**.
Source: `apps/web/react/src/pages/page-components.tsx: PolicyPage`; `apps/web/react/src/pages/refined/policies-refined.tsx`.
Browser evidence: [desktop](evidence/test-policies-desktop.png), [route observations](evidence/route-observations.json).

This review used local synthetic fixtures. Missing/stale fixture relationships or dates are explicitly separated from verified UI/source problems. No production provider or live external-probe execution is claimed.

## Proposed hierarchy

Active/upcoming/paused summary → schedules table with next run/timezone → one Create schedule workflow and an Edit schedule action.

## Prioritized findings

### 1. [P1] Scheduling vocabulary and defaults are difficult to reason about

**Observed / evidence:** Title is Test policies, action is Create schedule, row has Set weekly cadence, Pause, Archive. Dialog binds one target per selected group with a 222-entry check list.
**User impact:** Users cannot easily change a schedule intentionally or predict how many records will be created.
**Recommendation:** Use Validation schedules as screen label; provide guided Scope → Checks → Timing → Review, searchable check picker, and explicit number of bindings. Replace one-off cadence patch with Edit schedule.
**Acceptance check:** Review states exact targets, check, recurrence, timezone, window, first occurrence and record count before creation.

### 2. [P2] Timezone/window information is not prominent

**Observed / evidence:** Rows have next time, cadence and safe window; fixture has missing safe windows and identifiers that do not communicate local time.
**User impact:** A recurring validation can be mistaken for immediate or UTC-based work.
**Recommendation:** Show explicit timezone near every next occurrence; distinguish tenant timezone from viewer display time; warn when a configured window defers execution.
**Acceptance check:** A schedule spanning a date boundary/DST displays the same intended occurrence in list, detail and edit.

### 3. [P2] Design variants and wide repeated action columns add friction

**Observed / evidence:** Classic/Refined controls coexist with eleven table columns and repeated cadence controls.
**User impact:** Busy layout hides useful next-run and target context.
**Recommendation:** Choose one presentation; keep name, scope, next occurrence and state primary; move advanced fields into detail and row actions into an accessible menu.
**Acceptance check:** Paused and active states are labeled with their dispatch effect; primary schedule editing is easy at tablet widths.

## Actions, dialogs, widgets and states

Create schedule modal, scope picker, exact target selection, search/check choice, recurrence/expected verdict and review. Inspect Archive confirmation without submitting. Pause/resume/edit must announce success and refresh authoritative state; failed partial multi-group creation retains only unresolved selections.

Keep loading, retained/stale data, unavailable, no data, filtered-empty, disabled-by-role, invalid input, saving, error and success states distinct. Use the shared dialog/keyboard/focus contract; destructive confirmations state the exact affected object.

## Data and functionality prerequisites

Use current POST/PATCH/DELETE test-policy contracts; do not infer dispatch eligibility from enabled alone. Expected verdict is a declaration until measured. Current schedules apply only to supported bounded direct checks.

## Visual and motion direction

Use the existing theme tokens, restrained orange accents, familiar shared controls and visible 16–24px content insets. Give dense content a clear spacing owner; avoid nested surface borders and unexplained repeated pills. Animate only actual state changes with 90–200ms feedback and 200–300ms surface transitions; do not animate fake work or hide content before a reveal. Follow [motion specification](02-motion-and-interactions.md), including reduced motion and focus preservation.

## Skills for implementation

Use **UI/UX Pro Max**, then **Impeccable shape, clarify, adapt, harden, animate, polish**, plus **interaction-design** for forms, overlays and async feedback. Read [actual skill files and handoff](05-skills-and-handoff.md), [design direction](00-design-direction.md), and [naming](01-naming-and-navigation.md). Live validation pages also require [execution-trace specification](03-live-check-observability.md).

## Page acceptance criteria

Next run and timezone reconcile across views; no missing window appears as confirmed; partial creation has explicit recovery; users can alter cadence beyond a hardcoded weekly button; all errors retain inputs.

- Test 375/768/1024/1440px, dark/light, 200% text zoom, keyboard, reduced motion and touch targets.
- Validate the exact entity and role with real API behavior; do not synthesize missing provider/evidence/verdict data.
- Compare before/after screenshots and complete the primary workflow, including cancellation and recovery.
- Preserve outside-in-only scope, no default cloud access, and existing execution authorization.
- Update implementation docs/tracker only in a later authorized implementation task; this review does not mark features complete.

## Shared composition and task requirements

Apply [component standard](12-component-visual-specification.md), [content/mobile task budgets](14-content-and-responsive-task-budgets.md), and [feedback/persistence rules](16-feedback-responsiveness-and-daily-use.md). Reuse the appropriate R1–R5 [reference pattern](11-reference-screen-specifications.md), then verify this page’s primary task through [G0–G5 gates](17-design-acceptance-and-handoff-gates.md). No proposed screen, brand choice or usability result is approved/completed merely because this review exists.


## Data-to-decision and cross-page task contract

Source/saved-evidence review added 2026-10-04; proposed UX only, not new live verification.

| Contract | Page requirement |
| --- | --- |
| Decision / intended outcome | Edit schedule scope and timing without reconstructing bindings. |
| Data and interpretation | Schedule/check/target/group, enabled state/cadence/next time/window/expectation, declared timing vs actual dispatch. Missing next run is not imminent execution. |
| Current path / context | List links group/target; named check points to general checks; weekly patch/pause/archive; create modal has scope selection. |
| Proposed continuation | One schedule editor with bindings/check preview/timing/timezone/blockers; scoped actions keep row; exact check destination. |
| Carry automatically | Policy ID, immutable binding, current fields/version, caller filters and safe draft. |
| Back / Close restores | Schedule list state/selected row; edit errors retain timing choices. |
| Loading / missing / permission | Missing timing/check, partial multi-create, paused, not editable, rate/window/authorization gates. |
| Task acceptance | Edit shows correct target/check/timezone and next eligible fact; named-check preview preserves editor. |

Apply [contextual inspector](19-contextual-evidence-inspector.md), [cross-page actions/return-state](20-cross-page-task-flow-contract.md), [data semantics](23-data-meaning-and-workflow-state-contract.md) and [confirmed source links](22-contextual-link-and-source-audit.md). Inspecting never executes; technical record routes remain optional depth. Verify completion using [design acceptance](17-design-acceptance-and-handoff-gates.md), not just route rendering.
