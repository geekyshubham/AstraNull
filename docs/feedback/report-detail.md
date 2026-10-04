# Report detail — UX/UI review

Review: 2026-10-03–04. Status: feedback/proposed work only; no implementation is approved by this file.

## User goal

Understand the generated snapshot, its scope and limitations, then export or verify it.

## Inspected surface and evidence

Route: `/app#report-detail`. Observed heading: **Checkout edge readiness summary**.
Source: `apps/web/react/src/pages/detail-pages.tsx: ReportDetailPage`.
Browser evidence: [desktop](evidence/report-detail-desktop.png), [route observations](evidence/route-observations.json).

This review used local synthetic fixtures. Missing/stale fixture relationships or dates are explicitly separated from verified UI/source problems. No production provider or live external-probe execution is claimed.

## Proposed hierarchy

Report title/time/scope → executive or technical content preview → snapshot factors/findings → export menu and integrity result.

## Prioritized findings

### 1. [P1] Snapshot and current linked data coexist

**Observed / evidence:** Report summary contains recorded score/open findings, while coverage description says finding counts reflect current exact-run relationships.
**User impact:** Readers may treat changed live findings as original report contents.
**Recommendation:** Separate At generation from Current linked status with explicit timestamps; avoid overlaying live counts onto a historical report as though immutable.
**Acceptance check:** An old report retains its score/findings; live remediation context is clearly separate.

### 2. [P2] Export JSON is duplicated

**Observed / evidence:** Header and Export formats repeat JSON, with separate Markdown/HTML actions.
**User impact:** Repetition adds chrome and hides the actual report contents.
**Recommendation:** One export menu with formats plus a dedicated integrity panel; preview content first.
**Acceptance check:** Formats and verification state stay accessible without duplicate primary buttons.

### 3. [P2] Missing factor/period fields need a useful explanation

**Observed / evidence:** Fixture shows no factor array and unrecorded period.
**User impact:** Users cannot judge how the score was constructed.
**Recommendation:** Show available snapshot inputs and “Not included in this report” for missing sections, plus regenerate with explicit scope when authorized.
**Acceptance check:** Missing metadata never borrows the current dashboard factors.

## Actions, dialogs, widgets and states

Inspect each export option, digest verification states, report source links and unavailable-section states. Do not publish/share reports during review. Export actions should show in-progress/error/completed feedback and preserve current selection.

Keep loading, retained/stale data, unavailable, no data, filtered-empty, disabled-by-role, invalid input, saving, error and success states distinct. Use the shared dialog/keyboard/focus contract; destructive confirmations state the exact affected object.

## Data and functionality prerequisites

Use persisted report snapshot and its explicitly captured run IDs. Current finding relationships are live context only. PDF/immutable storage remain capability boundaries.

## Visual and motion direction

Use the existing theme tokens, restrained orange accents, familiar shared controls and visible 16–24px content insets. Give dense content a clear spacing owner; avoid nested surface borders and unexplained repeated pills. Animate only actual state changes with 90–200ms feedback and 200–300ms surface transitions; do not animate fake work or hide content before a reveal. Follow [motion specification](02-motion-and-interactions.md), including reduced motion and focus preservation.

## Skills for implementation

Use **UI/UX Pro Max**, then **Impeccable shape, clarify, adapt, harden, animate, polish**, plus **interaction-design** for forms, overlays and async feedback. Read [actual skill files and handoff](05-skills-and-handoff.md), [design direction](00-design-direction.md), and [naming](01-naming-and-navigation.md). Live validation pages also require [execution-trace specification](03-live-check-observability.md).

## Page acceptance criteria

Report preview/export agrees on scope/time; verification state is explicit; unavailable factor data is not invented; historical and live values cannot be confused.

- Test 375/768/1024/1440px, dark/light, 200% text zoom, keyboard, reduced motion and touch targets.
- Validate the exact entity and role with real API behavior; do not synthesize missing provider/evidence/verdict data.
- Compare before/after screenshots and complete the primary workflow, including cancellation and recovery.
- Preserve outside-in-only scope, no default cloud access, and existing execution authorization.
- Update implementation docs/tracker only in a later authorized implementation task; this review does not mark features complete.

## Host-profile snapshot semantics

Preserve profile/provider/dimension/cohort data as-of report generation. [Drift and remediation history](08-drift-concentration-remediation.md) requires explicit before/after baselines; live remediation must not rewrite a historical report. Unknown origin hosting and untested direct-check dimensions remain visible rather than borrowing current dashboard state.

## Shared composition and task requirements

Apply [component standard](12-component-visual-specification.md), [content/mobile task budgets](14-content-and-responsive-task-budgets.md), and [feedback/persistence rules](16-feedback-responsiveness-and-daily-use.md). Reuse the appropriate R1–R5 [reference pattern](11-reference-screen-specifications.md), then verify this page’s primary task through [G0–G5 gates](17-design-acceptance-and-handoff-gates.md). No proposed screen, brand choice or usability result is approved/completed merely because this review exists.


## Data-to-decision and cross-page task contract

Source/saved-evidence review added 2026-10-04; proposed UX only, not new live verification.

| Contract | Page requirement |
| --- | --- |
| Decision / intended outcome | Read historical result and its evidence in context. |
| Data and interpretation | Report snapshot score/factors/findings/captured runs/time, export state and live linked state separately. |
| Current path / context | Summary/export/custody/factor/coverage panels; linked records can scatter snapshot evidence. |
| Proposed continuation | Snapshot answer/evidence inspector with context; one export menu; current remediation clearly separate. |
| Carry automatically | Report snapshot/ref IDs, selected finding/run, caller list. |
| Back / Close restores | Same report section/selection; full artifact returns to snapshot. |
| Loading / missing / permission | Missing historical data, newer live status, verification unavailable, export denied. |
| Task acceptance | Primary report evidence preserves historical observation, not latest run; live status never rewrites report. |

Apply [contextual inspector](19-contextual-evidence-inspector.md), [cross-page actions/return-state](20-cross-page-task-flow-contract.md), [data semantics](23-data-meaning-and-workflow-state-contract.md) and [confirmed source links](22-contextual-link-and-source-audit.md). Inspecting never executes; technical record routes remain optional depth. Verify completion using [design acceptance](17-design-acceptance-and-handoff-gates.md), not just route rendering.
