# Validation schedule detail — UX/UI review

Review: 2026-10-03–04. Status: feedback/proposed work only; no implementation is approved by this file.

## User goal

Explain scope, cadence, next eligibility and why a schedule did or did not dispatch.

## Inspected surface and evidence

Route: `/app#policy-detail`. Observed heading: **Checkout daily bypass check**.
Source: `apps/web/react/src/pages/detail-pages.tsx: PolicyDetailPage`.
Browser evidence: [desktop](evidence/policy-detail-desktop.png), [route observations](evidence/route-observations.json).

This review used local synthetic fixtures. Missing/stale fixture relationships or dates are explicitly separated from verified UI/source problems. No production provider or live external-probe execution is claimed.

## Proposed hierarchy

Schedule identity and next occurrence → exact binding and timing → gate explanations → dispatch history; technical binding behind disclosure.

## Prioritized findings

### 1. [P1] A missing next run/window is not actionable

**Observed / evidence:** Inspected schedule has next eligible dash, no safe window, timezone not recorded, while it is Active.
**User impact:** Users cannot tell whether the schedule will actually run.
**Recommendation:** Show “Next run unavailable” with the exact missing configuration, and an authorized Edit schedule link. Differentiate active configuration from runtime eligibility.
**Acceptance check:** Active with missing timing never looks ready to dispatch; a user gets the concrete setup/recovery path.

### 2. [P2] Detail is descriptive rather than a management workflow

**Observed / evidence:** The page has binding facts and Dispatch gates but mostly navigation links.
**User impact:** Users must return to a list for schedule changes.
**Recommendation:** Provide contextual Edit/Pause/Resume/Archive using shared flows, with current binding and audit consequences restated.
**Acceptance check:** Actions respect permission and state and refresh this same entity after completion.

### 3. [P2] Technical IDs and “recorded” gates are hard to scan

**Observed / evidence:** Catalog IDs, raw expectation keys and multiple recorded/missing badges surround the schedule facts.
**User impact:** Configuration evidence is easy to confuse with a successfully executed run.
**Recommendation:** Translate gate descriptions into what happens next, with source detail available; keep the dispatch history outcome separate.
**Acceptance check:** No configuration gate is presented as a measured protection verdict.

## Actions, dialogs, widgets and states

Test Open exact target, linked check, group, technical binding disclosure, and dispatch-history links. Edit timing should preserve immutable bindings unless the backend explicitly permits replacement.

Keep loading, retained/stale data, unavailable, no data, filtered-empty, disabled-by-role, invalid input, saving, error and success states distinct. Use the shared dialog/keyboard/focus contract; destructive confirmations state the exact affected object.

## Data and functionality prerequisites

Current policy fields may omit timezone/window/next-run data. UI must request authoritative schedule metadata rather than invent it; linked run relationships require policy_id.

## Visual and motion direction

Use the existing theme tokens, restrained orange accents, familiar shared controls and visible 16–24px content insets. Give dense content a clear spacing owner; avoid nested surface borders and unexplained repeated pills. Animate only actual state changes with 90–200ms feedback and 200–300ms surface transitions; do not animate fake work or hide content before a reveal. Follow [motion specification](02-motion-and-interactions.md), including reduced motion and focus preservation.

## Skills for implementation

Use **UI/UX Pro Max**, then **Impeccable shape, clarify, adapt, harden, animate, polish**, plus **interaction-design** for forms, overlays and async feedback. Read [actual skill files and handoff](05-skills-and-handoff.md), [design direction](00-design-direction.md), and [naming](01-naming-and-navigation.md). Live validation pages also require [execution-trace specification](03-live-check-observability.md).

## Page acceptance criteria

Every disabled/missing gate explains next action; history uses exact policy relationships; empty dispatch history is distinct from a failed read; schedule management is consistent with the list.

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
| Decision / intended outcome | Understand when a schedule dispatches and resolve its blocker. |
| Data and interpretation | Immutable target/check binding, cadence/state, recorded next time/window, dispatch gates/history. Configuration proof is not execution proof. |
| Current path / context | Binding/schedule/gate/history panels; return to list for management. |
| Proposed continuation | Task editor with exact-check preview and target context; dispatch history outcome inspector; deep page retained. |
| Carry automatically | Policy/check/target, source timing, selected dispatch and safe draft. |
| Back / Close restores | Same policy section/list filters; no automatic target substitution. |
| Loading / missing / permission | 404 schedule, missing gate data, read-only role, edit conflict; no default Active for absent record. |
| Task acceptance | Find concrete next-run blocker and open linked check evidence without navigating general catalog. |

Apply [contextual inspector](19-contextual-evidence-inspector.md), [cross-page actions/return-state](20-cross-page-task-flow-contract.md), [data semantics](23-data-meaning-and-workflow-state-contract.md) and [confirmed source links](22-contextual-link-and-source-audit.md). Inspecting never executes; technical record routes remain optional depth. Verify completion using [design acceptance](17-design-acceptance-and-handoff-gates.md), not just route rendering.
