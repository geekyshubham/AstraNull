# Target group detail — UX/UI review

Review: 2026-10-03–04. Status: feedback/proposed work only; no implementation is approved by this file.

## User goal

Understand declared scope, verify its members, manage shared constraints, and choose a bounded validation.

## Inspected surface and evidence

Route: `/app#target-group-detail`. Observed heading: **edge-checkout**.
Source: `apps/web/react/src/pages/target-group-detail-view.tsx`; `apps/web/react/src/pages/detail-pages.tsx`.
Browser evidence: [desktop](evidence/target-group-detail-desktop.png), [route observations](evidence/route-observations.json).

This review used local synthetic fixtures. Missing/stale fixture relationships or dates are explicitly separated from verified UI/source problems. No production provider or live external-probe execution is claimed.

## Proposed hierarchy

Group header and concise proof/LOA summary → Targets | Validation settings | Schedules | Activity sections; keep per-target proof and actions in a clear table, advanced LOA/custody below.

## Prioritized findings

### 1. [P1] Missing detection reads “Not detected yet”

**Observed / evidence:** Declared target rows without an edge observation show Not detected yet.
**User impact:** Never checked and completed-with-no-signature are different conclusions.
**Recommendation:** Use Not checked for absent observation, Detecting for active work, Not detected only for usable negative evidence, and Unknown for failed/stale/conflicting results.
**Acceptance check:** A fresh untouched domain is never presented as evidence of no WAF/CDN.

### 2. [P2] Ownership ladder explanations dominate scope management

**Observed / evidence:** The page explains exact proof rungs and group rollup before the operational target list; LOA prints a long digest.
**User impact:** Users must understand internal aggregation to take a simple ownership action.
**Recommendation:** Show verified X/Y and locked reasons first; provide rung explanation and digest behind disclosures. Put TXT challenge next to the selected target.
**Acceptance check:** Verification workflow is identifiable above detailed scoring explanation; long digests wrap or copy without expanding layout.

### 3. [P2] Too many row actions and global rule dependencies

**Observed / evidence:** Rows offer Verify, Detect edge, Run test, Remove, while a separate Bounded run rule must be selected elsewhere.
**User impact:** A click can depend on offscreen state and confuse the target/check pairing.
**Recommendation:** Make one primary next action per row; use a target-scoped launch sheet that restates target, selected rule and bounds; secondary actions live in a menu.
**Acceptance check:** The launch confirmation shows exact target/check, disabled reasons are adjacent, and no first-target fallback occurs.

## Actions, dialogs, widgets and states

Inspect Add target, Import CSV, Import DNS zones, scan launcher, target selection, rule selectors and disclosures. Import CSV must preview accepted/rejected rows and explain atomic behavior before submit. Import provider zones remains optional, explicit selection. Remove names the target and future-test impact. DNS TXT copy/check controls need feedback, expiry and retry behavior.

Keep loading, retained/stale data, unavailable, no data, filtered-empty, disabled-by-role, invalid input, saving, error and success states distinct. Use the shared dialog/keyboard/focus contract; destructive confirmations state the exact affected object.

## Data and functionality prerequisites

GET /v1/target-groups/:id already includes exact-target edge detections. Ownership, LOA and safe-window rules remain server-authoritative. Separate missing metadata from actual negative evidence.

## Visual and motion direction

Use the existing theme tokens, restrained orange accents, familiar shared controls and visible 16–24px content insets. Give dense content a clear spacing owner; avoid nested surface borders and unexplained repeated pills. Animate only actual state changes with 90–200ms feedback and 200–300ms surface transitions; do not animate fake work or hide content before a reveal. Follow [motion specification](02-motion-and-interactions.md), including reduced motion and focus preservation.

## Skills for implementation

Use **UI/UX Pro Max**, then **Impeccable shape, clarify, adapt, harden, animate, polish**, plus **interaction-design** for forms, overlays and async feedback. Read [actual skill files and handoff](05-skills-and-handoff.md), [design direction](00-design-direction.md), and [naming](01-naming-and-navigation.md). Live validation pages also require [execution-trace specification](03-live-check-observability.md).

## Page acceptance criteria

Group proof reconciles with target rows; raw digest does not crowd the header; import errors preserve the file/selection; verification targets the chosen hostname only; all launch dialogs restate scope and controls.

- Test 375/768/1024/1440px, dark/light, 200% text zoom, keyboard, reduced motion and touch targets.
- Validate the exact entity and role with real API behavior; do not synthesize missing provider/evidence/verdict data.
- Compare before/after screenshots and complete the primary workflow, including cancellation and recovery.
- Preserve outside-in-only scope, no default cloud access, and existing execution authorization.
- Update implementation docs/tracker only in a later authorized implementation task; this review does not mark features complete.

## Member protection profiles addition

Link each member to its [host profile](06-host-protection-profile.md). Summary counts must show actual tested/unknown member coverage rather than one group PASS. Optional provider concentration uses role-specific known/unknown associations. Any declared origin relationship requires the separate verification and scope binding in [engineering review](09-engineering-consultation.md).

## Shared composition and task requirements

Apply [component standard](12-component-visual-specification.md), [content/mobile task budgets](14-content-and-responsive-task-budgets.md), and [feedback/persistence rules](16-feedback-responsiveness-and-daily-use.md). Reuse the appropriate R1–R5 [reference pattern](11-reference-screen-specifications.md), then verify this page’s primary task through [G0–G5 gates](17-design-acceptance-and-handoff-gates.md). No proposed screen, brand choice or usability result is approved/completed merely because this review exists.


## Data-to-decision and cross-page task contract

Source/saved-evidence review added 2026-10-04; proposed UX only, not new live verification.

| Contract | Page requirement |
| --- | --- |
| Decision / intended outcome | Verify/manage members and plan one bounded group or target validation. |
| Data and interpretation | Member identity/proof/expected behavior/edge observations, LOA, safe settings, schedules and run rules. Separate group authorization from per-target eligibility. |
| Current path / context | Proof ladder/TXT selector, target table, rule choices and scan launch coexist; import dialogs already scoped. |
| Proposed continuation | Keep member selection; own TXT and check plan beside row; staged launch inherits explicit group/target; import preview remains local. |
| Carry automatically | Group/member/challenge, compatible chosen rule, plan/exclusions; optional connector selection. |
| Back / Close restores | Member selection/expanded proof, group list origin and safe import/plan draft. |
| Loading / missing / permission | Empty group, unknown detection, expired TXT, import rejection, current execution gates. |
| Task acceptance | Selecting Verify on a member requires no repeated hostname selection; exact scope stays visible before start. |

Apply [contextual inspector](19-contextual-evidence-inspector.md), [cross-page actions/return-state](20-cross-page-task-flow-contract.md), [data semantics](23-data-meaning-and-workflow-state-contract.md) and [confirmed source links](22-contextual-link-and-source-audit.md). Inspecting never executes; technical record routes remain optional depth. Verify completion using [design acceptance](17-design-acceptance-and-handoff-gates.md), not just route rendering.
