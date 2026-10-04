# Target groups — UX/UI review

Review: 2026-10-03–04. Status: feedback/proposed work only; no implementation is approved by this file.

## User goal

Organize declared targets that share validation settings without making grouping an onboarding prerequisite.

## Inspected surface and evidence

Route: `/app#target-groups`. Observed heading: **Target groups**.
Source: `apps/web/react/src/pages/page-components.tsx: TargetGroupsPage`.
Browser evidence: [desktop](evidence/target-groups-desktop.png), [route observations](evidence/route-observations.json).

This review used local synthetic fixtures. Missing/stale fixture relationships or dates are explicitly separated from verified UI/source problems. No production provider or live external-probe execution is claimed.

## Proposed hierarchy

Concise group list → group name first, targets and critical open findings, ownership scope note, latest evidence time → secondary Create group and Add target actions.

## Prioritized findings

### 1. [P2] Technical IDs lead the list

**Observed / evidence:** The table begins GROUP with tg_checkout before NAME, while business context such as owner/criticality is missing in the fixture.
**User impact:** The list reads like a database browser instead of a service overview.
**Recommendation:** Lead with group name and description, show ID as copyable detail, use explicit Unassigned/Not declared fields, keep values factual.
**Acceptance check:** A user identifies a group by name, sees its purpose and target count, and can distinguish undeclared context from healthy state.

### 2. [P2] Group verdict can be mistaken for all-target coverage

**Observed / evidence:** A PASS appears for the group while several declared targets have no result.
**User impact:** One passing run may be read as every endpoint protected.
**Recommendation:** Show latest check outcome together with tested targets/total and evidence time. Keep group ownership rollup separate from check outcome.
**Acceptance check:** No group badge implies all targets were tested unless the denominator and supporting evidence match.

### 3. [P2] Add target and Create group compete with a targets-first model

**Observed / evidence:** The group page offers both actions and current navigation places groups above targets.
**User impact:** New users may build a group before knowing why they need one.
**Recommendation:** Move Targets above groups; helper copy explains shared settings. Keep Create group minimal with optional advanced details.
**Acceptance check:** Adding an endpoint without a custom group remains a supported first step.

## Actions, dialogs, widgets and states

Create declared target group modal: Name, More options, Cancel/Create. Add target modal: explicit group, kind/value, invalid input and cancellation. Existing groups should open by name/link/keyboard with clear focus. Do not add environment/agent setup to these forms.

Keep loading, retained/stale data, unavailable, no data, filtered-empty, disabled-by-role, invalid input, saving, error and success states distinct. Use the shared dialog/keyboard/focus contract; destructive confirmations state the exact affected object.

## Data and functionality prerequisites

Use active/archived group semantics and current target/runs/finding summaries. Do not invent service owners or replace missing criticality with a default severity.

## Visual and motion direction

Use the existing theme tokens, restrained orange accents, familiar shared controls and visible 16–24px content insets. Give dense content a clear spacing owner; avoid nested surface borders and unexplained repeated pills. Animate only actual state changes with 90–200ms feedback and 200–300ms surface transitions; do not animate fake work or hide content before a reveal. Follow [motion specification](02-motion-and-interactions.md), including reduced motion and focus preservation.

## Skills for implementation

Use **UI/UX Pro Max**, then **Impeccable shape, clarify, adapt, harden, animate, polish**, plus **interaction-design** for forms, overlays and async feedback. Read [actual skill files and handoff](05-skills-and-handoff.md), [design direction](00-design-direction.md), and [naming](01-naming-and-navigation.md). Live validation pages also require [execution-trace specification](03-live-check-observability.md).

## Page acceptance criteria

Create/Add dialogs stay within the viewport; Name errors are inline; missing owner/criticality is honest; group outcomes disclose tested coverage; keyboard row navigation works.

- Test 375/768/1024/1440px, dark/light, 200% text zoom, keyboard, reduced motion and touch targets.
- Validate the exact entity and role with real API behavior; do not synthesize missing provider/evidence/verdict data.
- Compare before/after screenshots and complete the primary workflow, including cancellation and recovery.
- Preserve outside-in-only scope, no default cloud access, and existing execution authorization.
- Update implementation docs/tracker only in a later authorized implementation task; this review does not mark features complete.

## Business scope and concentration addition

Use declared group context and explicitly labeled target inheritance. A group is not automatically one business service. Group detail can summarize provider concentration and important gaps from the [changes/concentration specification](08-drift-concentration-remediation.md), using declared target membership and independent provider roles; never infer a full business dependency graph.

## Shared composition and task requirements

Apply [component standard](12-component-visual-specification.md), [content/mobile task budgets](14-content-and-responsive-task-budgets.md), and [feedback/persistence rules](16-feedback-responsiveness-and-daily-use.md). Reuse the appropriate R1–R5 [reference pattern](11-reference-screen-specifications.md), then verify this page’s primary task through [G0–G5 gates](17-design-acceptance-and-handoff-gates.md). No proposed screen, brand choice or usability result is approved/completed merely because this review exists.


## Data-to-decision and cross-page task contract

Source/saved-evidence review added 2026-10-04; proposed UX only, not new live verification.

| Contract | Page requirement |
| --- | --- |
| Decision / intended outcome | Compare declared groups and inspect member gaps. |
| Data and interpretation | Name/ID, declared criticality/owner when present, membership, proof rollup, runs/findings/latest verdict. Group pass does not establish all-member coverage. |
| Current path / context | Group table → group detail → targets/checks/evidence; IDs can lead names. |
| Proposed continuation | Select group opens member overview; gap count opens scoped member findings; group settings edited in context. |
| Carry automatically | Group ID, member cohort, explicit proof/evidence window and inheritance. |
| Back / Close restores | Group filters/page/selection; member inspector closes within group. |
| Loading / missing / permission | Archived group/missing membership/partial reads explicit; absent business facts not invented. |
| Task acceptance | Group gap count opens exact matching findings, not all tenant findings; member proof independent. |

Apply [contextual inspector](19-contextual-evidence-inspector.md), [cross-page actions/return-state](20-cross-page-task-flow-contract.md), [data semantics](23-data-meaning-and-workflow-state-contract.md) and [confirmed source links](22-contextual-link-and-source-audit.md). Inspecting never executes; technical record routes remain optional depth. Verify completion using [design acceptance](17-design-acceptance-and-handoff-gates.md), not just route rendering.
