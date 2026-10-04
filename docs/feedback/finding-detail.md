# Finding detail and remediation — UX/UI review

Review: 2026-10-03–04. Status: feedback/proposed work only; no implementation is approved by this file.

## User goal

Understand the gap, see supporting evidence, assign responsibility and decide remediation or accepted risk.

## Inspected surface and evidence

Route: `/app#finding-detail`. Observed heading: **Origin direct bypass · checkout.acme.com**.
Source: `apps/web/react/src/pages/finding-detail-view.tsx`; `apps/web/react/src/pages/detail-pages.tsx`; `apps/web/react/src/lib/finding-detail.ts`.
Browser evidence: [desktop](evidence/finding-detail-desktop.png), [route observations](evidence/route-observations.json).

This review used local synthetic fixtures. Missing/stale fixture relationships or dates are explicitly separated from verified UI/source problems. No production provider or live external-probe execution is claimed.

## Proposed hierarchy

Outcome/severity/affected target → why it matters and evidence → owner/SLA/remediation plan → retest and lifecycle decision; custody export remains available but secondary.

## Prioritized findings

### 1. [P1] Finding explanation can contradict the visible open gap

**Observed / evidence:** The fixture’s Origin direct bypass finding is Open, while “Why this finding?” says protection stopped the test traffic using its linked run.
**User impact:** Users cannot decide whether the gap is real, historic or unresolved.
**Recommendation:** Use the finding’s recorded reason codes and matched evidence, and distinguish subsequent passing runs from the evidence that opened it. Correct contradictory fixtures separately.
**Acceptance check:** A finding explanation never substitutes an unrelated/latest pass for the original gap; newer evidence is clearly labeled.

### 2. [P1] Risk/closure decisions lack a robust review form

**Observed / evidence:** Accept risk confirmation says it records a terminal risk decision; closure is similarly concise.
**User impact:** A security owner needs accountable rationale, evidence and review context.
**Recommendation:** Where supported, require reason/owner and review expiry for accepted risk, closure evidence for resolution, with backend/audit requirements explicitly scoped.
**Acceptance check:** Decision records identify who/why/when and supporting evidence; UI does not invent unsupported lifecycle fields.

### 3. [P2] Evidence exports crowd a long page

**Observed / evidence:** Export evidence, Verify chain, Export bundle and artifact-specific export repeat alongside triage and affected-assets sections.
**User impact:** Primary remediation task competes with several export actions.
**Recommendation:** Consolidate export/integrity actions in one evidence menu/panel; keep one clear triage save and retest action.
**Acceptance check:** A user can assign, plan, retest and inspect evidence without scrolling through repeated export chrome.

## Actions, dialogs, widgets and states

Inspect technical evidence, triage fields, Accept risk/Close confirmations, affected target/run links, remediation empty state, Verify chain and export options. Retest must restate exact target/check and current authorization. Do not submit terminal decisions as part of a review.

Keep loading, retained/stale data, unavailable, no data, filtered-empty, disabled-by-role, invalid input, saving, error and success states distinct. Use the shared dialog/keyboard/focus contract; destructive confirmations state the exact affected object.

## Data and functionality prerequisites

Keep originating finding evidence separate from latest validation state. Risk expiry/reason and retest lineage are backend prerequisites if not already available. Every security-relevant mutation stays audited.

## Visual and motion direction

Use the existing theme tokens, restrained orange accents, familiar shared controls and visible 16–24px content insets. Give dense content a clear spacing owner; avoid nested surface borders and unexplained repeated pills. Animate only actual state changes with 90–200ms feedback and 200–300ms surface transitions; do not animate fake work or hide content before a reveal. Follow [motion specification](02-motion-and-interactions.md), including reduced motion and focus preservation.

## Skills for implementation

Use **UI/UX Pro Max**, then **Impeccable shape, clarify, adapt, harden, animate, polish**, plus **interaction-design** for forms, overlays and async feedback. Read [actual skill files and handoff](05-skills-and-handoff.md), [design direction](00-design-direction.md), and [naming](01-naming-and-navigation.md). Live validation pages also require [execution-trace specification](03-live-check-observability.md).

## Page acceptance criteria

Explanation aligns with original evidence; later pass cannot silently close a finding; triage errors retain notes; accept/close/retest have distinct consequences; no missing playbook is portrayed as completion.

- Test 375/768/1024/1440px, dark/light, 200% text zoom, keyboard, reduced motion and touch targets.
- Validate the exact entity and role with real API behavior; do not synthesize missing provider/evidence/verdict data.
- Compare before/after screenshots and complete the primary workflow, including cancellation and recovery.
- Preserve outside-in-only scope, no default cloud access, and existing execution authorization.
- Update implementation docs/tracker only in a later authorized implementation task; this review does not mark features complete.

## Protection-profile and change context

Show the linked [host profile](06-host-protection-profile.md) and original versus subsequent comparable evidence. A drift finding needs both observations and their scope/version; timeout or stale data alone is not provider loss. Retest follows [per-target remediation semantics](08-drift-concentration-remediation.md), while declared origin claims respect [authorization binding](09-engineering-consultation.md).

## Shared composition and task requirements

Apply [component standard](12-component-visual-specification.md), [content/mobile task budgets](14-content-and-responsive-task-budgets.md), and [feedback/persistence rules](16-feedback-responsiveness-and-daily-use.md). Reuse the appropriate R1–R5 [reference pattern](11-reference-screen-specifications.md), then verify this page’s primary task through [G0–G5 gates](17-design-acceptance-and-handoff-gates.md). No proposed screen, brand choice or usability result is approved/completed merely because this review exists.


## Data-to-decision and cross-page task contract

Source/saved-evidence review added 2026-10-04; proposed UX only, not new live verification.

| Contract | Page requirement |
| --- | --- |
| Decision / intended outcome | Decide remediation/risk using original proof. |
| Data and interpretation | Original gap/reason/evidence, latest validation separately, target/owner/SLA/triage/remediation/retest lineage and integrity. |
| Current path / context | Inline explanation/triage and evidence bundle already present; source-run/artifact links pull away. |
| Proposed continuation | Outcome and supporting evidence co-located, owner/remediation nearby; full artifact optional; retest review retains scope. |
| Carry automatically | Finding/target/check/original evidence, remediation membership, safe notes and latest result separately. |
| Back / Close restores | Queue/member selection and unsaved nonsecret triage; drawer does not discard edits. |
| Loading / missing / permission | Contradictory new pass, evidence fetch error vs no refs, denied triage, partial retest. |
| Task acceptance | Inspect originating proof without leaving finding; retest shows exact scope/current bounds before start. |

Apply [contextual inspector](19-contextual-evidence-inspector.md), [cross-page actions/return-state](20-cross-page-task-flow-contract.md), [data semantics](23-data-meaning-and-workflow-state-contract.md) and [confirmed source links](22-contextual-link-and-source-audit.md). Inspecting never executes; technical record routes remain optional depth. Verify completion using [design acceptance](17-design-acceptance-and-handoff-gates.md), not just route rendering.
