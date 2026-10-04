# Plan & usage / Billing — UX/UI review

Review: 2026-10-03–04. Status: feedback/proposed work only; no implementation is approved by this file.

## User goal

Understand recorded plan limits, effective feature access and remaining capacity without guessing billing functionality.

## Inspected surface and evidence

Route: `/app#subscription`. Observed heading: **Billing**.
Source: `apps/web/react/src/pages/page-components.tsx: SubscriptionPage`.
Browser evidence: [desktop](evidence/subscription-desktop.png), [route observations](evidence/route-observations.json).

This review used local synthetic fixtures. Missing/stale fixture relationships or dates are explicitly separated from verified UI/source problems. No production provider or live external-probe execution is claimed.

## Proposed hierarchy

Current plan/effective dates → usage with units/windows → effective entitlements and access source → actual commercial/support contact.

## Prioritized findings

### 1. [P2] Billing suggests transactions not present on the screen

**Observed / evidence:** Observed page shows plan/contract/entitlement/usage metadata rather than invoices/payment methods.
**User impact:** Users can expect billing actions that are unavailable.
**Recommendation:** Call it Plan & usage unless real billing flows are added; label contract fields and renewal absence clearly.
**Acceptance check:** Navigation title describes current capability and does not add fake pay/upgrade buttons.

### 2. [P1] Unknown usage needs to remain unknown

**Observed / evidence:** Some usage metrics are unavailable while other current direct-check limits are measured; deferred program metrics are not part of this handoff.
**User impact:** A user may assume zero use or unlimited quota.
**Recommendation:** Retain No measure/Not recorded, show authoritative windows/units for each measured quota and last source timestamp.
**Acceptance check:** Unknown never renders as 0%, zero count or unlimited entitlement.

### 3. [P2] Entitlement table is correct but internally worded

**Observed / evidence:** Plan inclusion, effective access authoritative and access source appear as raw decision columns.
**User impact:** Users need whether they can use a feature and why, with a practical action for disabled access.
**Recommendation:** Lead with Available/Unavailable and reason, with decision provenance expandable; describe optional add-ons in user language.
**Acceptance check:** Feature enablement does not imply configured provider credentials or functioning validation.

## Actions, dialogs, widgets and states

Inspect Refresh and entitlement/usage descriptions. Show plan loading/error/stale cases, exceeded limit, unavailable usage and disabled feature. Upgrade/contact actions require actual configured destinations and authorization.

Keep loading, retained/stale data, unavailable, no data, filtered-empty, disabled-by-role, invalid input, saving, error and success states distinct. Use the shared dialog/keyboard/focus contract; destructive confirmations state the exact affected object.

## Data and functionality prerequisites

Use subscription/current authoritative limits and grants; never derive rate allowance from the remaining chart alone. Distinguish count snapshot, observation window and portal load time.

## Visual and motion direction

Use the existing theme tokens, restrained orange accents, familiar shared controls and visible 16–24px content insets. Give dense content a clear spacing owner; avoid nested surface borders and unexplained repeated pills. Animate only actual state changes with 90–200ms feedback and 200–300ms surface transitions; do not animate fake work or hide content before a reveal. Follow [motion specification](02-motion-and-interactions.md), including reduced motion and focus preservation.

## Skills for implementation

Use **UI/UX Pro Max**, then **Impeccable shape, clarify, adapt, harden, animate, polish**, plus **interaction-design** for forms, overlays and async feedback. Read [actual skill files and handoff](05-skills-and-handoff.md), [design direction](00-design-direction.md), and [naming](01-naming-and-navigation.md). Live validation pages also require [execution-trace specification](03-live-check-observability.md).

## Page acceptance criteria

Window/units/denominator are explicit; available feature and configured integration are separate; stale/missing data remains qualified; quota bar stays keyboard-readable and reduced-motion safe.

- Test 375/768/1024/1440px, dark/light, 200% text zoom, keyboard, reduced motion and touch targets.
- Validate the exact entity and role with real API behavior; do not synthesize missing provider/evidence/verdict data.
- Compare before/after screenshots and complete the primary workflow, including cancellation and recovery.
- Preserve outside-in-only scope, no default cloud access, and existing execution authorization.
- Update implementation docs/tracker only in a later authorized implementation task; this review does not mark features complete.

## Core observations and optional analytics

Core authorized outside-in observations do not imply entitlement or credentials for optional WAF configuration analytics. Clearly distinguish unavailable/disabled optional data from zero or not-detected protection. [Engineering review](09-engineering-consultation.md) requires field/aggregate/export permission decisions before profile exposure.

## Shared composition and task requirements

Apply [component standard](12-component-visual-specification.md), [content/mobile task budgets](14-content-and-responsive-task-budgets.md), and [feedback/persistence rules](16-feedback-responsiveness-and-daily-use.md). Reuse the appropriate R1–R5 [reference pattern](11-reference-screen-specifications.md), then verify this page’s primary task through [G0–G5 gates](17-design-acceptance-and-handoff-gates.md). No proposed screen, brand choice or usability result is approved/completed merely because this review exists.


## Data-to-decision and cross-page task contract

Source/saved-evidence review added 2026-10-04; proposed UX only, not new live verification.

| Contract | Page requirement |
| --- | --- |
| Decision / intended outcome | Understand current plan limit/access and permitted next step. |
| Data and interpretation | Plan/contract/effective dates, usage window/count/limit, entitlement source; unknown usage not 0/unlimited. |
| Current path / context | Read-only plan/usage and grant source; no payment workflow. |
| Proposed continuation | Inspect metric/entitlement explanation in context; configured plan/support destination with account refs. |
| Carry automatically | Tenant/plan/feature/usage window/as-of; caller account task. |
| Back / Close restores | Same plan section; external contact only intentionally. |
| Loading / missing / permission | Usage unavailable/exceeded, add-on disabled vs no observation, renewal unknown. |
| Task acceptance | User explains actual remaining/unknown usage and feature availability without mistaking it for configured protection. |

Apply [contextual inspector](19-contextual-evidence-inspector.md), [cross-page actions/return-state](20-cross-page-task-flow-contract.md), [data semantics](23-data-meaning-and-workflow-state-contract.md) and [confirmed source links](22-contextual-link-and-source-audit.md). Inspecting never executes; technical record routes remain optional depth. Verify completion using [design acceptance](17-design-acceptance-and-handoff-gates.md), not just route rendering.
