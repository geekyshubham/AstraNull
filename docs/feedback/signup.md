# Request access — UX/UI review

Review: 2026-10-03–04. Status: feedback/proposed work only; no implementation is approved by this file.

## User goal

Submit enough organizational context for governed account review while explaining what happens next.

## Inspected surface and evidence

Route: `/app#signup`. Observed heading: **Request governed validation access.**.
Source: `apps/web/react/src/pages/public-pages.tsx: SignupPage`.
Browser evidence: [desktop](evidence/signup-desktop.png), [route observations](evidence/route-observations.json).

This review used local synthetic fixtures. Missing/stale fixture relationships or dates are explicitly separated from verified UI/source problems. No production provider or live external-probe execution is claimed.

## Proposed hierarchy

Organization/contact → requested plan/region → intended use → review → request confirmation and saved request ID.

## Prioritized findings

### 1. [P2] “Sign up” versus review-gated request needs consistency

**Observed / evidence:** Page correctly says Request governed validation access and reviewed provisioning.
**User impact:** A user arriving via signup language may expect immediate access.
**Recommendation:** Use Request access consistently in navigation and explain review/provisioning/invitation stages and actual response expectations.
**Acceptance check:** Submitting never implies active account until the recorded lifecycle reaches it.

### 2. [P2] Plan/region choices need context rather than empty defaults

**Observed / evidence:** Form offers requested plan/region choices; deferred program-interest controls are outside this release handoff.
**User impact:** Users may confuse requested plan with granted functionality.
**Recommendation:** Provide compact current-plan/capability and residency help; do not add deferred program intake.
**Acceptance check:** Selected plan is a request, not granted entitlement; no cloud credentials requested.

### 3. [P1] Request ID retention is essential to status lookup

**Observed / evidence:** Manual status lookup needs a request ID; the current confirmation already links to status with the returned ID.
**User impact:** Users who miss the confirmation lose the easiest recovery path.
**Recommendation:** Provide clear confirmation, copy/download reference and configured next-step contact; email only when backend sending is explicitly enabled.
**Acceptance check:** Request ID can be recovered/copy-acknowledged without exposing sensitive contact details or pretending an email was sent.

## Actions, dialogs, widgets and states

Inspect plan/region options, intended-use input, checkbox and field validation without submitting external intake. Confirmation/error/rejected states need fixture-backed QA. Preserve input on transient failure and focus the first invalid field.

Keep loading, retained/stale data, unavailable, no data, filtered-empty, disabled-by-role, invalid input, saving, error and success states distinct. Use the shared dialog/keyboard/focus contract; destructive confirmations state the exact affected object.

## Data and functionality prerequisites

Public intake and state tracking are review-gated. Do not silently provision tenants or send messages. Return recorded request reference and next state only.

## Visual and motion direction

Use the existing theme tokens, restrained orange accents, familiar shared controls and visible 16–24px content insets. Give dense content a clear spacing owner; avoid nested surface borders and unexplained repeated pills. Animate only actual state changes with 90–200ms feedback and 200–300ms surface transitions; do not animate fake work or hide content before a reveal. Follow [motion specification](02-motion-and-interactions.md), including reduced motion and focus preservation.

## Skills for implementation

Use **UI/UX Pro Max**, then **Impeccable shape, clarify, adapt, harden, animate, polish**, plus **interaction-design** for forms, overlays and async feedback. Read [actual skill files and handoff](05-skills-and-handoff.md), [design direction](00-design-direction.md), and [naming](01-naming-and-navigation.md). Live validation pages also require [execution-trace specification](03-live-check-observability.md).

## Page acceptance criteria

Labels match request semantics, validation is inline, submission is duplicate-safe, ID is clearly retained, next step is honest, and requested access remains a reviewed account request.

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
| Decision / intended outcome | Request reviewed access and keep returned reference. |
| Data and interpretation | Organization/contact/plan/region/use and review state, returned request ID. Requested plan not entitlement. |
| Current path / context | Current confirmation already links status with ID; form can hydrate submitted reference. |
| Proposed continuation | Preserve ID-prefilled confirmation/status, clearer real next stage/recovery; only request missing fields. |
| Carry automatically | Nonsecret request ID and safe submitted summary; no invented activation/invite. |
| Back / Close restores | Back to submitted confirmation or intended sign-in; no duplicate intake from retry. |
| Loading / missing / permission | Intake disabled, validation/read error, rate limit, submitted not active. |
| Task acceptance | Check status from confirmation never requires typing ID again; submission not portrayed as active account. |

Apply [contextual inspector](19-contextual-evidence-inspector.md), [cross-page actions/return-state](20-cross-page-task-flow-contract.md), [data semantics](23-data-meaning-and-workflow-state-contract.md) and [confirmed source links](22-contextual-link-and-source-audit.md). Inspecting never executes; technical record routes remain optional depth. Verify completion using [design acceptance](17-design-acceptance-and-handoff-gates.md), not just route rendering.
