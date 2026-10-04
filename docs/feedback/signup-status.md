# Access request status — UX/UI review

Review: 2026-10-03–04. Status: feedback/proposed work only; no implementation is approved by this file.

## User goal

Find the recorded review/provisioning status and know what action, if any, is required.

## Inspected surface and evidence

Route: `/app#signup-status`. Observed heading: **Track an access request.**.
Source: `apps/web/react/src/pages/public-pages.tsx: SignupStatusPage`.
Browser evidence: [desktop](evidence/signup-status-desktop.png), [route observations](evidence/route-observations.json).

This review used local synthetic fixtures. Missing/stale fixture relationships or dates are explicitly separated from verified UI/source problems. No production provider or live external-probe execution is claimed.

## Proposed hierarchy

Request ID lookup → readable lifecycle timeline → specific current status/next action → configured recovery channel.

## Prioritized findings

### 1. [P2] Manual case-sensitive ID is a fragile lookup path

**Observed / evidence:** The manual fallback asks for a case-sensitive request ID; current source already reads/trims a supplied query ID and auto-loads status. Recovery for a lost reference still relies on configured contact.
**User impact:** Copy mistakes and lost references can prevent users from checking progress.
**Recommendation:** Preserve existing confirmation deep links, query prefill and whitespace trimming; improve copyable request reference and explain casing without exposing request details to unauthorized parties.
**Acceptance check:** Invalid ID and service error remain different; no enumeration-friendly response leaks personal data.

### 2. [P2] Backend state names need a human journey

**Observed / evidence:** Submitted/approved/provisioned/invited/active are different steps.
**User impact:** Users may assume Approved means they can log in.
**Recommendation:** Show Received → Under review → Provisioning → Invitation sent → Account ready, derived only from recorded state.
**Acceptance check:** Every status explains whether login is possible and what happens next without fabricated completion dates.

### 3. [P2] Recovery is underspecified when no support contact exists

**Observed / evidence:** Fallback asks for deployment administrator/channel from onboarding.
**User impact:** A new prospect may not have that context yet.
**Recommendation:** Render configured public contact or explicit access-request recovery instructions; do not invent a staffed inbox.
**Acceptance check:** Missing-contact state is truthful and does not link to an unavailable route.

## Actions, dialogs, widgets and states

Inspect lookup field, validation, Log in and no-ID/invalid-ID/loading states. Status retrieval is public but must preserve privacy. Do not repeatedly query guessed production request IDs.

Keep loading, retained/stale data, unavailable, no data, filtered-empty, disabled-by-role, invalid input, saving, error and success states distinct. Use the shared dialog/keyboard/focus contract; destructive confirmations state the exact affected object.

## Data and functionality prerequisites

Use public request state and approved display fields. Any new emailed status link needs explicit delivery support and appropriate anti-enumeration controls.

## Visual and motion direction

Use the existing theme tokens, restrained orange accents, familiar shared controls and visible 16–24px content insets. Give dense content a clear spacing owner; avoid nested surface borders and unexplained repeated pills. Animate only actual state changes with 90–200ms feedback and 200–300ms surface transitions; do not animate fake work or hide content before a reveal. Follow [motion specification](02-motion-and-interactions.md), including reduced motion and focus preservation.

## Skills for implementation

Use **UI/UX Pro Max**, then **Impeccable shape, clarify, adapt, harden, animate, polish**, plus **interaction-design** for forms, overlays and async feedback. Read [actual skill files and handoff](05-skills-and-handoff.md), [design direction](00-design-direction.md), and [naming](01-naming-and-navigation.md). Live validation pages also require [execution-trace specification](03-live-check-observability.md).

## Page acceptance criteria

Timeline maps actual state, case/whitespace help clear, service failure preserves ID, reference privacy maintained, no progress percentage/ETA invented.

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
| Decision / intended outcome | Know recorded stage and next permitted step. |
| Data and interpretation | Request ID/review/provisioning/invitation status and safe public fields. Stage/date only when returned. |
| Current path / context | Query-ID trim and automatic lookup already supported; manual field fallback. |
| Proposed continuation | Keep reference continuity; readable lifecycle/next action and configured lost-reference recovery. |
| Carry automatically | Request ID nonsecret within allowed privacy; status source time. |
| Back / Close restores | Same request after login/back or retry; no secret token persistence. |
| Loading / missing / permission | Not found versus failed lookup/rate limited; status privacy and no invented ETA. |
| Task acceptance | Existing ID link loads correct request; approved/provisioned/invited/active meanings distinguished. |

Apply [contextual inspector](19-contextual-evidence-inspector.md), [cross-page actions/return-state](20-cross-page-task-flow-contract.md), [data semantics](23-data-meaning-and-workflow-state-contract.md) and [confirmed source links](22-contextual-link-and-source-audit.md). Inspecting never executes; technical record routes remain optional depth. Verify completion using [design acceptance](17-design-acceptance-and-handoff-gates.md), not just route rendering.
