# Support — UX/UI review

Review: 2026-10-03–04. Status: feedback/proposed work only; no implementation is approved by this file.

## User goal

Find the real contact/escalation path and supply useful evidence without implying an unconfigured response commitment.

## Inspected surface and evidence

Route: `/app#support`. Observed heading: **Support**.
Source: `apps/web/react/src/pages/page-components.tsx: SupportPage`.
Browser evidence: [desktop](evidence/support-desktop.png), [route observations](evidence/route-observations.json).

This review used local synthetic fixtures. Missing/stale fixture relationships or dates are explicitly separated from verified UI/source problems. No production provider or live external-probe execution is claimed.

## Proposed hierarchy

Configured contact and ownership first → escalation workflow → current case/evidence context → optional account details.

## Prioritized findings

### 1. [P1] Missing support configuration needs an actionable owner

**Observed / evidence:** Inspected deployment has no support contact channel and offers a general message plus workflow links.
**User impact:** A user facing an incident cannot tell whom to contact next.
**Recommendation:** Show configured support owner/contact if available, a deployment-admin fallback if not, and actual response coverage only when recorded.
**Acceptance check:** No fake 24/7 or SLA claim; missing channel includes a concrete configuration/escalation next step.

### 2. [P2] Counts come from subscription context and can diverge from current dashboard

**Observed / evidence:** Fixture support says two open findings while dashboard has one; subscription usage is the source.
**User impact:** Users may believe incidents multiplied between pages.
**Recommendation:** Label snapshot time/source and use a common authoritative current-open definition or explicitly snapshot counts. Confirm fixture consistency separately.
**Acceptance check:** A current count uses the same lifecycle predicate across pages; stale snapshot is visibly qualified.

### 3. [P2] Support workflow links do not package the evidence context

**Observed / evidence:** User can navigate to findings/runs/notifications but lacks a ready investigation summary.
**User impact:** Escalation requires manually collecting several IDs and timestamps.
**Recommendation:** Offer a redacted support summary with exact target/run/finding/evidence references and copy/export feedback where permitted.
**Acceptance check:** Summary never contains credentials or broad customer payloads and points to authorized exact records.

## Actions, dialogs, widgets and states

Inspect configured Contact support, current finding/check/notification links, exact audit View links and the missing-contact state. Support retains target/check/evidence context; no future-release request workflow is assigned. Do not message support during review.

Keep loading, retained/stale data, unavailable, no data, filtered-empty, disabled-by-role, invalid input, saving, error and success states distinct. Use the shared dialog/keyboard/focus contract; destructive confirmations state the exact affected object.

## Data and functionality prerequisites

Contact URI, named coverage and SLA are configuration/evidence, not UI defaults. Source snapshot times must be supplied for confident freshness labels.

## Visual and motion direction

Use the existing theme tokens, restrained orange accents, familiar shared controls and visible 16–24px content insets. Give dense content a clear spacing owner; avoid nested surface borders and unexplained repeated pills. Animate only actual state changes with 90–200ms feedback and 200–300ms surface transitions; do not animate fake work or hide content before a reveal. Follow [motion specification](02-motion-and-interactions.md), including reduced motion and focus preservation.

## Skills for implementation

Use **UI/UX Pro Max**, then **Impeccable shape, clarify, adapt, harden, animate, polish**, plus **interaction-design** for forms, overlays and async feedback. Read [actual skill files and handoff](05-skills-and-handoff.md), [design direction](00-design-direction.md), and [naming](01-naming-and-navigation.md). Live validation pages also require [execution-trace specification](03-live-check-observability.md).

## Page acceptance criteria

Actual support channel and coverage are honest; escalation references are useful; absent configuration does not look healthy; no message is sent as an incidental click.

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
| Decision / intended outcome | Escalate exact investigation or open its related event. |
| Data and interpretation | Configured owner/contact and coverage, subscription-derived counts/as-of, recent event references. Contact not configured is real limitation. |
| Current path / context | Individual View opens the general audit ledger without its event context. |
| Proposed continuation | Current target/check/finding references prefilled in support draft; View resolves its own event. |
| Carry automatically | Safe target/run/finding/event refs, declared scope, nonsecret notes, actual configured channel. |
| Back / Close restores | Same investigation/draft and originating list context. |
| Loading / missing / permission | Unconfigured contact, stale counts, inaccessible event; no auto-message or fabricated SLA. |
| Task acceptance | View opens selected event; escalation retains refs and only sends after explicit authorized action. |

Apply [contextual inspector](19-contextual-evidence-inspector.md), [cross-page actions/return-state](20-cross-page-task-flow-contract.md), [data semantics](23-data-meaning-and-workflow-state-contract.md) and [confirmed source links](22-contextual-link-and-source-audit.md). Inspecting never executes; technical record routes remain optional depth. Verify completion using [design acceptance](17-design-acceptance-and-handoff-gates.md), not just route rendering.
