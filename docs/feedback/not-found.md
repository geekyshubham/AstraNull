# Missing or unavailable route — UX/UI review

Review: 2026-10-03–04. Status: feedback/proposed work only; no implementation is approved by this file.

## User goal

Recover from a broken bookmark, removed surface, permission denial or missing entity without concealing what happened.

## Inspected surface and evidence

Route: `http://127.0.0.1:5173/app?ux_review=7#not-a-route`. Observed heading: **Portal route not found.**.
Source: `apps/web/react/src/pages/router.tsx`; `apps/web/react/src/lib/navigation.ts`; `apps/web/react/src/lib/route-access.ts`.
Browser evidence: [desktop](evidence/not-found-desktop.png), [route observations](evidence/route-observations.json).

This review used local synthetic fixtures. Missing/stale fixture relationships or dates are explicitly separated from verified UI/source problems. No production provider or live external-probe execution is claimed.

## Proposed hierarchy

Clear missing/unavailable explanation → safe return to current authorized home → optional related real route.

## Prioritized findings

### 1. [P2] Error copy exposes implementation internals

**Observed / evidence:** Current message discusses removed aliases and React portal paths.
**User impact:** Users need a recovery action, not routing architecture.
**Recommendation:** Use “This page is unavailable” and short context; retain diagnostics in technical detail.
**Acceptance check:** User can reach the authorized home in one action and no hidden route is fabricated.

### 2. [P1] Permission fallback and not-found must remain distinct

**Observed / evidence:** Role-gated route rejection can send a user to a fallback home with a temporary notice.
**User impact:** Users can think a requested page opened when it actually did not.
**Recommendation:** Show persistent contextual explanation for denied route, preserve intended destination for authorized recovery, and avoid inferred entity facts.
**Acceptance check:** A denied route never renders unauthorized datasets; a missing entity never displays default healthy values.

### 3. [P2] Return links need audit against removed pages

**Observed / evidence:** Evidence detail points to a vault concept with no current sidebar list route.
**User impact:** Back links can create loops or dead ends.
**Recommendation:** Use verified route builders and originating context, test every return link after ADR removals.
**Acceptance check:** No agent/environment/removed vault alias silently becomes dashboard without explanation.

## Actions, dialogs, widgets and states

Unknown hash was tested with a customer admin and returned the explicit missing-route state. Customer role-denial and missing entity are distinct states. Treat auth/config errors independently from 404.

Keep loading, retained/stale data, unavailable, no data, filtered-empty, disabled-by-role, invalid input, saving, error and success states distinct. Use the shared dialog/keyboard/focus contract; destructive confirmations state the exact affected object.

## Data and functionality prerequisites

Current route map is authoritative; removed agent/environment aliases stay removed. Role gating and tenant isolation happen before data presentation.

## Visual and motion direction

Use the existing theme tokens, restrained orange accents, familiar shared controls and visible 16–24px content insets. Give dense content a clear spacing owner; avoid nested surface borders and unexplained repeated pills. Animate only actual state changes with 90–200ms feedback and 200–300ms surface transitions; do not animate fake work or hide content before a reveal. Follow [motion specification](02-motion-and-interactions.md), including reduced motion and focus preservation.

## Skills for implementation

Use **UI/UX Pro Max**, then **Impeccable shape, clarify, adapt, harden, animate, polish**, plus **interaction-design** for forms, overlays and async feedback. Read [actual skill files and handoff](05-skills-and-handoff.md), [design direction](00-design-direction.md), and [naming](01-naming-and-navigation.md). Live validation pages also require [execution-trace specification](03-live-check-observability.md).

## Page acceptance criteria

Unknown hash, denied role, expired auth and missing record are different; safe recovery remains keyboard reachable and no technical internal is the only explanation.

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
| Decision / intended outcome | Recover without concealing the requested context. |
| Data and interpretation | Unknown route/entity, denied access and expired auth are different; no record inference. |
| Current path / context | Unknown hash explicit state; some role gates redirect with notice. |
| Proposed continuation | Explain reason; offer authorized caller/list/entity parent and retain safe intent where useful. |
| Carry automatically | Safe requested route/entity/return ref; no secret URLs. |
| Back / Close restores | Original authorized filter/list if possible, canonical home on cold unknown link. |
| Loading / missing / permission | 404/403/auth/network differentiated; stale/deleted row fallback. |
| Task acceptance | Recovery does not silently show healthy/default entity or erase all investigation context. |

Apply [contextual inspector](19-contextual-evidence-inspector.md), [cross-page actions/return-state](20-cross-page-task-flow-contract.md), [data semantics](23-data-meaning-and-workflow-state-contract.md) and [confirmed source links](22-contextual-link-and-source-audit.md). Inspecting never executes; technical record routes remain optional depth. Verify completion using [design acceptance](17-design-acceptance-and-handoff-gates.md), not just route rendering.
