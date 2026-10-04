# Invitation password setup — UX/UI review

Review: 2026-10-03–04. Status: feedback/proposed work only; no implementation is approved by this file.

## User goal

Complete a valid one-time invitation with clear password requirements and recover from expired or already-used tokens.

## Inspected surface and evidence

Route: `/app#set-password`. Observed heading: **Set your account password.**.
Source: `apps/web/react/src/pages/public-pages.tsx: SetPasswordPage`.
Browser evidence: [desktop](evidence/set-password-desktop.png), [route observations](evidence/route-observations.json).

This review used local synthetic fixtures. Missing/stale fixture relationships or dates are explicitly separated from verified UI/source problems. No production provider or live external-probe execution is claimed.

## Proposed hierarchy

Invitation context → password and confirmation → compact live requirements → submit result → sign-in link.

## Prioritized findings

### 1. [P1] Manual invitation token is an implementation-heavy default

**Observed / evidence:** The saved no-token state asks for manual token entry; current source also preloads the invitation token from a link and strips it from the address bar.
**User impact:** Users should not have to understand a security token to activate a valid invitation link.
**Recommendation:** Preserve the existing invitation-link prefill and address-bar stripping, keep token out of persistent history/logging, and show safe account/workspace context only after validation.
**Acceptance check:** Expired/used/invalid token gets the right recovery; token never appears in screenshots or diagnostics.

### 2. [P2] Long password policy text needs actionable feedback

**Observed / evidence:** Requirement is at least 12 characters and three character classes, plus email-name restriction.
**User impact:** A user cannot easily see which requirement is failing.
**Recommendation:** Show compact satisfied/remaining requirements, allow password manager/paste, tie confirm error to its field, and use show/hide accessibly.
**Acceptance check:** No blanket paste blocking; requirement feedback is accurate and screen-reader accessible.

### 3. [P2] Success and failure must preserve the invitation lifecycle

**Observed / evidence:** Setting password activates and closes invitation.
**User impact:** A generic success/retry could encourage reuse or lose useful recovery context.
**Recommendation:** Success states account ready and next sign-in step; retryable server failures retain safe input appropriately, while used-token state clearly ends the flow.
**Acceptance check:** UI never implies an invalid invitation activated an account.

## Actions, dialogs, widgets and states

Inspect Show/Hide password, required-field and confirm validation, invalid invitation state, Back to login. Do not consume a real invitation or activate an account during review.

Keep loading, retained/stale data, unavailable, no data, filtered-empty, disabled-by-role, invalid input, saving, error and success states distinct. Use the shared dialog/keyboard/focus contract; destructive confirmations state the exact affected object.

## Data and functionality prerequisites

One-time invite authorization and backend password policy are authoritative. Security implementation details such as scrypt do not need to occupy the main customer explanation.

## Visual and motion direction

Use the existing theme tokens, restrained orange accents, familiar shared controls and visible 16–24px content insets. Give dense content a clear spacing owner; avoid nested surface borders and unexplained repeated pills. Animate only actual state changes with 90–200ms feedback and 200–300ms surface transitions; do not animate fake work or hide content before a reveal. Follow [motion specification](02-motion-and-interactions.md), including reduced motion and focus preservation.

## Skills for implementation

Use **UI/UX Pro Max**, then **Impeccable shape, clarify, adapt, harden, animate, polish**, plus **interaction-design** for forms, overlays and async feedback. Read [actual skill files and handoff](05-skills-and-handoff.md), [design direction](00-design-direction.md), and [naming](01-naming-and-navigation.md). Live validation pages also require [execution-trace specification](03-live-check-observability.md).

## Page acceptance criteria

Password manager works, field errors associated, token status differentiated, no secret echo, submit busy state stable, expired invitation has real recovery.

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
| Decision / intended outcome | Activate valid invitation with clear token/password handling. |
| Data and interpretation | Transient invitation token/account context where authorized, password requirements and one-time activation outcome. |
| Current path / context | Token query prefilled and stripped already; manual token fallback; password fields and feedback. |
| Proposed continuation | Preserve safe token handling; local requirements/errors and authoritative activation next step. |
| Carry automatically | Transient token in memory only; nonsecret desired auth destination. |
| Back / Close restores | Invalid/expired flow reaches real recovery; no password/token restored from persistent draft. |
| Loading / missing / permission | Used/expired/invalid invite, policy/confirm error, uncertain submission and success. |
| Task acceptance | Valid link does not require retyping token; secret removed from URL and never in saved navigation state. |

Apply [contextual inspector](19-contextual-evidence-inspector.md), [cross-page actions/return-state](20-cross-page-task-flow-contract.md), [data semantics](23-data-meaning-and-workflow-state-contract.md) and [confirmed source links](22-contextual-link-and-source-audit.md). Inspecting never executes; technical record routes remain optional depth. Verify completion using [design acceptance](17-design-acceptance-and-handoff-gates.md), not just route rendering.
