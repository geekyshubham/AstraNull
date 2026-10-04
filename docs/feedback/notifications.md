# Notifications — UX/UI review

Review: 2026-10-03–04. Status: feedback/proposed work only; no implementation is approved by this file.

## User goal

Understand which events notify which channels, then recover failed delivery deliberately.

## Inspected surface and evidence

Route: `/app#notifications`. Observed heading: **Notifications**.
Source: `apps/web/react/src/pages/governance-pages.tsx: NotificationsPage`.
Browser evidence: [desktop](evidence/notifications-desktop.png), [route observations](evidence/route-observations.json).

This review used local synthetic fixtures. Missing/stale fixture relationships or dates are explicitly separated from verified UI/source problems. No production provider or live external-probe execution is claimed.

## Proposed hierarchy

Rules and recent delivery outcomes → event/delivery list with inspectable failure reason → advanced retry/recovery tools.

## Prioritized findings

### 1. [P1] Channels and rules are managed in two places

**Observed / evidence:** Integrations has channel add/edit/remove/enable controls; Notifications has New rule, Rules, Recent events, Providers and delivery operations.
**User impact:** Users cannot predict where to edit routing versus recover delivery.
**Recommendation:** Explain channels as destinations and rules as routing; cross-link to the relevant channel/settings. Use a rule detail view that exposes channel, triggers, enabled state and last attempt.
**Acceptance check:** The same rule has consistent state/trigger/destination across both pages; no apparent duplicate creation flow.

### 2. [P2] DLQ jargon and broad recovery buttons lead with implementation

**Observed / evidence:** Dashboard tiles say DLQ/critical; operations offer preview/process due retries and redrive.
**User impact:** A support operator lacks the plain reason, affected channel, and specific next step.
**Recommendation:** Label Failed deliveries with expandable retry policy; preview affected attempts/counts and separate Retry from reconfigure channel.
**Acceptance check:** No retry sends implicitly from an ambiguous generic button; batch recovery states destination, number and duplicate-delivery risk.

### 3. [P2] New rule form needs clear spatial focus

**Observed / evidence:** New rule expands an inline form, not a modal; header changes to Close rule form while metrics remain visible.
**User impact:** Users may miss where the action opened or lose form data on navigating away.
**Recommendation:** Scroll/focus the form heading deliberately, keep cancel and field errors local, and preserve values on API errors.
**Acceptance check:** Keyboard focus reaches the expanded form, close is clear, no success is shown before authoritative save.

## Actions, dialogs, widgets and states

Inspect New rule/Close, channel/trigger inputs, preview due retries, preview DLQ redrive, Process due retries and Redrive confirmation. Preview is metadata-only; live recovery can send external notifications, so only inspect confirmation during review. Use sample failures to verify meaningful recovery advice.

Keep loading, retained/stale data, unavailable, no data, filtered-empty, disabled-by-role, invalid input, saving, error and success states distinct. Use the shared dialog/keyboard/focus contract; destructive confirmations state the exact affected object.

## Data and functionality prerequisites

Event created is not notification delivered. Destination config, delivery ledger/provider enablement and retry lifecycle must remain separate. Do not create real external notifications as UX evidence.

## Visual and motion direction

Use the existing theme tokens, restrained orange accents, familiar shared controls and visible 16–24px content insets. Give dense content a clear spacing owner; avoid nested surface borders and unexplained repeated pills. Animate only actual state changes with 90–200ms feedback and 200–300ms surface transitions; do not animate fake work or hide content before a reveal. Follow [motion specification](02-motion-and-interactions.md), including reduced motion and focus preservation.

## Skills for implementation

Use **UI/UX Pro Max**, then **Impeccable shape, clarify, adapt, harden, animate, polish**, plus **interaction-design** for forms, overlays and async feedback. Read [actual skill files and handoff](05-skills-and-handoff.md), [design direction](00-design-direction.md), and [naming](01-naming-and-navigation.md). Live validation pages also require [execution-trace specification](03-live-check-observability.md).

## Page acceptance criteria

Rule and channel state reconcile; no-attempt differs from failed; preview explains exact affected set; errors point to channel/rule configuration; redaction persists.

- Test 375/768/1024/1440px, dark/light, 200% text zoom, keyboard, reduced motion and touch targets.
- Validate the exact entity and role with real API behavior; do not synthesize missing provider/evidence/verdict data.
- Compare before/after screenshots and complete the primary workflow, including cancellation and recovery.
- Preserve outside-in-only scope, no default cloud access, and existing execution authorization.
- Update implementation docs/tracker only in a later authorized implementation task; this review does not mark features complete.

## Protection-change notifications

Potential drift/remediation/maintenance triggers follow [confirmed-change semantics](08-drift-concentration-remediation.md). Include exact target, observed change, source time and evidence link, with redacted summaries and opt-in routing. Stale data, failed polling and a timeout are different from confirmed protection loss. No message sending was authorized by this documentation addition.

## Shared composition and task requirements

Apply [component standard](12-component-visual-specification.md), [content/mobile task budgets](14-content-and-responsive-task-budgets.md), and [feedback/persistence rules](16-feedback-responsiveness-and-daily-use.md). Reuse the appropriate R1–R5 [reference pattern](11-reference-screen-specifications.md), then verify this page’s primary task through [G0–G5 gates](17-design-acceptance-and-handoff-gates.md). No proposed screen, brand choice or usability result is approved/completed merely because this review exists.


## Data-to-decision and cross-page task contract

Source/saved-evidence review added 2026-10-04; proposed UX only, not new live verification.

| Contract | Page requirement |
| --- | --- |
| Decision / intended outcome | Understand a delivery failure and correct its own routing. |
| Data and interpretation | Rules/triggers/destination preview, event vs attempt, provider health/retry/DLQ, config versus sent state. |
| Current path / context | Rules here, channels elsewhere; inline New rule; preview/live batch controls. |
| Proposed continuation | Rule editor can inspect/select channel in place; failure opens exact attempt and relevant channel/config with resume. |
| Carry automatically | Rule/channel/event/attempt IDs, triggers, safe draft and affected retry scope. |
| Back / Close restores | Same failure/rule filter and draft; Cancel makes no delivery. |
| Loading / missing / permission | No attempt vs disabled vs failure, retry uncertainty, permission/config gates. |
| Task acceptance | Failed delivery activation shows reason and exact destination config; explicit retry does not duplicate unknown outcome. |

Apply [contextual inspector](19-contextual-evidence-inspector.md), [cross-page actions/return-state](20-cross-page-task-flow-contract.md), [data semantics](23-data-meaning-and-workflow-state-contract.md) and [confirmed source links](22-contextual-link-and-source-audit.md). Inspecting never executes; technical record routes remain optional depth. Verify completion using [design acceptance](17-design-acceptance-and-handoff-gates.md), not just route rendering.
