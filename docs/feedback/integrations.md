# Integrations — UX/UI review

Review: 2026-10-03–04. Status: feedback/proposed work only; no implementation is approved by this file.

## User goal

Choose an optional provider or notification connection, understand access requirements, and know whether it is actually functioning.

## Inspected surface and evidence

Route: `/app#integrations`. Observed heading: **Integrations**.
Source: `apps/web/react/src/pages/integrations-page.tsx`; `apps/web/react/src/components/integrations/notification-channels.tsx`; `apps/web/react/src/lib/provider-setup-guides.ts`.
Browser evidence: [desktop](evidence/integrations-desktop.png), [route observations](evidence/route-observations.json).

This review used local synthetic fixtures. Missing/stale fixture relationships or dates are explicitly separated from verified UI/source problems. No production provider or live external-probe execution is claimed.

## Proposed hierarchy

Providers | Notification channels tabs → connected/incomplete/failed summary → compact searchable provider directory → setup inspector; keep manual ingestion as an advanced workflow.

## Prioritized findings

### 1. [P1] Connection configuration, polling and successful delivery are different states

**Observed / evidence:** Provider cards show configured connectors; notification cards show configured channels, while delivery may be disabled and no attempts recorded.
**User impact:** A user may assume a connected record means provider data was refreshed or alerts sent.
**Recommendation:** Show separate Configured, Credential validated, Last successful sync, Delivery enabled and Last successful delivery where applicable. Use unknown/no attempt distinctly.
**Acceptance check:** A record with no credential/snapshot/delivery evidence is never labeled fully working.

### 2. [P2] Nine provider cards plus channels make one long page

**Observed / evidence:** Directory, configured connectors, four channel cards and lifecycle table all compete for attention.
**User impact:** Users must scroll through unrelated provider and alert configuration tasks.
**Recommendation:** Use tabs or clear section navigation; lead with connected/problem records and keep unconfigured provider directory compact.
**Acceptance check:** A user can find their configured provider or alert failure without scanning every setup card.

### 3. [P2] Provider setup has multiple branching surfaces

**Observed / evidence:** Connect Cloudflare opens a selector for read-only connection, manual metadata, or single domain. Add provider, Add domain, Manual snapshot and individual cards repeat paths.
**User impact:** The distinction between core target declaration and optional credential access is harder to understand.
**Recommendation:** Give each path an explicit task name, explain permissions before asking for a secret, and keep core Add domain in Targets with an optional contextual link.
**Acceptance check:** Choosing a provider never implies access has been granted; manual-only providers cannot offer a live polling action.

## Actions, dialogs, widgets and states

Inspect nine provider setup guides and credential/manual modes; Add provider, Add domain, Manual snapshot, provider validate/snapshot/disable, Slack/Teams/Email/Webhook dialogs and channel edit/remove. Connect dialogs need URL/email validation, inline trigger selection, clear one-time secret handling, retained input on error, and explicit configured-versus-delivering state. Sample payload remains a disclosure. Do not send test alerts or save credentials during review.

Keep loading, retained/stale data, unavailable, no data, filtered-empty, disabled-by-role, invalid input, saving, error and success states distinct. Use the shared dialog/keyboard/focus contract; destructive confirmations state the exact affected object.

## Data and functionality prerequisites

Honor deployment/tenant feature gates and actual backend provider capability. Cloudflare/Akamai EdgeDNS/GoDaddy/Namecheap/NS1/AWS WAF are documented credential paths; GCP/Azure/Hetzner are manual metadata in this current slice. Notification destination preview is redacted; no secret belongs in browser-visible list/feedback.

## Visual and motion direction

Use the existing theme tokens, restrained orange accents, familiar shared controls and visible 16–24px content insets. Give dense content a clear spacing owner; avoid nested surface borders and unexplained repeated pills. Animate only actual state changes with 90–200ms feedback and 200–300ms surface transitions; do not animate fake work or hide content before a reveal. Follow [motion specification](02-motion-and-interactions.md), including reduced motion and focus preservation.

## Skills for implementation

Use **UI/UX Pro Max**, then **Impeccable shape, clarify, adapt, harden, animate, polish**, plus **interaction-design** for forms, overlays and async feedback. Read [actual skill files and handoff](05-skills-and-handoff.md), [design direction](00-design-direction.md), and [naming](01-naming-and-navigation.md). Live validation pages also require [execution-trace specification](03-live-check-observability.md).

## Page acceptance criteria

Configured/synced/delivering are not conflated; guide and selected provider remain aligned; manual mode never polls; modal content/footer fits mobile; redacted destination remains redacted after edit failure; outbound tests require explicit intent.

- Test 375/768/1024/1440px, dark/light, 200% text zoom, keyboard, reduced motion and touch targets.
- Validate the exact entity and role with real API behavior; do not synthesize missing provider/evidence/verdict data.
- Compare before/after screenshots and complete the primary workflow, including cancellation and recovery.
- Preserve outside-in-only scope, no default cloud access, and existing execution authorization.
- Update implementation docs/tracker only in a later authorized implementation task; this review does not mark features complete.

## Optional configuration evidence

Rule counts, blocking/monitoring configuration mode, rule-update timestamps and configuration drift are displayed only from supported, permitted integration evidence. External behavioral checks remain observations and cannot establish configuration. Keep [provider-role provenance](06-host-protection-profile.md) and [engineering permission boundaries](09-engineering-consultation.md) consistent across profile, inventory, rollup and export.

## Shared composition and task requirements

Apply [component standard](12-component-visual-specification.md), [content/mobile task budgets](14-content-and-responsive-task-budgets.md), and [feedback/persistence rules](16-feedback-responsiveness-and-daily-use.md). Reuse the appropriate R1–R5 [reference pattern](11-reference-screen-specifications.md), then verify this page’s primary task through [G0–G5 gates](17-design-acceptance-and-handoff-gates.md). No proposed screen, brand choice or usability result is approved/completed merely because this review exists.


## Data-to-decision and cross-page task contract

Source/saved-evidence review added 2026-10-04; proposed UX only, not new live verification.

| Contract | Page requirement |
| --- | --- |
| Decision / intended outcome | Finish chosen optional provider/channel setup in one flow. |
| Data and interpretation | Implemented provider capability/mode, connector credential reference/validation/snapshot/time, channel config/delivery/opt-in status. Configured not working. |
| Current path / context | Multiple provider entry branches and directory plus channels; setup guides/dialogs already contextual. |
| Proposed continuation | Choose provider/mode once; requirements/configuration/result in same flow; rule-created channel returns to unfinished routing. |
| Carry automatically | Provider/mode/connector/channel IDs, safe nonsecret form state, caller rule. |
| Back / Close restores | Same directory row/provider or rule editor; do not persist secrets. |
| Loading / missing / permission | Manual-only, feature denied, credential invalid, sync failure, no attempt, outbound disabled. |
| Task acceptance | Validation result names same provider/mode; notification destination created in context resumes rule without restart. |

Apply [contextual inspector](19-contextual-evidence-inspector.md), [cross-page actions/return-state](20-cross-page-task-flow-contract.md), [data semantics](23-data-meaning-and-workflow-state-contract.md) and [confirmed source links](22-contextual-link-and-source-audit.md). Inspecting never executes; technical record routes remain optional depth. Verify completion using [design acceptance](17-design-acceptance-and-handoff-gates.md), not just route rendering.
