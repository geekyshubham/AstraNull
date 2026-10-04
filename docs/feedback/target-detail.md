# Target detail — UX/UI review

Review: 2026-10-03–04. Status: feedback/proposed work only; no implementation is approved by this file.

## User goal

Explain one endpoint’s protections and findings, then show each check’s recorded execution and outcome.

## Inspected surface and evidence

Route: `/app#target-detail`. Observed heading: **checkout.acme.com**.
Source: `apps/web/react/src/pages/target-detail-view.tsx`; `apps/web/react/src/components/targets/domain-protection.tsx`; `apps/web/react/src/lib/domain-checks.mjs`.
Browser evidence: [desktop](evidence/target-detail-desktop.png), [route observations](evidence/route-observations.json).

This review used local synthetic fixtures. Missing/stale fixture relationships or dates are explicitly separated from verified UI/source problems. No production provider or live external-probe execution is claimed.

## Proposed hierarchy

Endpoint header with ownership and next action → edge detection versus efficacy summary → concise next-step flow → check queue with selected-check inspector → Findings/History/Evidence tabs.

## Prioritized findings

### 1. [P1] Two validation workflows compete

**Observed / evidence:** The page has Edge protection, All checks (149), a four-step Validate this target workflow, and lower Protection path/WAF-CDN/Recent runs/Findings tabs.
**User impact:** Users see multiple ways to start/check the same target and cannot tell which area is authoritative.
**Recommendation:** Unify ownership, check selection, launch, and live status into one target workspace. Place detected providers and efficacy in a compact summary; deep signals remain expandable.
**Acceptance check:** A first-time user can verify, launch and inspect results using one consistent sequence; run actions do not appear as unrelated duplicates.

### 2. [P1] Current per-check summaries are short of requested terminal visibility

**Observed / evidence:** Check rows can explain work and metadata, but the inspected endpoint lacks a recorded live request/response/evaluation trace.
**User impact:** Users cannot confidently follow what ran and how a result was evaluated.
**Recommendation:** Adopt the live-observability specification with protocol-aware Request/Response/Evaluation/Evidence panels and actual event timestamps.
**Acceptance check:** Equivalent curl is labeled as reconstructed; missing data stays missing; a result links to exact-target signed evidence.

### 3. [P2] Premium/Classic and dense counters create cognitive load

**Observed / evidence:** A design switch sits above ownership/detection/check count/run count/finding count/verdict, with long category lists.
**User impact:** Presentation choices distract from the endpoint’s next action and may sound like entitlements.
**Recommendation:** Choose one presentation, use three or four essential facts, and show check categories as a navigable queue with status counts. Put IDs/expected baseline in detail.
**Acceptance check:** No customer needs to choose a design variant; no unknown detection appears green or universally protected.

## Actions, dialogs, widgets and states

Inspect Protection path, WAF/CDN edge, Recent runs and Findings tabs; category disclosures, protected/not-run filters, technical evidence, tags, and Run all checks confirmation. Run all should explain selected check count, total request upper bound, exclusions, pause/defer gates and sequential behavior. Do not run live external probes during a UX review.

Keep loading, retained/stale data, unavailable, no data, filtered-empty, disabled-by-role, invalid input, saving, error and success states distinct. Use the shared dialog/keyboard/focus contract; destructive confirmations state the exact affected object.

## Data and functionality prerequisites

Use GET /v1/targets/:id, its challenge and edge detection, compatible check catalog, linked scans/runs/findings. Efficacy must use check evidence, not fingerprint presence. Preserve DNS ownership and external-only confidence.

## Visual and motion direction

Use the existing theme tokens, restrained orange accents, familiar shared controls and visible 16–24px content insets. Give dense content a clear spacing owner; avoid nested surface borders and unexplained repeated pills. Animate only actual state changes with 90–200ms feedback and 200–300ms surface transitions; do not animate fake work or hide content before a reveal. Follow [motion specification](02-motion-and-interactions.md), including reduced motion and focus preservation.

## Skills for implementation

Use **UI/UX Pro Max**, then **Impeccable shape, clarify, adapt, harden, animate, polish**, plus **interaction-design** for forms, overlays and async feedback. Read [actual skill files and handoff](05-skills-and-handoff.md), [design direction](00-design-direction.md), and [naming](01-naming-and-navigation.md). Live validation pages also require [execution-trace specification](03-live-check-observability.md).

## Page acceptance criteria

Ownership proof, detected provider, observed blocking, origin exposure, and stale/no evidence remain distinct; selection survives polling; 149 checks are navigable without an enormous expanded page; live output follows the shared spec.

- Test 375/768/1024/1440px, dark/light, 200% text zoom, keyboard, reduced motion and touch targets.
- Validate the exact entity and role with real API behavior; do not synthesize missing provider/evidence/verdict data.
- Compare before/after screenshots and complete the primary workflow, including cancellation and recovery.
- Preserve outside-in-only scope, no default cloud access, and existing execution authorization.
- Update implementation docs/tracker only in a later authorized implementation task; this review does not mark features complete.

## Host protection profile addition

[Host profile](06-host-protection-profile.md) becomes the canonical design: separate WAF/CDN/hosting attribution, declared purpose/owner/criticality, an accessible family-specific evidence inspector, six readiness dimensions, priority remediation, and Changes & history. Reorganize competing protection/check workflows instead of stacking another card. [Engineering findings](09-engineering-consultation.md) identify inferred vendor/header/Anycast/source statements and unsafe absence defaults that must not be reused as evidence.

## Shared visual/task handoff

Use [reference specifications](11-reference-screen-specifications.md), [component standard](12-component-visual-specification.md), [responsive budgets](14-content-and-responsive-task-budgets.md) and [feedback/navigation](16-feedback-responsiveness-and-daily-use.md). Page focus: R2/R5; J1/J4; T2 unknown, T4 evidence and T6 context continuity. See [acceptance gate](17-design-acceptance-and-handoff-gates.md). All references remain proposed until rendered and explicitly approved; user task results are Not run.


## Data-to-decision and cross-page task contract

Source/saved-evidence review added 2026-10-04; proposed UX only, not new live verification.

| Contract | Page requirement |
| --- | --- |
| Decision / intended outcome | Understand protection and investigate a result without object hopping. |
| Data and interpretation | Exact target, proof/tags, WAF/CDN/cloud source, efficacy/check status, recent runs/findings and declaration facts. Independent family sources and untested dimensions. |
| Current path / context | Competing protection/steps/checks/tabs; Open evidence goes to an internal result-record detail page. |
| Proposed continuation | One target workspace with summary/priority and selected-check evidence beside outcome; Run review preselects exact target. |
| Carry automatically | Target/check/run/observation/artifact references and original-versus-latest finding context. |
| Back / Close restores | Same tab/check/category/expanded detail/scroll; no switch to newest result. |
| Loading / missing / permission | Ownership pending, source error, unknown/stale, not applicable, open finding after later pass. |
| Task acceptance | Open evidence reveals recorded operation/response/evaluation in one action; full run route optional. |

Apply [contextual inspector](19-contextual-evidence-inspector.md), [cross-page actions/return-state](20-cross-page-task-flow-contract.md), [data semantics](23-data-meaning-and-workflow-state-contract.md) and [confirmed source links](22-contextual-link-and-source-audit.md). Inspecting never executes; technical record routes remain optional depth. Verify completion using [design acceptance](17-design-acceptance-and-handoff-gates.md), not just route rendering.
