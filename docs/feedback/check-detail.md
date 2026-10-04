# Check detail — UX/UI review

Review: 2026-10-03–04. Status: feedback/proposed work only; no implementation is approved by this file.

## User goal

Explain one bounded check, its requirements, safety limits, evaluation logic, and recent exact-check evidence.

## Inspected surface and evidence

Route: `http://127.0.0.1:5173/app?ux_review=6#check-detail?id=origin.leak_scan.safe`. Observed heading: **Origin Leak Scan (Safe)**.
Source: `apps/web/react/src/pages/detail-pages.tsx: CheckDetailPage`.
Browser evidence: [desktop](evidence/check-detail-desktop.png), [route observations](evidence/route-observations.json).

This review used local synthetic fixtures. Missing/stale fixture relationships or dates are explicitly separated from verified UI/source problems. No production provider or live external-probe execution is claimed.

## Proposed hierarchy

Plain-language purpose and scope → How it works | Requirements | Evidence limits → compatible target selection → schedule/run action; taxonomy IDs under Technical details.

## Prioritized findings

### 1. [P2] Technical taxonomy takes priority over practical fit

**Observed / evidence:** Page displays ATT/resource/pattern/WV/ND identifiers, metadata categories and raw check IDs around requirements.
**User impact:** An engineer must decode catalog internals to know whether they can run the check.
**Recommendation:** Start with a three-part explanation: what is sent, observed signal, evaluation rule; show compatible target kinds and setup next; move taxonomy IDs to disclosure.
**Acceptance check:** Purpose/requirements and permitted action are clear before IDs; no check is described as supporting a target kind outside the catalog.

### 2. [P2] Generic remediation adds little guidance

**Observed / evidence:** Inspected Origin Leak Scan remediation says review evidence and declared behavior.
**User impact:** Users have no concrete next inspection step when the check reports a gap.
**Recommendation:** Add catalog-grounded remediation paths and evidence limits, with protocol-appropriate examples; link affected findings/runs.
**Acceptance check:** Remediation is relevant to the recorded check and never derived from a generic provider assumption.

### 3. [P2] Recent outcome needs target and freshness context

**Observed / evidence:** A single “Last verdict” without exact target/window can be read as a property of the check itself.
**User impact:** A check passed on one endpoint does not prove other endpoints safe.
**Recommendation:** Show latest result as target, observation time, outcome and evidence link; use No recorded result if the lookup lacks data.
**Acceptance check:** No sibling or unrelated run supplies a result, and stale evidence is marked.

## Actions, dialogs, widgets and states

Inspect Schedule this check, taxonomy/technical disclosures and history links. Current invalid-ID state was also exercised; it should retain a helpful return to the library. Safe bounds must use actual operations, including DNS vetting, not a misleading HTTP-only request count.

Keep loading, retained/stale data, unavailable, no data, filtered-empty, disabled-by-role, invalid input, saving, error and success states distinct. Use the shared dialog/keyboard/focus contract; destructive confirmations state the exact affected object.

## Data and functionality prerequisites

Use the check catalog and exact check_id-linked runs/policies. Some demo IDs referenced by old policies are absent; treat stale fixture linkage as fixture cleanup, not proof that all detail routes are broken.

## Visual and motion direction

Use the existing theme tokens, restrained orange accents, familiar shared controls and visible 16–24px content insets. Give dense content a clear spacing owner; avoid nested surface borders and unexplained repeated pills. Animate only actual state changes with 90–200ms feedback and 200–300ms surface transitions; do not animate fake work or hide content before a reveal. Follow [motion specification](02-motion-and-interactions.md), including reduced motion and focus preservation.

## Skills for implementation

Use **UI/UX Pro Max**, then **Impeccable shape, clarify, adapt, harden, animate, polish**, plus **interaction-design** for forms, overlays and async feedback. Read [actual skill files and handoff](05-skills-and-handoff.md), [design direction](00-design-direction.md), and [naming](01-naming-and-navigation.md). Live validation pages also require [execution-trace specification](03-live-check-observability.md).

## Page acceptance criteria

A valid catalog ID renders the correct check, invalid IDs have recovery, target type/evidence level/bounds match the catalog, and technical data does not push the main workflow out of reach.

- Test 375/768/1024/1440px, dark/light, 200% text zoom, keyboard, reduced motion and touch targets.
- Validate the exact entity and role with real API behavior; do not synthesize missing provider/evidence/verdict data.
- Compare before/after screenshots and complete the primary workflow, including cancellation and recovery.
- Preserve outside-in-only scope, no default cloud access, and existing execution authorization.
- Update implementation docs/tracker only in a later authorized implementation task; this review does not mark features complete.

## Scope and result vocabulary

Show the check-specific plan/scenario, expected behavior and recorded evaluation rule behind the [host dimension](06-host-protection-profile.md). Allowed request count is not necessarily successful protection or application arrival. [Engineering review](09-engineering-consultation.md) requires explicit applicability/exclusion and evidence references before aggregate efficacy is shown.

## Shared composition and task requirements

Apply [component standard](12-component-visual-specification.md), [content/mobile task budgets](14-content-and-responsive-task-budgets.md), and [feedback/persistence rules](16-feedback-responsiveness-and-daily-use.md). Reuse the appropriate R1–R5 [reference pattern](11-reference-screen-specifications.md), then verify this page’s primary task through [G0–G5 gates](17-design-acceptance-and-handoff-gates.md). No proposed screen, brand choice or usability result is approved/completed merely because this review exists.


## Data-to-decision and cross-page task contract

Source/saved-evidence review added 2026-10-04; proposed UX only, not new live verification.

| Contract | Page requirement |
| --- | --- |
| Decision / intended outcome | Explain one named check in caller target or schedule context. |
| Data and interpretation | Purpose/profile, applicability/setup, bounds, expected/evaluation logic, exact-check linked history/policies. A latest check result needs target/time. |
| Current path / context | Detailed catalog facts and links to schedules/library; unavailable ID has recovery. |
| Proposed continuation | Exact-check preview beside caller, schedule/launch with caller scope; detail remains shareable depth. |
| Carry automatically | Check ID/version, target if specified, policy or catalog return context. |
| Back / Close restores | Same named schedule/target/catalog query; no library reset. |
| Loading / missing / permission | Unknown/removed check, incompatible kind, missing setup, denied start; read metadata if allowed. |
| Task acceptance | Click a schedule check opens that check, with caller scope, not the library homepage. |

Apply [contextual inspector](19-contextual-evidence-inspector.md), [cross-page actions/return-state](20-cross-page-task-flow-contract.md), [data semantics](23-data-meaning-and-workflow-state-contract.md) and [confirmed source links](22-contextual-link-and-source-audit.md). Inspecting never executes; technical record routes remain optional depth. Verify completion using [design acceptance](17-design-acceptance-and-handoff-gates.md), not just route rendering.
