# Release evidence (auditor) — UX/UI review

Review: 2026-10-03–04. Status: feedback/proposed work only; no implementation is approved by this file.

## User goal

Explain release evidence gaps and attestations without confusing metadata inventory with production launch approval.

## Inspected surface and evidence

Route: `http://127.0.0.1:5173/app?ux_review=5#release-evidence`. Observed heading: **Release evidence**.
Source: `apps/web/react/src/pages/governance-pages.tsx: ReleaseEvidencePage`.
Browser evidence: [desktop](evidence/release-evidence-desktop.png), [route observations](evidence/route-observations.json).

This review used local synthetic fixtures. Missing/stale fixture relationships or dates are explicitly separated from verified UI/source problems. No production provider or live external-probe execution is claimed.

## Proposed hierarchy

Release/profile selector if supported → inventory completeness/validity → actionable gap ledger → attestation and retained custody links.

## Prioritized findings

### 1. [P1] Accepted inventory can still contain invalid evidence

**Observed / evidence:** Fixture shows an accepted VECTOR SAFETY POLICY row that fails contract validation, and invalid attestation.
**User impact:** An auditor could interpret Accepted as a verified production gate.
**Recommendation:** Show attachment acceptance, schema validation, custody verification and external signoff as separate dimensions.
**Acceptance check:** Accepted-but-invalid stays an explicit failure; inventory completeness never claims customer production readiness.

### 2. [P2] Gap ledger truncates missing kinds

**Observed / evidence:** Page lists a subset then “…and 12 more kinds.”
**User impact:** An implementation/operator handoff cannot identify all missing work from the main view.
**Recommendation:** Provide full expandable/paginated ledger with owner, required artifact, blocker and action if the data exists; keep summary printable.
**Acceptance check:** Every missing requirement can be inspected/exported; no invented owner or signoff.

### 3. [P2] Release scope and profile need stronger framing

**Observed / evidence:** Summary combines required kinds, attestation status and readiness.
**User impact:** A customer can mistake local/staging evidence for their deployment launch.
**Recommendation:** Pin release/environment/profile and checked-at time; show “Inventory,” “Contract validity,” and “Customer launch signoff” separately.
**Acceptance check:** Local fixture evidence never produces a production approval claim.

## Actions, dialogs, widgets and states

Auditor route was inspected with the correct role after initial route-gate rejection. Inspect Copy gap summary, Technical export and custody references only as permitted; no release submission or signoff during review.

Keep loading, retained/stale data, unavailable, no data, filtered-empty, disabled-by-role, invalid input, saving, error and success states distinct. Use the shared dialog/keyboard/focus contract; destructive confirmations state the exact affected object.

## Data and functionality prerequisites

Use release inventory and actual attestation validation. Names of absent fields/owners are requirements, not available data. Keep current customer evidence permissions and tenant isolation.

## Visual and motion direction

Use the existing theme tokens, restrained orange accents, familiar shared controls and visible 16–24px content insets. Give dense content a clear spacing owner; avoid nested surface borders and unexplained repeated pills. Animate only actual state changes with 90–200ms feedback and 200–300ms surface transitions; do not animate fake work or hide content before a reveal. Follow [motion specification](02-motion-and-interactions.md), including reduced motion and focus preservation.

## Skills for implementation

Use **UI/UX Pro Max**, then **Impeccable shape, clarify, adapt, harden, animate, polish**, plus **interaction-design** for forms, overlays and async feedback. Read [actual skill files and handoff](05-skills-and-handoff.md), [design direction](00-design-direction.md), and [naming](01-naming-and-navigation.md). Live validation pages also require [execution-trace specification](03-live-check-observability.md).

## Page acceptance criteria

All gaps visible; invalid evidence cannot be styled as passed; exact release/profile is clear; external approval blockers remain distinct from JSON validity.

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
| Decision / intended outcome | Explain a specific release gate and supporting artifact. |
| Data and interpretation | Release/profile evidence inventory, acceptance/schema/integrity/external signoff distinctions and missing kinds. |
| Current path / context | Gap ledger and inventory/attestation separate; truncated missing-kind summary. |
| Proposed continuation | Select gate opens requirement/source/invalid reason/action beside ledger; complete gap list available. |
| Carry automatically | Release/profile/kind/artifact/attestation version and source scope. |
| Back / Close restores | Same ledger filter/selected requirement. |
| Loading / missing / permission | Accepted invalid artifact, absent external signoff, missing kind vs unavailable read. |
| Task acceptance | Selecting invalid accepted artifact shows why it fails; no metadata validity becomes customer launch approval. |

Apply [contextual inspector](19-contextual-evidence-inspector.md), [cross-page actions/return-state](20-cross-page-task-flow-contract.md), [data semantics](23-data-meaning-and-workflow-state-contract.md) and [confirmed source links](22-contextual-link-and-source-audit.md). Inspecting never executes; technical record routes remain optional depth. Verify completion using [design acceptance](17-design-acceptance-and-handoff-gates.md), not just route rendering.
