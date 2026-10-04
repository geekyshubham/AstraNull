# Evidence artifact detail — UX/UI review

Review: 2026-10-03–04. Status: feedback/proposed work only; no implementation is approved by this file.

## User goal

Identify the evidence source and distinguish a recorded digest from verified integrity.

## Inspected surface and evidence

Route: `/app#evidence-detail`. Observed heading: **Probe result**.
Source: `apps/web/react/src/pages/detail-pages.tsx: EvidenceDetailPage`; `apps/web/react/src/lib/custody.ts`.
Browser evidence: [desktop](evidence/evidence-detail-desktop.png), [route observations](evidence/route-observations.json).

This review used local synthetic fixtures. Missing/stale fixture relationships or dates are explicitly separated from verified UI/source problems. No production provider or live external-probe execution is claimed.

## Proposed hierarchy

Artifact name and source run → observation/provenance → integrity status and verification action → available metadata/content → export.

## Prioritized findings

### 1. [P1] Recorded digest and verified custody must be visually distinct

**Observed / evidence:** Page already cautions that supplied chain metadata is not independently verified, but provides Recompute digest and Export artifact near a digest-recorded summary.
**User impact:** Users can mistake local recomputation for verification of original evidence custody.
**Recommendation:** Show Recorded hash, Locally recomputed, Server chain verified, and Not verified as distinct states with method/time.
**Acceptance check:** A local digest match is never labeled server custody verified.

### 2. [P2] Breadcrumb points to an Evidence vault without a current list route

**Observed / evidence:** Inspected page says Back to Evidence vault while current sidebar has no vault item.
**User impact:** Users may be sent to a removed or unexpected surface.
**Recommendation:** Return to the actual originating finding/run or an authorized evidence list if one exists; audit the return href rather than inventing a new page.
**Acceptance check:** Back navigation resolves to a real route and retains context.

### 3. [P2] Empty stored JSON dominates the artifact story

**Observed / evidence:** Fixture has recorded metadata/size but no object-valued payload preview.
**User impact:** The user sees a missing JSON area without enough meaningful source explanation.
**Recommendation:** Prioritize available type/source/time/digest metadata; explain why content is unavailable without suggesting it is corrupt.
**Acceptance check:** Missing preview differs from fetch failure and intentionally metadata-only retention.

## Actions, dialogs, widgets and states

Inspect technical artifact/custody disclosures, source run, Recompute digest and export. Offer copy feedback for IDs/hashes and allow wrapping. Do not export secrets or imply unavailable content was downloaded.

Keep loading, retained/stale data, unavailable, no data, filtered-empty, disabled-by-role, invalid input, saving, error and success states distinct. Use the shared dialog/keyboard/focus contract; destructive confirmations state the exact affected object.

## Data and functionality prerequisites

Only render payload fields actually available under retention/access policy. Integrity state requires actual verification response, not a CSS badge based on the existence of a digest.

## Visual and motion direction

Use the existing theme tokens, restrained orange accents, familiar shared controls and visible 16–24px content insets. Give dense content a clear spacing owner; avoid nested surface borders and unexplained repeated pills. Animate only actual state changes with 90–200ms feedback and 200–300ms surface transitions; do not animate fake work or hide content before a reveal. Follow [motion specification](02-motion-and-interactions.md), including reduced motion and focus preservation.

## Skills for implementation

Use **UI/UX Pro Max**, then **Impeccable shape, clarify, adapt, harden, animate, polish**, plus **interaction-design** for forms, overlays and async feedback. Read [actual skill files and handoff](05-skills-and-handoff.md), [design direction](00-design-direction.md), and [naming](01-naming-and-navigation.md). Live validation pages also require [execution-trace specification](03-live-check-observability.md).

## Page acceptance criteria

Hash/verification status is truthful, origin links work, metadata-only states are useful, and long digests wrap safely in both themes.

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
| Decision / intended outcome | Inspect/share one artifact and understand integrity. |
| Data and interpretation | Artifact type/size/source run, available content/metadata, recorded digest and actual recomputation/verification state. Metadata-only not corruption. |
| Current path / context | Standalone artifact; return can reference absent Evidence vault concept. |
| Proposed continuation | Optional expansion of inspector; exact source summary and correct contextual Back; verification/export explicit. |
| Carry automatically | Artifact/source finding/run, origin inspector selection and permitted snapshot. |
| Back / Close restores | Origin inspector/list, or canonical source route on cold load. |
| Loading / missing / permission | Expired/denied/no preview vs failed fetch; recorded hash not verified. |
| Task acceptance | Artifact bookmarked alone resolves correctly; Back returns to investigation, not removed vault alias. |

Apply [contextual inspector](19-contextual-evidence-inspector.md), [cross-page actions/return-state](20-cross-page-task-flow-contract.md), [data semantics](23-data-meaning-and-workflow-state-contract.md) and [confirmed source links](22-contextual-link-and-source-audit.md). Inspecting never executes; technical record routes remain optional depth. Verify completion using [design acceptance](17-design-acceptance-and-handoff-gates.md), not just route rendering.
