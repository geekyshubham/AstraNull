# Vector library / check library — UX/UI review

Review: 2026-10-03–04. Status: feedback/proposed work only; no implementation is approved by this file.

## User goal

Choose a suitable bounded check for a declared target and understand what its evidence can and cannot prove.

## Inspected surface and evidence

Route: `/app#checks`. Observed heading: **Vector library**.
Source: `apps/web/react/src/pages/vector-library-page.tsx`; `apps/web/react/src/pages/vector-library-page.css`; `apps/web/react/src/lib/vector-library.mjs`.
Browser evidence: [desktop](evidence/checks-desktop.png), [route observations](evidence/route-observations.json).

This review used local synthetic fixtures. Missing/stale fixture relationships or dates are explicitly separated from verified UI/source problems. No production provider or live external-probe execution is claimed.

## Proposed hierarchy

Target selector → recommended applicable checks → advanced vector catalog with grouped taxonomy and optional filters → review drawer with requirements and runnable mapping.

## Prioritized findings

### 1. [P1] Catalog size is easy to confuse with executable coverage

**Observed / evidence:** Header leads with 721 vectors; rows map to bounded checks, declaration-only, transport-only, restricted, monitor-only, or unsupported dispositions.
**User impact:** A buyer/user may believe all catalog vectors can be directly tested.
**Recommendation:** Show catalog entries, runnable checks, and applicable checks as separate labeled measures. Give plain-language evidence level and limitations before E1–E5 codes.
**Acceptance check:** 721 is never represented as number of executed checks or validated protections.

### 2. [P2] Group-first selector contradicts the target-first workflow

**Observed / evidence:** Evaluation target requires choosing both a target group and an exact target before fit is useful.
**User impact:** Users coming from a known hostname must rediscover its group.
**Recommendation:** Provide a direct searchable target selector that resolves its group internally; keep explicit group scope for multi-target workflows.
**Acceptance check:** A deep link with a target preselects the exact target and restates it; no automatic first-target substitution.

### 3. [P2] Advanced taxonomy/filter rail dominates the page

**Observed / evidence:** Five categorical filters, search, pagination, repeated Review actions and design variants surround 25 rows.
**User impact:** The page looks expert-only before explaining a check’s practical purpose.
**Recommendation:** Collapse advanced filters, show purposeful category names and task-based recommendations, use one Review inspector and a visible active-filter summary.
**Acceptance check:** Filtered results show counts and reset; a user can find ownership-compatible DNS/WAF/TLS checks without memorizing taxonomy.

## Actions, dialogs, widgets and states

Click Review, next/previous catalog pages, each filter type, target/group dropdowns, search, Classic/Premium, and a mapped check detail link. Review drawer should show What it checks, Why it matters, Expected protection, Required setup, Safe bounds, Evidence limits, then a clear permitted action. Future-release restricted entries are excluded from the current direct-check picker; do not add a request workflow.

Keep loading, retained/stale data, unavailable, no data, filtered-empty, disabled-by-role, invalid input, saving, error and success states distinct. Use the shared dialog/keyboard/focus contract; destructive confirmations state the exact affected object.

## Data and functionality prerequisites

Catalog vectors and check mappings have different IDs and evidence capability. Use real catalog projection and target-fit logic; no vector-level verdict synthesis or presumed support.

## Visual and motion direction

Use the existing theme tokens, restrained orange accents, familiar shared controls and visible 16–24px content insets. Give dense content a clear spacing owner; avoid nested surface borders and unexplained repeated pills. Animate only actual state changes with 90–200ms feedback and 200–300ms surface transitions; do not animate fake work or hide content before a reveal. Follow [motion specification](02-motion-and-interactions.md), including reduced motion and focus preservation.

## Skills for implementation

Use **UI/UX Pro Max**, then **Impeccable shape, clarify, adapt, harden, animate, polish**, plus **interaction-design** for forms, overlays and async feedback. Read [actual skill files and handoff](05-skills-and-handoff.md), [design direction](00-design-direction.md), and [naming](01-naming-and-navigation.md). Live validation pages also require [execution-trace specification](03-live-check-observability.md).

## Page acceptance criteria

Runnable versus declaration/restricted/monitor states are obvious; Review stays usable on narrow screens; all advanced filters are keyboard reachable; changing target recomputes compatibility without silently starting work.

- Test 375/768/1024/1440px, dark/light, 200% text zoom, keyboard, reduced motion and touch targets.
- Validate the exact entity and role with real API behavior; do not synthesize missing provider/evidence/verdict data.
- Compare before/after screenshots and complete the primary workflow, including cancellation and recovery.
- Preserve outside-in-only scope, no default cloud access, and existing execution authorization.
- Update implementation docs/tracker only in a later authorized implementation task; this review does not mark features complete.

## Readiness-dimension mapping

Explain how each applicable check contributes to [application/origin/network/DNS/operations dimensions](06-host-protection-profile.md), including evidence limits and declaration-only status. Catalog vector counts, runnable checks and current host plan are different denominators. Do not offer a bounded semantic check as volumetric capacity validation.

## Shared composition and task requirements

Apply [component standard](12-component-visual-specification.md), [content/mobile task budgets](14-content-and-responsive-task-budgets.md), and [feedback/persistence rules](16-feedback-responsiveness-and-daily-use.md). Reuse the appropriate R1–R5 [reference pattern](11-reference-screen-specifications.md), then verify this page’s primary task through [G0–G5 gates](17-design-acceptance-and-handoff-gates.md). No proposed screen, brand choice or usability result is approved/completed merely because this review exists.


## Data-to-decision and cross-page task contract

Source/saved-evidence review added 2026-10-04; proposed UX only, not new live verification.

| Contract | Page requirement |
| --- | --- |
| Decision / intended outcome | Understand a vector/check and select valid work for current scope. |
| Data and interpretation | 721 vectors versus runnable mapped checks, capabilities/E-tiers, target dispositions, required setup and safety bounds. Counts are separate. |
| Current path / context | Group then target selectors and taxonomy filters; Review already offers contextual vector detail. |
| Proposed continuation | Preserve useful Review; caller target retained; exact-check preview explains purpose/fit/limits; full taxonomy optional. |
| Carry automatically | Vector/check IDs, explicit caller target/group, search/pagination and mapping version. |
| Back / Close restores | Catalog query/page/filters and safe planned checks. |
| Loading / missing / permission | Missing map, no compatible target, declaration-only, restricted/monitor-only, required input. |
| Task acceptance | Review identifies actual mapped check and evidence limit; target-launch preview never reselects scope. |

Apply [contextual inspector](19-contextual-evidence-inspector.md), [cross-page actions/return-state](20-cross-page-task-flow-contract.md), [data semantics](23-data-meaning-and-workflow-state-contract.md) and [confirmed source links](22-contextual-link-and-source-audit.md). Inspecting never executes; technical record routes remain optional depth. Verify completion using [design acceptance](17-design-acceptance-and-handoff-gates.md), not just route rendering.
