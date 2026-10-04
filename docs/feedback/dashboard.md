# Dashboard — UX/UI review

Review: 2026-10-03–04. Status: feedback/proposed work only; no implementation is approved by this file.

## User goal

Answer what is declared, which protections have been observed, what needs attention, and what to validate next in one short scan.

## Inspected surface and evidence

Route: `http://127.0.0.1:5173/app?ux_review=baseline#dashboard?tab=overview`. Observed heading: **Readiness overview**.
Source: `apps/web/react/src/pages/dashboard-page.tsx`; `apps/web/react/src/pages/dashboard-page.css`; `apps/web/react/src/lib/dashboard-metrics.ts`; `apps/web/react/src/components/charts/`.
Browser evidence: [desktop](evidence/dashboard-desktop.png), [route observations](evidence/route-observations.json).

This review used local synthetic fixtures. Missing/stale fixture relationships or dates are explicitly separated from verified UI/source problems. No production provider or live external-probe execution is claimed.

## Proposed hierarchy

Header and last evidence time → readiness/coverage/open-gap summary → domain protection coverage → priority actions beside target posture → recent activity → optional factor/path explanations. Risk trends remains a separate, useful analytic view.

## Prioritized findings

### 1. [P1] Domain protection coverage is missing

**Observed / evidence:** The existing overview has Readiness, Declared targets, Evidence coverage, and Open findings. Its Edge/CDN stage reports provider metadata, not per-domain counts.
**User impact:** Security owners cannot see WAF/CDN adoption or unknown coverage.
**Recommendation:** Add distinct declared hostname count; WAF detected/not detected/unknown and CDN detected/not detected/unknown counts, denominator and freshness, with filtered drill-downs. Keep effectiveness separate.
**Acceptance check:** A hostname is counted once; IPs/CIDRs do not enter the domain denominator; absent observations remain unknown and no provider logo implies protection.

### 2. [P1] Protection narrative mixes authorization and traffic defenses

**Observed / evidence:** The path leads with Internet “3/5 verified,” then Edge/CDN, WAF, Origin, under “Where does attack traffic get stopped?”
**User impact:** Ownership proof is permission to probe, not a defense that stops traffic.
**Recommendation:** Move authorization into its own scope context. Present observed edge behavior and origin reachability as evidence, not an assumed physical topology. Move path detail behind disclosure.
**Acceptance check:** A pending-ownership target is described as locked, not an unprotected internet stage; no asserted chain is derived solely from provider metadata.

### 3. [P2] Large diagram and expanded factors push decisions down

**Observed / evidence:** The desktop screenshot leads with a large path panel; weighted factors expose long provenance/authorization paragraphs. `.dashboard-overview` inherits a display:contents panel.
**User impact:** Priority actions sit below explanatory chrome. The baseline has section spacing; the display:contents panel is a layout detail to preserve, not proof that gaps are missing.
**Recommendation:** Give overview an explicit layout gap; put useful counts and actions first; collapse “Why this score?” explanations, keep published points visible. Fit compact tables within their own columns.
**Acceptance check:** No neighboring widgets touch; priority gaps and domain visibility appear before technical explanations at 1440px; 375px has no page overflow.

### 4. [P2] A green verdict donut can overstate broad readiness

**Observed / evidence:** The fixture shows one correlated passing check in a green donut while a high-priority finding remains open.
**User impact:** A user can read the green ring as estate-wide protection.
**Recommendation:** Label the ring by what it counts and scope/window; pair with tested/untested totals and a visible high-priority warning. Use “Passed this check,” not universal protection.
**Acceptance check:** A single pass cannot visually erase an open gap; zero observations produce an explicit unmeasured state.

## Actions, dialogs, widgets and states

Exercise Overview/Risk trends with keyboard, score drill-down, refresh, theme, target/run/finding links. New coverage metrics should open a read-only domain table with WAF/CDN state, observed time, exact target, and originating evidence/run. Include zero-match, no-domain, unavailable, stale, and unknown cases. Keep focus after closing. Show stop/kill-switch notices with real reason and time.

Keep loading, retained/stale data, unavailable, no data, filtered-empty, disabled-by-role, invalid input, saving, error and success states distinct. Use the shared dialog/keyboard/focus contract; destructive confirmations state the exact affected object.

## Data and functionality prerequisites

Current inventory does not expose the per-target edge observation on its list response. Use a tenant-scoped additive rollup/list projection from persisted trusted target_edge_detections, with dev-json/Postgres parity and no per-domain N+1 requests. Define normalization and freshness. Proposed statuses and layout are recommendations only; no new endpoint is implemented by this review.

## Visual and motion direction

Use the existing theme tokens, restrained orange accents, familiar shared controls and visible 16–24px content insets. Give dense content a clear spacing owner; avoid nested surface borders and unexplained repeated pills. Animate only actual state changes with 90–200ms feedback and 200–300ms surface transitions; do not animate fake work or hide content before a reveal. Follow [motion specification](02-motion-and-interactions.md), including reduced motion and focus preservation.

## Skills for implementation

Use **UI/UX Pro Max**, then **Impeccable shape, clarify, adapt, harden, animate, polish**, plus **interaction-design** for forms, overlays and async feedback. Read [actual skill files and handoff](05-skills-and-handoff.md), [design direction](00-design-direction.md), and [naming](01-naming-and-navigation.md). Live validation pages also require [execution-trace specification](03-live-check-observability.md).

## Page acceptance criteria

Verify unique hostname counting, overlapping WAF/CDN, stale/future/conflicting/inconclusive results, target load failure, no targets, open findings alongside a passing run, exact-target links, read-only roles, dark/light, narrow viewport, and reduced motion.

- Test 375/768/1024/1440px, dark/light, 200% text zoom, keyboard, reduced motion and touch targets.
- Validate the exact entity and role with real API behavior; do not synthesize missing provider/evidence/verdict data.
- Compare before/after screenshots and complete the primary workflow, including cancellation and recovery.
- Preserve outside-in-only scope, no default cloud access, and existing execution authorization.
- Update implementation docs/tracker only in a later authorized implementation task; this review does not mark features complete.

## Protection-profile analytics addition

Use [segmented analytics](07-dashboard-protection-analytics.md) for Overview: declared hosts, critical declared scope with gaps, applicable-check coverage and prioritized work. Website/API/login cohorts reveal gaps hidden by the estate total. Put provider concentration and comparable regressions in Risk trends. Every count must open a matching filtered inventory and expose unit, denominator and freshness. Do not use WAF-asset rollups as host/service totals or derive volumetric capacity from bounded checks.

## Shared visual/task handoff

Use [reference specifications](11-reference-screen-specifications.md), [component standard](12-component-visual-specification.md), [responsive budgets](14-content-and-responsive-task-budgets.md) and [feedback/navigation](16-feedback-responsiveness-and-daily-use.md). Page focus: R1; J2 returning security owner; T1 priority, T2 uncertainty and T7 refresh recovery. See [acceptance gate](17-design-acceptance-and-handoff-gates.md). All references remain proposed until rendered and explicitly approved; user task results are Not run.


## Data-to-decision and cross-page task contract

Source/saved-evidence review added 2026-10-04; proposed UX only, not new live verification.

| Contract | Page requirement |
| --- | --- |
| Decision / intended outcome | Identify the most important current gap and supporting proof. |
| Data and interpretation | Published readiness/factors, declared target counts, current open findings, evidence coverage, recent runs, WAF summary. Label score formula/window, target versus group versus finding units, and unknown/stale coverage. |
| Current path / context | Metric often opens broad collection; priority links already resolve exact finding; run/posture rows navigate entity detail. |
| Proposed continuation | Single gap opens exact finding/evidence inspector; aggregate opens matching visible cohort; running work opens selected active session. |
| Carry automatically | Finding or cohort predicates, assessment/window/as-of, target IDs, caller state. |
| Back / Close restores | Same dashboard tab/metric/cohort, selection and scroll; no automatic reorder. |
| Loading / missing / permission | Partial rollup error preserves other data; no evidence is unmeasured; read-only users inspect without Run. |
| Task acceptance | A critical-gap activation exposes the right finding/proof or exact cohort; visible totals and list reconcile. |

Apply [contextual inspector](19-contextual-evidence-inspector.md), [cross-page actions/return-state](20-cross-page-task-flow-contract.md), [data semantics](23-data-meaning-and-workflow-state-contract.md) and [confirmed source links](22-contextual-link-and-source-audit.md). Inspecting never executes; technical record routes remain optional depth. Verify completion using [design acceptance](17-design-acceptance-and-handoff-gates.md), not just route rendering.
