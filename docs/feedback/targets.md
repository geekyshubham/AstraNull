# Targets — UX/UI review

Review: 2026-10-03–04. Status: feedback/proposed work only; no implementation is approved by this file.

## User goal

Find and verify a declared endpoint, understand its actual eligibility, and open its evidence.

## Inspected surface and evidence

Route: `/app#targets`. Observed heading: **Targets**.
Source: `apps/web/react/src/pages/targets-page.tsx`; `apps/web/react/src/lib/target-csv-import.ts`.
Browser evidence: [desktop](evidence/targets-desktop.png), [route observations](evidence/route-observations.json).

This review used local synthetic fixtures. Missing/stale fixture relationships or dates are explicitly separated from verified UI/source problems. No production provider or live external-probe execution is claimed.

## Proposed hierarchy

Targets first in navigation → compact ownership summary → search and essential filters → table with target, ownership, WAF/CDN observation, last evidence, and one main action; advanced group/source/added details can be column preferences.

## Prioritized findings

### 1. [P1] “Ready for validation” is the declared-target count

**Observed / evidence:** The fixture shows 5 ready, 3 verified, 2 unverified. Source renders targets.length for the ready metric.
**User impact:** The UI promises runnability for targets whose ownership gate is not satisfied.
**Recommendation:** Rename to a truthful recorded measure or derive can-start eligibility from exact proof, check fit, windows, concurrency, and limits. Do not reuse total count.
**Acceptance check:** Two pending targets never contribute to a runnable count; a gate reason is available when a start is disabled.

### 2. [P2] Table hides the most useful actions beyond its horizontal edge

**Observed / evidence:** The desktop screenshot fits target/kind/tags/group/verification/source, while later evidence/action columns require horizontal navigation. Target kind and manual source are repeated.
**User impact:** A user has to scan duplicated metadata and scroll to take the next step.
**Recommendation:** Keep target and ownership anchored; move kind/source detail into one secondary line, prioritize last observation and Open/Verify. Offer additional columns on demand.
**Acceptance check:** At 1024/1440px primary target action is discoverable without hunting; at 375px table scroll stays local and clear.

### 3. [P2] No last-validation value can look like a never-tested endpoint

**Observed / evidence:** Rows show Never while detail/demo runs exist; the inventory currently lacks an authoritative last-validation field.
**User impact:** Missing list metadata is interpreted as a real absence of testing.
**Recommendation:** Use “Not available in inventory” until an exact-target latest evidence timestamp is provided; do not infer from group runs.
**Acceptance check:** Unknown timestamps differ from confirmed no-run state; no sibling run is borrowed.

## Actions, dialogs, widgets and states

Add target is an inline workflow on this page, not a modal. Inspect its name/kind/group/tags fields, default group behavior, validation, and cancel. Edit tags and Remove use dialogs; retain invalid tags, show exact target in destructive copy, and preserve evidence history. Review unverified should apply a visible, removable filter. Test search, group/kind/tag/ownership filters and Open target.

Keep loading, retained/stale data, unavailable, no data, filtered-empty, disabled-by-role, invalid input, saving, error and success states distinct. Use the shared dialog/keyboard/focus contract; destructive confirmations state the exact affected object.

## Data and functionality prerequisites

Use GET /v1/targets tenant scope and exact verification fields. WAF/CDN and last observation require an additive list projection if introduced. Tag limits/normalization must match ADR-0008; kind/value are immutable after declaration.

## Visual and motion direction

Use the existing theme tokens, restrained orange accents, familiar shared controls and visible 16–24px content insets. Give dense content a clear spacing owner; avoid nested surface borders and unexplained repeated pills. Animate only actual state changes with 90–200ms feedback and 200–300ms surface transitions; do not animate fake work or hide content before a reveal. Follow [motion specification](02-motion-and-interactions.md), including reduced motion and focus preservation.

## Skills for implementation

Use **UI/UX Pro Max**, then **Impeccable shape, clarify, adapt, harden, animate, polish**, plus **interaction-design** for forms, overlays and async feedback. Read [actual skill files and handoff](05-skills-and-handoff.md), [design direction](00-design-direction.md), and [naming](01-naming-and-navigation.md). Live validation pages also require [execution-trace specification](03-live-check-observability.md).

## Page acceptance criteria

Unverified count reconciles with rows; filtered totals are labeled; pending proof does not say Ready; a zero filter result offers Clear filters; form errors preserve input; Escape returns focus from Edit/Remove.

- Test 375/768/1024/1440px, dark/light, 200% text zoom, keyboard, reduced motion and touch targets.
- Validate the exact entity and role with real API behavior; do not synthesize missing provider/evidence/verdict data.
- Compare before/after screenshots and complete the primary workflow, including cancellation and recovery.
- Preserve outside-in-only scope, no default cloud access, and existing execution authorization.
- Update implementation docs/tracker only in a later authorized implementation task; this review does not mark features complete.

## Protection cohorts and host list addition

Expose concise WAF/CDN observation, origin-hosting certainty, declared service roles, criticality, owner and freshness in prioritized columns or detail expansion. Add the filters behind [dashboard cohorts](07-dashboard-protection-analytics.md), with count/list parity and pagination-independent totals. “Hosts with declared login role” is not “login endpoints assessed.” Retain unreachable and TLS-failed targets as investigation items, and keep IP/CIDR scope supported.

## Shared visual/task handoff

Use [reference specifications](11-reference-screen-specifications.md), [component standard](12-component-visual-specification.md), [responsive budgets](14-content-and-responsive-task-budgets.md) and [feedback/navigation](16-feedback-responsiveness-and-daily-use.md). Page focus: R3; J1/J3; T3 exact-target selection and T6 return/filter context. See [acceptance gate](17-design-acceptance-and-handoff-gates.md). All references remain proposed until rendered and explicitly approved; user task results are Not run.


## Data-to-decision and cross-page task contract

Source/saved-evidence review added 2026-10-04; proposed UX only, not new live verification.

| Contract | Page requirement |
| --- | --- |
| Decision / intended outcome | Find one declared endpoint and finish its next ownership/validation task. |
| Data and interpretation | Exact identity/kind, tags/group, ownership, source/added time. Ready count currently equals total; missing validation time is not confirmed Never. WAF/CDN columns require actual projection. |
| Current path / context | Search/filter → target detail; row tag/remove controls; adding already opens created target. |
| Proposed continuation | Select target opens useful profile; Verify opens its own proof; scoped validation starts from that target; correct current behavior retained. |
| Carry automatically | Target/group/ownership challenge IDs; filters/sort/page; safe tag draft. |
| Back / Close restores | Same filtered row/page/scroll; deleted target gets contextual fallback. |
| Loading / missing / permission | No inventory vs no matches vs read error distinct; pending ownership cannot look runnable. |
| Task acceptance | Pending target Verify shows its own TXT; returning retains filters and exact target. |

Apply [contextual inspector](19-contextual-evidence-inspector.md), [cross-page actions/return-state](20-cross-page-task-flow-contract.md), [data semantics](23-data-meaning-and-workflow-state-contract.md) and [confirmed source links](22-contextual-link-and-source-audit.md). Inspecting never executes; technical record routes remain optional depth. Verify completion using [design acceptance](17-design-acceptance-and-handoff-gates.md), not just route rendering.
