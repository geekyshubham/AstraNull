# Visible complexity, copy and responsive task budgets

2026-10-04. Proposed composition rules for [reference screens](11-reference-screen-specifications.md). These budgets constrain visible complexity, not access to essential evidence. Never clip safety information, omit an actual blocker, or truncate accessible labels to satisfy a word count.

## Content budget

| Region | Initial-view budget | Where depth goes |
| --- | --- | --- |
| Page arrival | One title; optional introduction ≤25 words; one primary action | Help/disclosure for product concepts. |
| Header metadata | One concise contextual line; up to four relevant facts | Target facts/evidence; long IDs copyable in detail. |
| Summary | Up to four headline measures, each label ≤5 words and one short qualifier | Formula/scope/source in metric inspector. |
| Main workspace | Two decision areas at desktop, one task sequence mobile | Supporting history/taxonomy below or in tabs. |
| Priority actions | Three rows maximum in dashboard summary | Full Findings/remediation queue with same filter. |
| Provider row | Family, provider, state, age, Evidence action | Recorded signals and caveats in inspector. |
| Dimension row | Label, outcome, current scope/count, age | Evaluation rule/coverage exclusions on activation. |
| Form guidance | One short introduction; persistent labels; one specific helper per field as needed | Advanced settings progressive, not a wall of introduction. |
| Safety guidance | Exact target, bounds, meaningful limit and gate at the relevant action | Complete artifact/permission evidence one step deeper. |
| Explanation | One conclusion, one reason, one next action | Technical fields/raw redacted records in disclosure. |

Four options is not a universal psychological ceiling: expert catalogs require more. Use staged decisions and searchable lists instead of arbitrary hiding. A long explanation often signals unresolved product logic; clarify the source and action first.

## Copy examples

| Context | Proposed visible copy | Additional detail |
| --- | --- | --- |
| Dashboard | “See coverage, open gaps and running validation.” | Formula and provenance in inspection. |
| Unknown WAF | “WAF status unknown” | “No recent usable observation. Review the source or run a bounded check.” |
| Negative fingerprint | “WAF not detected” | Not a claim that no WAF exists. |
| Locked run | “Verify ownership to run this check” | Exact proof instructions and applicable gates. |
| Refresh failure | “Could not refresh coverage. Showing results from 10:20.” | Retry; raw error reference in technical detail. |
| Retest | “Review retest for 3 declared targets” | Exact pairs, bounds and exclusions before start. |
| Cancel | “Stop this validation?” | Previous evidence retained; actual stop behavior and scope. |

Use verb + object for controls. Avoid generic “OK,” “Proceed,” internal API keys and repeated platform promises in every card. Use familiar terms consistently across list/detail/dialog/report. A decision's necessary consequence stays visible, even when it exceeds the normal helper budget.

## Responsive task matrix

Breakpoints describe task rearrangement; do not implement device identification. Desktop ≥1120px uses current expanded sidebar; tablet 700–1119px uses drawer and stacked task areas; narrow <700px uses one column. Validate intermediate widths and 200% text zoom, not just named breakpoints.

| Surface | Desktop task | Tablet adjustment | Mobile first content / controls |
| --- | --- | --- | --- |
| Dashboard | Coverage + priority actions side by side | Priorities precede analytics in stack | Gap/active work first, up to two measures per row, cohort comparison in readable list/table. |
| Host profile | Attribution/dimensions with priority context | Single continuous profile | Identity → ownership/action → urgent gap → observations → dimensions. Long technical rationale collapsed. |
| Targets | Table with primary identity, ownership, observation, last evidence, action | Hide optional columns by explicit priority | Keep target, ownership/next step and Open/Verify. Observation in expandable row detail; expert full table optional. |
| Validate live | Queue + selected-check inspector | Queue collapses to named selector/list | Active check, last event/connectivity, result; Request/Response/Evaluation/Evidence selectors; queue one activation away. |
| Findings | Severity/affected target/owner/deadline/action | Combine supporting fields | Outcome + severity + affected target count + next action. Filters in clearly named sheet. |
| Schedule launcher | Scope/check/time/review stages | Same stages, smaller measure | Stage title, choice, selected summary and next action; catalog never fills the whole flow before scope. |
| Dialog/evidence | Bounded dialog/drawer, scroll body | Viewport-safe insets | Safe-width sheet; header identity, reachable footer; keyboard-aware. |

**Inventory exception:** a task-oriented narrow view may use a semantic list or expanded-row representation of the same records; it must not invent facts or replace all expert tables with incoherent cards. Full comparison/audit tables can scroll locally, but the primary Open/Verify action cannot be stranded at the far right. Detail states and selection must remain equivalent between representations.

## Primary action placement

Desktop header action aligns with title; narrow profile offers a full-width action after ownership context. Active live-work Stop remains reachable in a persistent work toolbar where feasible; reserve layout space, avoid covering evidence, respect safe-area/keyboard and allow zoom. Any sticky footer must have a tested fallback when viewport height is too short. Never hide an urgent control simply to meet a viewport screenshot.

## Filters and technical detail on mobile

Show search and one essential scope/status filter; More filters opens a labeled sheet showing current selections and count. Apply/Reset/Close have explicit behavior. Do not re-run expensive requests while a user is still editing multi-field filter criteria unless the UI supports intentional immediate filtering.

Tabs retain names, keyboard semantics and visible overflow affordance; do not reduce them to unexplained icons. Provider/dimension explanation collapses, but unknown/stale/gap labels and next actions stay visible. No hover-only tooltip, fixed-height text crop, horizontal page scroll or hidden footer.

## Task acceptance

At 375px, users can identify urgent gap, open provider evidence, navigate to the right target, select a compatible check and read response/evaluation without navigating a wide table. At tablet widths they can compare key statuses without tiny type. At zoom/translation, content grows and controls remain reachable.

Use [journeys](15-first-use-and-returning-user-journeys.md) and [task gate](17-design-acceptance-and-handoff-gates.md). Overflow measurement alone is insufficient.
