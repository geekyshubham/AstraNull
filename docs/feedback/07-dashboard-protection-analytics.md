# Dashboard protection analytics — segmentation and placement

Added 2026-10-04. Proposed handoff only; see [host profile](06-host-protection-profile.md) and [engineering contracts](09-engineering-consultation.md).

## Senior UX recommendation

Dashboard Overview should answer “Which important declared services need attention?” rather than adding every metric as another equal-size card. Keep four compact headline facts, one segmented coverage comparison, a prioritized action list and recent validation. Put provider concentration and historical comparisons in Risk trends.

| Surface | Recommended content | Why / drill-down |
| --- | --- | --- |
| Overview headline | Declared hosts; declared critical-service gaps; current evaluation coverage; changes needing review | Each opens a filtered Targets/Findings/Changes view. Exact units are labeled. |
| Overview coverage block | WAF and CDN observations, then breakdown by Website/API/Login/Unclassified | Exposes service-type gaps hidden by aggregate coverage; open selected cohort. |
| Overview prioritized actions | Consolidated actionable gap, impact, owner, affected hosts, evidence freshness, retest | Routes to remediation group/finding and exact-target validation review. |
| Risk trends | Confirmed regressions, coverage over comparable cohorts, provider concentration by role, stale evidence | Historical comparison and dependency review without crowding arrival. |
| Overview active checks | Target, selected direct check, actual phase and last recorded event | Open that target’s selected-check inspector; do not add an execution-history route. |
| Targets inventory | Cohort filters and endpoint rows behind every aggregate | Visible applied filters, exact record links, clear reset and denominators. |

Keep current published score as a qualified readiness summary, not “85% DDoS protected.” The profile defines separate assurance dimensions.

## Counting units

A declared target, unique hostname, business service, web application, login endpoint, check-target pair, finding instance and remediation group are different units. One hostname can serve an API and login flow; a group is not necessarily one business service. Website/API/login categories may overlap. Do not imply that a service-role tag creates a uniquely inventoried login URL.

Until a canonical declared service/endpoint relationship exists, label the view **Hosts with declared login role**, **Hosts with declared API role**, and **Unclassified hosts**. A first-class service/application/endpoint count requires a typed declaration and stable ID. “Active” must have a stated definition/window and source; an archived flag alone is not evidence a service is answering.

## Metrics and frontend/backend contract questions

| Metric | Definition / denominator | Required data | Drill-down |
| --- | --- | --- | --- |
| Declared hosts | Unique normalized declared hostname identity within active declared scope | Target IDs, kinds, normalized host identity; URL-target deduplication rules | Host list; duplicates/group associations remain inspectable. |
| WAF visibility | Detected/not detected/inconclusive/not checked; stale separately marked | Trusted per-family observation and freshness policy | Filter family/status/window; profile evidence on each row. |
| CDN visibility | Same observation semantics independently of WAF | CDN-specific evidence, not WAF vendor fallback | Exact cohort list. |
| Critical-service gaps | Distinct declared critical service IDs with unresolved scoped findings; if no service model, label **Critical declared targets with gaps** | Declared criticality, explicit inheritance, scoped lifecycle and relationship | Affected target/service list, not raw total findings. |
| Declared origins reachable | Distinct declared origins with current authoritative reachability evidence | Explicit origin bindings, authorized check IDs, result/provenance | Origin scope/result/run list. No discovered origin inventory. |
| Evaluation coverage | Current evaluated applicable check-target pairs / applicable plan pairs | Scope/catalog/plan version, applicability and current result time | Inconclusive, missing setup, not run, stale, excluded listed separately. |
| Confirmed regressions | Comparable previously passing behavior now fails, or comparable control/routing observation changes | Prior/current snapshots, stable check versions/scope, source times | Changes view with before/after evidence. |
| Top actions | Explicit consolidated changes with per-host outcomes and owner | Finding identity, remediation relationship, declared impact and fresh evidence | Remediation detail and bounded retest review. |

Metric response must expose source/scope, assessed-at time, freshness policy/version, counts, units and applied filters. Suggestions such as a new rollup endpoint are proposals, not existing API promises. Do not load every host detail to compute a dashboard metric in the browser.

## Recommended comparison visual

Use a horizontal stacked-bar table, with rows for All declared hosts, declared API role, declared login role, websites and unclassified. For WAF/CDN, show detected, negative, inconclusive/unmeasured counts with visible legend and totals. Mark stale evidence explicitly. Show the exact numerator/denominator in text and supply the same information as an accessible table.

Do not use a pie chart to imply non-overlapping roles, a radar chart for missing dimensions, or a provider-logo count as protection efficacy. Zero denominator shows **Not applicable / none assessed**. An error shows **Unavailable**, not zero. A historical observation becoming stale is not proof that the control disappeared.

The source brief quotes 142/178 web applications and 12/31 login pages to illustrate the segmentation problem. Those are user-supplied report classifications, not verified AstraNull data; keep them out of live product/demo KPIs. See [source notes](10-protection-profile-source-notes.md).

## Filtered-host behavior

Criticality, declared service roles, observed provider family/product, owner, tags, evidence freshness, validation outcome, origin reachability and maintenance state. Display active filters and count unit. Support multiple roles without accidental double counting. Save/share filter state only in an authorized tenant context; do not encode sensitive payloads or secrets in URLs.

A dashboard click should land in Targets with those filters applied. Use a full inventory workspace for large cohorts; a modal can preview a small breakdown, with **Open full list**. If provider/freshness filters do not exist yet, implement the end-to-end list contract before adding a clickable metric. Count and list must share the same predicates and snapshot consistency.

## Data truth and pagination

Do not reuse optional WAF-asset rollups as declared-host totals. The add-on has different identities, eligibility and cardinality. Provider concentration across layered providers may exceed 100% when summed; display distinct dependent hosts/services per provider and known/unknown associations. Traffic volume and business dependencies stay unknown without appropriate evidence/declarations.

Retain unreachable, TLS-failed and unclassified targets in investigation cohorts. A filter or stale observation must not make the estate look healthier through silent exclusion.

## Delivery order and acceptance

1. Define host profile identity/provenance and service-role declarations.
2. Build truthful profile fields and matched inventory/rollup contracts.
3. Add segmented dashboard and filtered lists.
4. Add live trace and retained change/remediation workflows.

Verify multi-role hosts, duplicate hostname/URL declarations, zero denominator, unknown/stale/conflicting family evidence, inherited/unassigned criticality, scoped origin results, closed/accepted findings, permissions, pagination and count-to-list parity. Comparisons must state cohort/check/window changes instead of producing false improvement/regression. Use UI/UX Pro Max and the [shared design/motion skills](05-skills-and-handoff.md); keep dark/light, mobile and textual chart equivalents.

## Shared visual/task handoff

Use [reference specifications](11-reference-screen-specifications.md), [component standard](12-component-visual-specification.md), [responsive budgets](14-content-and-responsive-task-budgets.md) and [feedback/navigation](16-feedback-responsiveness-and-daily-use.md). Page focus: R1; J2; T1 priority and T2 denominator/uncertainty comprehension. See [acceptance gate](17-design-acceptance-and-handoff-gates.md). All references remain proposed until rendered and explicitly approved; user task results are Not run.
