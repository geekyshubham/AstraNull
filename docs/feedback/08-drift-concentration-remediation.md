# Protection changes, concentration, maintenance and remediation

Added 2026-10-04. Extends [host profile](06-host-protection-profile.md), [dashboard analytics](07-dashboard-protection-analytics.md), Findings, Integrations, Notifications and Reports. These are proposed workflows with backend prerequisites, not new completed pages.

## Placement decision

| Capability | Main home | Secondary exposure |
| --- | --- | --- |
| Protection drift / routing changes | Target detail → Changes & history | Dashboard Risk trends; concise regression cue on Overview; opt-in notifications. |
| Provider concentration | Dashboard → Risk trends | Target-group detail for a declared scope; provider evidence in target profile. |
| Login/API gap views | Targets saved/filterable cohorts | Dashboard segmented table; report cohort snapshot. |
| Maintenance signals | Target detail → separate Maintenance section | Targets maintenance filter; optional dashboard investigation summary. |
| Consolidated remediation | Existing Finding group / finding detail | Dashboard prioritized actions, target Findings, report snapshot. |
| Retest outcomes | Remediation detail with each exact-target result | Target history and linked live validation. |

Start inside existing routes. Add a navigation page only when a distinct operational queue needs sustained work; do not create a card or sidebar item for every metric.

## Drift classification and interaction

Retain comparable previous/current observations, scope/check/corpus version, timestamps, provenance and baseline. Identify:

- WAF/CDN detection changed or disappeared in a successful comparable observation.
- Declared hostname’s observed DNS/CNAME routing changed.
- Authorized declared origin reachability changed.
- Previously passing check now has a conclusive failure in a comparable scenario.
- Optional provider integration reports an actual configuration change.

**Observation expired**, **Check timed out**, **Source disconnected**, **Corpus changed** and **No comparison baseline** are different states from confirmed regression. Do not alert “WAF removed” because yesterday’s fingerprint timed out. No promised live drift coverage exists without an actual supported schedule, comparison retention and sources.

A Changes row displays human summary, exact target, prior/current state, observed time and impact. Open a side-by-side evidence view. “Change detected” is not always “Risk increased”; record authorized expected maintenance/deployment context where supported. Acknowledge does not close the original finding. Notification triggers require explicit user routing and existing opt-in delivery behavior.

## Provider concentration

Separate CDN, WAF, authoritative DNS, observed edge/cloud and attributable origin-hosting roles. Group by canonical provider/product and role, show distinct dependent declared hosts and distinct critical declared services only if the service model exists. Preserve multi-provider/layer overlap and unknown associations.

Use sorted horizontal bars plus a table: provider, role, dependent hosts, critical declared scope, unknown/stale share, evidence period. Clicking a row opens its scoped inventory. Never infer a complete dependency graph from one CNAME or declare a cloud provider behind a proxied origin without evidence. A shared provider is operational context, not automatically a vulnerability or outage prediction.

## Maintenance indicators

Certificate expiry (actual certificate and date), TLS failure, unresolved DNS, repeated service errors and unavailable transport are investigation signals. Render method, observation time and check/source. Keep them in a separately titled Maintenance section, outside the DDoS verdict score unless the published scoring model expressly uses them and explains how.

Expiry badges use user timezone and absolute date; unknown certificate state has no countdown. “Repeated errors” requires a defined series/window, not one failed request. An unreachable target stays in inventory and unknown protection counts.

## Remediation groups and retest

Group only findings that share a proposed actionable change and responsible owner/scope. Existing issue-group identity is not automatically a remediation project or one fix. Do not group merely by same provider name if distinct controls/services require different changes.

Recommended detail:

1. Outcome and business impact, with declared provenance.
2. Affected exact targets and each finding’s original evidence/lifecycle.
3. Proposed change, accountable owner, reason and approval/work state where supported.
4. Last retest and remaining unresolved targets.
5. **Review retest**: explicit target/check pairs, current authorization, bounds, exclusions and stale/unsupported scope.
6. Per-target completion results; original evidence remains retained.

No generic “Fix all” should push configuration to customer infrastructure. Optional connectors remain read-only unless a separately authorized write capability exists. A recommendation or saved playbook is not an applied fix. One host passing retest does not close every group member; inconclusive/cancelled/stale work cannot establish remediation.

## Backend dependencies

Latest-only target edge snapshots are insufficient for a trustworthy provider/routing history. Define a retained comparison record or derive from immutable signed artifacts with explicit scope/version. Existing WAF add-on drift/trend and action-item capabilities are useful partial foundations, but they have their own asset/connector semantics. Cross-target remediation/retest links and notification events need tenant isolation, stable identity, audit, retention/redaction and idempotent handling.

Reports must snapshot the comparison baseline, cohort and applied filters; do not mix current remediated state into a prior report. Audit records a decision, not proof that an infrastructure change succeeded.

## Frontend requirements and acceptance

- Stable event pagination/cursors; newest events must not steal focus or alter an open comparison drawer.
- Empty No baseline, Source unavailable and No confirmed changes states are different.
- Before/after labels are textual and keyboard accessible; color is supplementary.
- Filters retain exact provider role and declared service context on navigation.
- Compare matching check/scenario/corpus; differences are labeled rather than scored as regression.
- Retest uses current gates and exact targets; partial results remain visible.
- No default traffic-volume score, provider-mode claim, undeclared-origin scan or automatic inventory discovery is introduced.

Use UI/UX Pro Max horizontal comparisons, Impeccable shape/clarify/harden/adapt/animate/polish, existing shared tables/dialogs, and [motion contract](02-motion-and-interactions.md). Briefly emphasize a recorded changed row; do not animate continual “threat detection” for unobserved work.
