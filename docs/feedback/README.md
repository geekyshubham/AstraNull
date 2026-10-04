# AstraNull UI/UX feedback

**Review only; no application code changes or commits remain.** These files are the handoff backlog for future authorized implementation agents. Reviewed 2026-10-03–04 using UI/UX Pro Max, Impeccable, interaction-design guidance and live browser inspection.

## Current-release scope

Read [scope correction](24-current-release-scope.md) first. Staff/privileged operational pages and standalone execution-list/detail pages are deferred and removed from this handoff. The current journey is **target → direct check → result/evidence on that target**. Backend execution IDs remain technical provenance, not additional navigation.

## Start here

1. [Dashboard review](dashboard.md): domain/WAF/CDN analytics, useful next actions, evidence-qualified readiness and layout.
2. [Live check visibility](03-live-check-observability.md): actual requests/commands, recorded responses, evaluation rules and evidence.
3. [Design direction](00-design-direction.md), [naming/navigation](01-naming-and-navigation.md), [motion](02-motion-and-interactions.md).
4. [Coverage and limitations](04-review-coverage.md): what was clicked/inspected, synthetic-data limits and the local setup incident.
5. [Skills and handoff](05-skills-and-handoff.md): actual skill paths, workflow and per-agent implementation prompt. Animation skills were already installed; no additional skill installation was necessary.

## Task-first investigation update — 2026-10-04

All 28 current-release page reviews now include data interpretation and cross-page completion contracts. Prioritize contextual evidence and correct destinations before further decorative polish:

- [Evidence beside the result](19-contextual-evidence-inspector.md): one-action primary proof, optional forensic detail and correct source relationships.
- [Cross-page task contract](20-cross-page-task-flow-contract.md): 18 journeys, inspect/edit/navigate/execute rules and restoration.
- [All-page data and UX review](21-all-page-data-and-task-review.md): each page's decision, current/proposed path, carried context, failure states and task acceptance.
- [Confirmed contextual-link/source audit](22-contextual-link-and-source-audit.md): wrong/broad destinations and existing good patterns to retain.
- [Shared data/state meaning](23-data-meaning-and-workflow-state-contract.md): units, freshness, provenance, missing-data semantics and safe continuation.

Current source and the saved browser baseline support this addition; it is **not a new live current-release page click-through**. Audit already has inline drill-down; signup/status/invitation already preserve some references. Recommendations extend those foundations rather than inventing missing-work claims.

## Protection-profile addition — 2026-10-04

The supplied brief is incorporated with read-only senior frontend/backend consultation. Start with these implementation-ready recommendations; **no coding is authorized by this handoff**:

- [Host protection profile and UI placement](06-host-protection-profile.md): exact fields, dimensions, provider evidence inspector and target-page hierarchy.
- [Dashboard segmentation and drill-downs](07-dashboard-protection-analytics.md): login/API/website cohorts, critical scope, honest units and counts.
- [Drift, provider concentration, maintenance and remediation](08-drift-concentration-remediation.md): existing route placements, comparison semantics and per-host retest.
- [Senior engineering consultation](09-engineering-consultation.md): verified existing capabilities, missing contracts, source issues, ownership and acceptance checks.
- [Source brief traceability](10-protection-profile-source-notes.md): each supplied requirement mapped to its handoff; referenced report figures remain unverified classifications, not product data.

Relevant existing page reviews now have linked addenda. Prioritize host profiles, segmented analytics, live evidence, then retained drift/remediation workflows. Keep optional configuration integration evidence distinct from core observations.

## Reproducible design handoff — 2026-10-04

The latest suggestions now have shared specifications and future acceptance gates:

- [Five reference-screen specifications](11-reference-screen-specifications.md): dashboard, host profile, inventory, dialog/drawer and mobile; realistic populated/empty/error examples.
- [Component visual standard](12-component-visual-specification.md): typography, dimensions, alignment, spacing and states.
- [Surface/color decision](13-surface-color-decision.md): existing pure-black default versus a restrained raised-tone candidate.
- [Content and responsive task budgets](14-content-and-responsive-task-budgets.md): what stays visible, column priorities and mobile action placement.
- [First-use and returning-user journeys](15-first-use-and-returning-user-journeys.md): declaration, proof, bounded validation and result comprehension.
- [Feedback, loading and daily-use controls](16-feedback-responsiveness-and-daily-use.md): retained data, dirty forms, truthful undo, saved views and Back behavior.
- [Design acceptance gates](17-design-acceptance-and-handoff-gates.md): reference approval and measurable representative-user tasks.
- [Suggestion traceability](18-handoff-strengthening-traceability.md): what is specified, pending and untested.

**Reference screens are specifications, not approved rendered designs.** Surface changes await an explicit brand decision; current DESIGN.md remains authoritative. Usability targets are proposed; no study was run. Complete this shared preparation before a later authorized implementation task.

## Highest-priority improvements

- Domain analytics: distinct declared hostnames; observed WAF/CDN presence, explicit not-detected/unknown/stale states, freshness and evidence drill-downs. Detection must not be called protection efficacy.
- Correct “Ready for validation”: Targets currently counts every declared target, including pending ownership.
- One-action contextual proof from results, exact named destinations and restored investigation state; the live inspector exposes request → response → evaluation without mandatory object hopping.
- Clear finding rationale and lifecycle decisions anchored to original evidence; avoid broader claims from one passing check.
- Better dialog footer insets, searchable staged launchers, table column priorities and progressive technical disclosure.
- Consistent naming and removal of customer-facing design experiment switches; purposeful reduced-motion-safe feedback.

## Shared surfaces

- [Shell/navigation/tables](shared-shell.md).
- [All overlay families](shared-overlays.md).
- [Direct checks on the target](direct-check-execution-flow.md).

## Current-release page reviews — 28

| Page | Feedback |
| --- | --- |
| Dashboard | [dashboard.md](dashboard.md) |
| Targets | [targets.md](targets.md) |
| Target groups | [target-groups.md](target-groups.md) |
| Target group detail | [target-group-detail.md](target-group-detail.md) |
| Target detail | [target-detail.md](target-detail.md) |
| Vector library / check library | [checks.md](checks.md) |
| Check detail | [check-detail.md](check-detail.md) |
| Test policies / validation schedules | [test-policies.md](test-policies.md) |
| Validation schedule detail | [policy-detail.md](policy-detail.md) |
| Findings queue | [findings.md](findings.md) |
| Finding detail and remediation | [finding-detail.md](finding-detail.md) |
| Grouped finding detail | [finding-group-detail.md](finding-group-detail.md) |
| Evidence artifact detail | [evidence-detail.md](evidence-detail.md) |
| Reports | [reports.md](reports.md) |
| Report detail | [report-detail.md](report-detail.md) |
| Integrations | [integrations.md](integrations.md) |
| Notifications | [notifications.md](notifications.md) |
| Audit log | [audit.md](audit.md) |
| Settings | [settings.md](settings.md) |
| Support | [support.md](support.md) |
| Plan & usage / Billing | [subscription.md](subscription.md) |
| Release evidence (auditor) | [release-evidence.md](release-evidence.md) |
| Public landing | [landing.md](landing.md) |
| Customer sign-in | [login.md](login.md) |
| Request access | [signup.md](signup.md) |
| Access request status | [signup-status.md](signup-status.md) |
| Invitation password setup | [set-password.md](set-password.md) |
| Missing or unavailable route | [not-found.md](not-found.md) |

Each review contains user goal, observed evidence, prioritized issues, recommended hierarchy, popup/widget behavior, API/data prerequisites, motion direction, skills and acceptance criteria. Severity: P1 significant correctness/workflow/trust issue; P2 usability/polish issue with workaround; P3 optional refinement. No numerical “world-class” score or exhaustive production readiness claim is made.

Targets remain manually/API/CSV declared, provider integrations optional, and current direct checks bounded and authorized. Existing safety boundaries remain unchanged; future-release workflows are not implementation tasks here.
