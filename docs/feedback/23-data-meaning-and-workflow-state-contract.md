# Data meaning and workflow state — shared UX contract

2026-10-04. Applies to every page and every inspector. Proposed presentation/contract requirements grounded in current source and saved evidence; no new implementation or live validation.

## Every important datum answers these questions

1. What entity/unit does this describe?
2. Was it declared, observed, computed, or externally configured?
3. What exact scope/scenario/window applies?
4. When was it observed, generated, refreshed or changed?
5. Is it current, stale, partial, unavailable, unknown or not applicable?
6. What evidence or record supports it?
7. What can the user do next, under the current role?

Do not show all seven fields as permanent technical clutter. Display unit/status/time and next action, then expose the full context beside the result in the inspector. A tiny tooltip or raw JSON dump is not a complete explanation.

## Common semantic distinctions

| Data | Interpretation contract | Useful next step |
| --- | --- | --- |
| Declared target | Customer-provided endpoint identity, not discovered inventory | Verify/edit permitted context; inspect profile. |
| Group / business context | Membership/shared policy versus actual declared service/criticality/owner | Inspect members; edit explicit declaration. |
| Ownership proof | Permission/scope gate, not traffic-stopping protection | Exact TXT/challenge and current verification status. |
| Compatibility | Applicable check/target kind/setup, not permission to run now | Scope-specific check preview; gate review. |
| Provider detection | Family-specific observed fingerprint/attribution, not efficacy or origin hosting | How identified opens recorded signals. |
| Provider configuration | Optional authorized integration record, with source time | Inspect own connector/rules evidence; no inferred blocking mode. |
| Check execution | Planned/running/completed/cancelled lifecycle | Selected operation/response timeline. |
| Verdict | Outcome of scoped evaluation with actual evidence | Expected vs observed and evaluation reasons. |
| Applicability / coverage | Eligible plan pairs versus evaluated/current/conclusive pairs | Inspect not-run/inconclusive/stale/excluded scope. |
| Finding | Evidence-backed issue/lifecycle at its own observation | Original proof, owner/remediation and separate retest. |
| Retest | New bounded evidence linked to original issue | Compare same target/scenario; no auto-sibling closure. |
| Score | Versioned computed summary with weights/window/unknowns | Formula/factor evidence; no broad protection guarantee. |
| Drift | Comparable observed before/after change | Side-by-side sources and scenario/version. |
| Audit | Recorded action/actor/change, not proof fix succeeded | Exact event/resource inspector. |
| Report | Generated historical snapshot | Snapshot proof/export, live remediation separately. |
| Digest / custody | Recorded hash, local computation and server verification are different | Explicit verification result/time/method. |
| Alert | Trigger event, delivery attempt, successful delivery and destination config are separate | Exact failure/attempt and own rule/channel. |
| Plan quota | Count + limit + measurement window + access source | Inspect unknown/exceeded allowance; no fake upgrade. |
| Support | Actual configured contact/coverage with context | Safe escalation draft; no unstated messages/SLA. |
| Invitation/status | Recorded access lifecycle and one-time token semantics | Correct next real stage/auth route. |

## Missing-data vocabulary

| Condition | Render / action | Never substitute |
| --- | --- | --- |
| No execution exists | Not checked / no recorded run | Passed, zero attacks, no protection. |
| Observation attempted but inconclusive | Inconclusive + reason/source | Not detected merely because result unknown. |
| Successful negative fingerprint | Not detected in this observation | Universal no-WAF assertion. |
| Historical success expired | Last observed [time], stale | Current assurance or confirmed control removal. |
| Latest attempt failed | Attempt failed, last success separate | Fresh negative/success, fake regression. |
| Source fetch failed | Unavailable/Retry; retained data labeled | No records or zero. |
| Permission denied | Access required/role boundary | Empty cohort or privileged workaround. |
| Incompatible scope | Not applicable + reason | 100% protected or failed check. |
| Backend field absent | Not recorded | Guessed value/default that looks measured. |
| No filtered matches | No matches + Clear filters | Empty workspace/Add first target. |
| Partial loaded page | Display page/count semantics and authoritative total if supplied | Loaded rows treated as estate total. |

Preserve historical facts while exposing freshness; do not erase a known old vendor identity into a blank because the latest request timed out. Do not include one host's current CDN timestamp as freshness for old origin/DNS evidence.

## Count and relationship invariants

Target record, normalized hostname, URL/service endpoint, group, catalog vector, check, check-target pair, session, child run, event, artifact, finding instance, issue group and remediation action are different units. Service roles/provider roles may overlap. Label the unit beside totals and ratios.

Every aggregate links to a collection with identical definition/filters/window. A dashboard critical gap cannot open all findings without its predicate. A report count is as-of the report, not a mixed current list. Zero applicable denominator is not a percentage. Unreachable/TLS-failed/unknown endpoints remain investigation scope, not silent exclusions.

Resolve source references by relationship, not object proximity or whichever data cache was visited last. A source run for a finding is different from latest target run. A group representative's artifact is different from selected member's artifact. A notification event is different from its delivery attempt. If explicit linkage is absent, say so and do not synthesize it.

## Context-sensitive request semantics

- Inspector reads resolve exact authorized refs and cancel/discard stale responses when selection changes.
- Edit initializes only fields the contract permits; immutable binding/value stays immutable.
- Execute requires an explicit review/intent, current ownership/scope/rate/concurrency/window/role gates, and audited outcome.
- Export is explicit, scoped and redacted; inspection does not download a file automatically.
- Retry delivery may send externally; a preview does not. Unknown attempt outcome requires reconciliation before retry.
- Support drafts retain safe references; no auto-message occurs.
- One-time secrets remain transient; navigation-state/draft persistence does not contain tokens/passwords/credentials.

## Public and subordinate flows

The retained current-release browser baseline does not exhaust every state/subflow. Current Login source also includes password-recovery request/reset modes, invitation token continuation, deployment IdP redirects and developer sign-in. Treat each as a task:

- Recovery request: provide nonsecret email, acknowledge generically as required by privacy, retain rate-limit/error context; never imply a message sent without backend confirmation.
- Reset/invitation: transient token consumed through actual contract, stripped from URL as implemented; invalid/expired/used states lead to real recovery; no token in saved return state.
- Provider setup branches, notification destinations, report preview/export and schedule creation are subordinate workspaces, not a reason to add competing sidebar nouns.
- State restoration across authentication is constrained by authorization; denied destination shows safe fallback, not silent privilege escalation.

These additional source-only modes were not newly live-tested in this addition. Implementing agents should include them in their authorized state matrix.

## Lightweight data-to-task review before page acceptance

For each prominent value/badge/list/action, record unit, source/as-of, relationships, missing semantics, intended action and actual destination. Remove a repeated metric that does not help a decision; move provenance depth to contextual inspection. Replace misleading default/empty labels with explicit uncertainty. Confirm named control specificity and Back continuity.

Use documents 19–22 plus [engineering consultation](09-engineering-consultation.md), [content budgets](14-content-and-responsive-task-budgets.md) and [acceptance](17-design-acceptance-and-handoff-gates.md). Do not build a second client-side verdict engine to make the UI convenient.
