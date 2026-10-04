# Cross-page task-flow contract

2026-10-04. Source/saved-evidence review and proposed handoff only. Preserve existing positive contextual behavior. Current paths below are representative, not measured click/time baselines for all users.

## Universal action semantics

| Intent | Preferred surface | Label / side effect |
| --- | --- | --- |
| Inspect result/provider/artifact | Inline/adjacent inspector or one drawer | View evidence / How identified; read-only. |
| Inspect named check | Contextual exact-check preview | Check name/Review; not whole library. |
| Change a few contextual fields | Inline editor or focused sheet | Edit owner/tags/context; explicit save. |
| Plan substantial work | Dedicated staged workspace | Plan validation/Edit schedule; review before execute. |
| Confirm consequential change | Focused scoped confirmation | Stop/Remove/Revoke/Accept risk with actual consequence. |
| Deep investigation/share/bookmark | Stable detail route | Open full details; context return defined. |
| Browse broad collection | Full list with actual applied cohort | View all/Review matching targets; count and filter visible. |

Rows and nested controls must not execute each other's intents. Inspect, edit, navigate and execute cannot share an ambiguous catch-all “Open.” No nested dialog chains.

## Common context envelope

Carry exact source record(s), target/group/check, selected observation/assessment, outcome/source time, caller route and permitted list state. Use the authorized customer tenant; no cross-tenant execution workflow is assigned. Carry only available verified relationships; never choose the first target/check/group by default.

Preserve search, filters, sort, page/cursor, selected row/check, expanded detail, safe draft, scroll and focus. Viewport switch should preserve identity. Server checks current permissions/gates before action; carried context is not authorization. Cold links load authoritative data independently.

## Flow table

| ID / task | Current friction / useful existing behavior | Proposed completion path | Context carried | Intent / destination |
| --- | --- | --- | --- | --- |
| TF-01 Dashboard gap | Totals often open broad lists; prioritized finding already links exact detail | Action → exact finding inspector; cohort → filtered queue with visible predicate → inspector | Finding or cohort, assessment/window, list state | Inspect/cohort navigation; no execute. |
| TF-02 Target investigation | Edge/check/step/tab areas compete; Open evidence points to run detail | Target workspace → selected outcome + supporting evidence together | Target, check/run/artifact, declared context | Inspect; full detail optional. |
| TF-03 Ownership | Group and exact-target challenge choices create extra context | Target → own challenge/TXT/copy/check status → resume same target | Exact target/challenge, expiry, prior attempted proof | Inspect/copy; Check now is explicit governed read/proof action. |
| TF-04 Run suitable check | Library requires group/target choice; contextual target run controls already exist | Target → scoped compatible plan → review bounds → Start → same work inspector | Target/group, selected check, current gates | Plan then explicit execute. |
| TF-05 Understand check | Named schedule check links general library | Named check → exact contextual purpose/applicability/evidence preview | Check ID, caller target/schedule | Inspect; library is optional browsing. |
| TF-06 Follow validation | Existing execution records split proof into internal details | Target → selected direct check → answer/trace beside check queue | Target/check/recorded operation, selected phase | Inspect/follow; Stop separate. |
| TF-07 Finding triage | Explanation/evidence partly inline; artifact/run routes still pull away | Finding row → outcome/evidence/owner/remediation → review decision or retest | Finding original evidence, exact target/check, draft | Inspect/edit; terminal decision confirm. |
| TF-08 Group findings | Group → member → finding → evidence is repeated | Group workspace → select member → adjacent evidence/triage; Next/Previous | Canonical group key, member finding/target, filter | Inspect member; no bulk success/closure. |
| TF-09 Schedule | List/detail/library/target facts split; one-off weekly patch | Schedule → editor scope/check/time/timezone/next dispatch/blockers → review/save | Policy IDs, immutable bindings, caller filters | Inspect/edit; dispatch remains separate. |
| TF-10 Provider setup | Read-only/manual/single-domain branches repeat across entry points | Select provider/mode once → requirements → configuration → real validation result | Provider capability/mode, connector, safe draft | Configure explicitly; inspect does not poll/save. |
| TF-11 Alerts | Channels in Integrations; routing/failures in Notifications | Rule setup → select/create destination in context → resume rule; failed attempt → failure + exact channel context | Rule/channel/attempt/trigger, nonsecret draft | Edit/inspect; retry sends only explicitly. |
| TF-12 Report | Builder begins audience/format; context from caller can be lost | From current scope → preview audience/evidence window → export; estate-wide mode explicit | Target/group/cohort, snapshot/window, exclusions | Plan/preview; export separate action. |
| TF-13 Audit | Ledger already selects inline metadata; Support View is broad | Event link → select exact event in ledger/inspector with recorded change | Event/resource/actor/time, origin route | Inspect; not an infrastructure operation. |
| TF-14 Support | View opens audit broadly | Contextual escalation draft with refs → actual configured channel; View selects exact event | Target/check/finding/event refs, safe notes | Draft/navigate; sending only explicit. |
| TF-15 Settings | Long tabbed workflows and technical facts mixed | Choose task → local editor and save/result → return same tab | Tenant, credential/retention identity, safe drafts | Edit/confirm; secrets not persisted. |
| TF-16 Public access | Request/status/invitation/login are separate, but current signup already passes ID and invitation preloads/strips token | Confirmation → ID-prefilled status → recorded next step → invite/password → intended sign-in | Nonsecret request reference; invitation transient secret only | Inspect/activate intentionally; production auth unchanged. |
| TF-18 Recovery | Missing entity/route can reset to broad home | Explain missing/denied/expired separately → caller context or authorized canonical parent | Requested safe reference, origin state | Navigate recovery; never infer healthy facts. |

## Return, states and task acceptance

| Flow IDs | Back/Close must restore | Loading / missing / permission behavior | Completion check |
| --- | --- | --- | --- |
| TF-01–02 | Same dashboard/cohort/list selection and scroll | Region loading; evidence failure/absence distinct; read gate | Exact gap proof in one action; unknown stays unknown. |
| TF-03–04 | Target and planned scope/checks; no group reselection | Pending/expired proof, incompatibility, concurrency/rate gates visible | Launch flow starts with caller target; only current permitted bounds execute. |
| TF-05 | Same schedule/catalog/target and safe form | Missing check gives exact-ID recovery, not first check fallback | Click named check → same check preview/detail. |
| TF-06 | Same selected step/trace/queue position | Pending evaluation, disconnect, unavailable source distinct | No mandatory internal-record navigation to understand a result. |
| TF-07–08 | Finding/group filter, selected member, safe unsaved triage | Original proof missing/denied explicit; no sibling substitution | Primary evidence one action; Next/Previous preserves member identity. |
| TF-09 | Schedule list filters/page; editor draft | Missing timing/contract vs read error; edit permissions | Scope/check/time/next gate understood without library detour. |
| TF-10–11 | Selected provider/mode or unfinished rule | Setup failures retain nonsecret state; credentials not stored; outbound disabled explained | Finish setup without restarting another form; failed attempt opens own configuration. |
| TF-12 | Scope and preview options; report list | Snapshot metadata unavailable not silently current; export permission | Preview/export keeps intended scope/window. |
| TF-13–14 | Exact audit/list or escalation draft | Event denied/missing and contact unconfigured distinct | View exact event; support carries references without auto-send. |
| TF-15 | Current tab/task, safe edits | Dirty/busy authoritative outcome, role boundary | Save/revoke consequence clear without losing context. |
| TF-16 | Request reference/intended authorized destination | Lookup error/rate limit; invalid/expired invite/auth modes | Current ID-prefill/token stripping preserved; next real stage explained. |
| TF-18 | Authorized origin/filter where available | 404/403/auth expiry/network distinguished | No dead-end/loop/default healthy record. |

## Engineering prerequisites

Shared evidence resolver/inspector and navigation-state policy before per-page wiring. Define deep-link/filter parameters and corresponding list APIs; a proposed URL parameter is not already supported. Contextual schedule/provider/notification/report forms need explicit initialize/resume schemas, server-side validation and no stale-selected target.

Preserve read-only routes for deep investigation. Remove only redundant navigation, not security review stages or actual evidence checks. Avoid central global state that leaks context across tenant/role; restore by scoped stable identities.

## Priority

Shared evidence inspector → exact destinations/context propagation → unified target/direct-check/group investigation → restore state → forms/report/support continuity → visual finishing. Reference/mockup and contract preparation still precedes implementation; this changes emphasis among implementation slices, not current authorization.

Link to [inspector](19-contextual-evidence-inspector.md), [all-page data review](21-all-page-data-and-task-review.md), [link audit](22-contextual-link-and-source-audit.md), [feedback](16-feedback-responsiveness-and-daily-use.md), and [acceptance](17-design-acceptance-and-handoff-gates.md).
