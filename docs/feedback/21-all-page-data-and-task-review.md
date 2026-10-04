# All-page data-to-decision and task review

2026-10-04. Covers all 28 current-release page families using current source plus saved browser evidence. **No new live all-page click-through, user study, code, traffic, provider access or data change occurred.** Navigation/deep-link defects specifically confirmed in source are listed in document 22; broader paths below are qualitative reviews, not measured step counts.

## Review lens

For each page: what question is the user answering, which data supports that answer, what action follows, and what must remain in context? Targets/checks/runs/scans/artifacts are backend identities; user tasks are investigation, verification, validation, remediation and reporting.

Answer and primary supporting evidence should be together. Do not simply move the same navigation chain into four mandatory tabs. Preserve optional full detail/bookmark/export routes and deliberate execution/governance review.

Cross-cutting [data meaning](23-data-meaning-and-workflow-state-contract.md), [inspector](19-contextual-evidence-inspector.md), [task flow](20-cross-page-task-flow-contract.md) and [source audit](22-contextual-link-and-source-audit.md) control implementation.

## Page ledger

| Page | User's decision | Review |
| --- | --- | --- |
| Dashboard | Identify the most important current gap and supporting proof. | [dashboard](dashboard.md) |
| Targets | Find one declared endpoint and finish its next ownership/validation task. | [targets](targets.md) |
| Target groups | Compare declared groups and inspect member gaps. | [target-groups](target-groups.md) |
| Target group detail | Verify/manage members and plan one bounded group or target validation. | [target-group-detail](target-group-detail.md) |
| Target detail | Understand protection and investigate a result without object hopping. | [target-detail](target-detail.md) |
| Vector library / check library | Understand a vector/check and select valid work for current scope. | [checks](checks.md) |
| Check detail | Explain one named check in caller target or schedule context. | [check-detail](check-detail.md) |
| Test policies / validation schedules | Edit schedule scope and timing without reconstructing bindings. | [test-policies](test-policies.md) |
| Validation schedule detail | Understand when a schedule dispatches and resolve its blocker. | [policy-detail](policy-detail.md) |
| Findings queue | Prioritize observed gaps and inspect proof before triage. | [findings](findings.md) |
| Finding detail and remediation | Decide remediation/risk using original proof. | [finding-detail](finding-detail.md) |
| Grouped finding detail | Compare each affected target without repeated navigation. | [finding-group-detail](finding-group-detail.md) |
| Evidence artifact detail | Inspect/share one artifact and understand integrity. | [evidence-detail](evidence-detail.md) |
| Reports | Preview intended scope before exporting. | [reports](reports.md) |
| Report detail | Read historical result and its evidence in context. | [report-detail](report-detail.md) |
| Integrations | Finish chosen optional provider/channel setup in one flow. | [integrations](integrations.md) |
| Notifications | Understand a delivery failure and correct its own routing. | [notifications](notifications.md) |
| Audit log | Inspect exact recorded action without searching another page. | [audit](audit.md) |
| Release evidence (auditor) | Explain a specific release gate and supporting artifact. | [release-evidence](release-evidence.md) |
| Settings | Complete one account/security change with local feedback. | [settings](settings.md) |
| Support | Escalate exact investigation or open its related event. | [support](support.md) |
| Plan & usage / Billing | Understand current plan limit/access and permitted next step. | [subscription](subscription.md) |
| Public landing | Understand outside-in value and enter correct flow. | [landing](landing.md) |
| Customer sign-in | Sign in through actual deployment auth and resume authorized intent. | [login](login.md) |
| Request access | Request reviewed access and keep returned reference. | [signup](signup.md) |
| Access request status | Know recorded stage and next permitted step. | [signup-status](signup-status.md) |
| Invitation password setup | Activate valid invitation with clear token/password handling. | [set-password](set-password.md) |
| Missing or unavailable route | Recover without concealing the requested context. | [not-found](not-found.md) |

## Per-page task contracts

### 1. Dashboard

| Contract | Requirement |
| --- | --- |
| Decision / intended outcome | Identify the most important current gap and supporting proof. |
| Data and interpretation | Published readiness/factors, declared target counts, current open findings, evidence coverage, recent runs, WAF summary. Label score formula/window, target versus group versus finding units, and unknown/stale coverage. |
| Current path / context | Metric often opens broad collection; priority links already resolve exact finding; run/posture rows navigate entity detail. |
| Proposed continuation | Single gap opens exact finding/evidence inspector; aggregate opens matching visible cohort; running work opens selected active session. |
| Carry automatically | Finding or cohort predicates, assessment/window/as-of, target IDs, caller state. |
| Back / Close restores | Same dashboard tab/metric/cohort, selection and scroll; no automatic reorder. |
| Loading / missing / permission | Partial rollup error preserves other data; no evidence is unmeasured; read-only users inspect without Run. |
| Task acceptance | A critical-gap activation exposes the right finding/proof or exact cohort; visible totals and list reconcile. |

### 2. Targets

| Contract | Requirement |
| --- | --- |
| Decision / intended outcome | Find one declared endpoint and finish its next ownership/validation task. |
| Data and interpretation | Exact identity/kind, tags/group, ownership, source/added time. Ready count currently equals total; missing validation time is not confirmed Never. WAF/CDN columns require actual projection. |
| Current path / context | Search/filter → target detail; row tag/remove controls; adding already opens created target. |
| Proposed continuation | Select target opens useful profile; Verify opens its own proof; scoped validation starts from that target; correct current behavior retained. |
| Carry automatically | Target/group/ownership challenge IDs; filters/sort/page; safe tag draft. |
| Back / Close restores | Same filtered row/page/scroll; deleted target gets contextual fallback. |
| Loading / missing / permission | No inventory vs no matches vs read error distinct; pending ownership cannot look runnable. |
| Task acceptance | Pending target Verify shows its own TXT; returning retains filters and exact target. |

### 3. Target groups

| Contract | Requirement |
| --- | --- |
| Decision / intended outcome | Compare declared groups and inspect member gaps. |
| Data and interpretation | Name/ID, declared criticality/owner when present, membership, proof rollup, runs/findings/latest verdict. Group pass does not establish all-member coverage. |
| Current path / context | Group table → group detail → targets/checks/evidence; IDs can lead names. |
| Proposed continuation | Select group opens member overview; gap count opens scoped member findings; group settings edited in context. |
| Carry automatically | Group ID, member cohort, explicit proof/evidence window and inheritance. |
| Back / Close restores | Group filters/page/selection; member inspector closes within group. |
| Loading / missing / permission | Archived group/missing membership/partial reads explicit; absent business facts not invented. |
| Task acceptance | Group gap count opens exact matching findings, not all tenant findings; member proof independent. |

### 4. Target group detail

| Contract | Requirement |
| --- | --- |
| Decision / intended outcome | Verify/manage members and plan one bounded group or target validation. |
| Data and interpretation | Member identity/proof/expected behavior/edge observations, LOA, safe settings, schedules and run rules. Separate group authorization from per-target eligibility. |
| Current path / context | Proof ladder/TXT selector, target table, rule choices and scan launch coexist; import dialogs already scoped. |
| Proposed continuation | Keep member selection; own TXT and check plan beside row; staged launch inherits explicit group/target; import preview remains local. |
| Carry automatically | Group/member/challenge, compatible chosen rule, plan/exclusions; optional connector selection. |
| Back / Close restores | Member selection/expanded proof, group list origin and safe import/plan draft. |
| Loading / missing / permission | Empty group, unknown detection, expired TXT, import rejection, current execution gates. |
| Task acceptance | Selecting Verify on a member requires no repeated hostname selection; exact scope stays visible before start. |

### 5. Target detail

| Contract | Requirement |
| --- | --- |
| Decision / intended outcome | Understand protection and investigate a result without object hopping. |
| Data and interpretation | Exact target, proof/tags, WAF/CDN/cloud source, efficacy/check status, recent runs/findings and declaration facts. Independent family sources and untested dimensions. |
| Current path / context | Competing protection/steps/checks/tabs; Open evidence goes to an internal result-record detail page. |
| Proposed continuation | One target workspace with summary/priority and selected-check evidence beside outcome; Run review preselects exact target. |
| Carry automatically | Target/check/run/observation/artifact references and original-versus-latest finding context. |
| Back / Close restores | Same tab/check/category/expanded detail/scroll; no switch to newest result. |
| Loading / missing / permission | Ownership pending, source error, unknown/stale, not applicable, open finding after later pass. |
| Task acceptance | Open evidence reveals recorded operation/response/evaluation in one action; full run route optional. |

### 6. Vector library / check library

| Contract | Requirement |
| --- | --- |
| Decision / intended outcome | Understand a vector/check and select valid work for current scope. |
| Data and interpretation | 721 vectors versus runnable mapped checks, capabilities/E-tiers, target dispositions, required setup and safety bounds. Counts are separate. |
| Current path / context | Group then target selectors and taxonomy filters; Review already offers contextual vector detail. |
| Proposed continuation | Preserve useful Review; caller target retained; exact-check preview explains purpose/fit/limits; full taxonomy optional. |
| Carry automatically | Vector/check IDs, explicit caller target/group, search/pagination and mapping version. |
| Back / Close restores | Catalog query/page/filters and safe planned checks. |
| Loading / missing / permission | Missing map, no compatible target, declaration-only, restricted/monitor-only, required input. |
| Task acceptance | Review identifies actual mapped check and evidence limit; target-launch preview never reselects scope. |

### 7. Check detail

| Contract | Requirement |
| --- | --- |
| Decision / intended outcome | Explain one named check in caller target or schedule context. |
| Data and interpretation | Purpose/profile, applicability/setup, bounds, expected/evaluation logic, exact-check linked history/policies. A latest check result needs target/time. |
| Current path / context | Detailed catalog facts and links to schedules/library; unavailable ID has recovery. |
| Proposed continuation | Exact-check preview beside caller, schedule/launch with caller scope; detail remains shareable depth. |
| Carry automatically | Check ID/version, target if specified, policy or catalog return context. |
| Back / Close restores | Same named schedule/target/catalog query; no library reset. |
| Loading / missing / permission | Unknown/removed check, incompatible kind, missing setup, denied start; read metadata if allowed. |
| Task acceptance | Click a schedule check opens that check, with caller scope, not the library homepage. |

### 8. Test policies / validation schedules

| Contract | Requirement |
| --- | --- |
| Decision / intended outcome | Edit schedule scope and timing without reconstructing bindings. |
| Data and interpretation | Schedule/check/target/group, enabled state/cadence/next time/window/expectation, declared timing vs actual dispatch. Missing next run is not imminent execution. |
| Current path / context | List links group/target; named check points to general checks; weekly patch/pause/archive; create modal has scope selection. |
| Proposed continuation | One schedule editor with bindings/check preview/timing/timezone/blockers; scoped actions keep row; exact check destination. |
| Carry automatically | Policy ID, immutable binding, current fields/version, caller filters and safe draft. |
| Back / Close restores | Schedule list state/selected row; edit errors retain timing choices. |
| Loading / missing / permission | Missing timing/check, partial multi-create, paused, not editable, rate/window/authorization gates. |
| Task acceptance | Edit shows correct target/check/timezone and next eligible fact; named-check preview preserves editor. |

### 9. Validation schedule detail

| Contract | Requirement |
| --- | --- |
| Decision / intended outcome | Understand when a schedule dispatches and resolve its blocker. |
| Data and interpretation | Immutable target/check binding, cadence/state, recorded next time/window, dispatch gates/history. Configuration proof is not execution proof. |
| Current path / context | Binding/schedule/gate/history panels; return to list for management. |
| Proposed continuation | Task editor with exact-check preview and target context; dispatch history outcome inspector; deep page retained. |
| Carry automatically | Policy/check/target, source timing, selected dispatch and safe draft. |
| Back / Close restores | Same policy section/list filters; no automatic target substitution. |
| Loading / missing / permission | 404 schedule, missing gate data, read-only role, edit conflict; no default Active for absent record. |
| Task acceptance | Find concrete next-run blocker and open linked check evidence without navigating general catalog. |

### 10. Findings queue

| Contract | Requirement |
| --- | --- |
| Decision / intended outcome | Prioritize observed gaps and inspect proof before triage. |
| Data and interpretation | Finding instances versus issue groups versus targets; severity/lifecycle/owner/SLA, original evidence/time and later retest. Missing SLA not guessed. |
| Current path / context | Grouped list → member/detail → evidence/artifact routes; filters/row context useful. |
| Proposed continuation | Finding action opens outcome/evidence inspector; group selects member beside list; scoped triage/retest. |
| Carry automatically | Finding/group/member target, original run/artifact, queue filters and safe notes. |
| Back / Close restores | Same lifecycle/severity/owner/cohort/sort/page/selection. |
| Loading / missing / permission | No matches, no open findings, stale/partial source, accepted risk distinct from resolved. |
| Task acceptance | Finding row primary proof one action; group counts reflect exact current filter and membership. |

### 11. Finding detail and remediation

| Contract | Requirement |
| --- | --- |
| Decision / intended outcome | Decide remediation/risk using original proof. |
| Data and interpretation | Original gap/reason/evidence, latest validation separately, target/owner/SLA/triage/remediation/retest lineage and integrity. |
| Current path / context | Inline explanation/triage and evidence bundle already present; source-run/artifact links pull away. |
| Proposed continuation | Outcome and supporting evidence co-located, owner/remediation nearby; full artifact optional; retest review retains scope. |
| Carry automatically | Finding/target/check/original evidence, remediation membership, safe notes and latest result separately. |
| Back / Close restores | Queue/member selection and unsaved nonsecret triage; drawer does not discard edits. |
| Loading / missing / permission | Contradictory new pass, evidence fetch error vs no refs, denied triage, partial retest. |
| Task acceptance | Inspect originating proof without leaving finding; retest shows exact scope/current bounds before start. |

### 12. Grouped finding detail

| Contract | Requirement |
| --- | --- |
| Decision / intended outcome | Compare each affected target without repeated navigation. |
| Data and interpretation | Canonical group key, members/targets/lifecycle/severity/owners/evidence; representative is not every member. |
| Current path / context | Lead finding for full proof; member finding links lead to another route. |
| Proposed continuation | Select affected member updates adjacent outcome/evidence/triage; Next/Previous traverses current member cohort. |
| Carry automatically | Group key/filter and exact member finding/target/source IDs. |
| Back / Close restores | Same group member/order/filter/scroll; removed member fallback explained. |
| Loading / missing / permission | Mixed outcomes, absent member refs, denied record, unavailable group; no sibling evidence. |
| Task acceptance | Next/Previous shows correct source for each member; one pass cannot resolve siblings. |

### 13. Evidence artifact detail

| Contract | Requirement |
| --- | --- |
| Decision / intended outcome | Inspect/share one artifact and understand integrity. |
| Data and interpretation | Artifact type/size/source run, available content/metadata, recorded digest and actual recomputation/verification state. Metadata-only not corruption. |
| Current path / context | Standalone artifact; return can reference absent Evidence vault concept. |
| Proposed continuation | Optional expansion of inspector; exact source summary and correct contextual Back; verification/export explicit. |
| Carry automatically | Artifact/source finding/run, origin inspector selection and permitted snapshot. |
| Back / Close restores | Origin inspector/list, or canonical source route on cold load. |
| Loading / missing / permission | Expired/denied/no preview vs failed fetch; recorded hash not verified. |
| Task acceptance | Artifact bookmarked alone resolves correctly; Back returns to investigation, not removed vault alias. |

### 14. Reports

| Contract | Requirement |
| --- | --- |
| Decision / intended outcome | Preview intended scope before exporting. |
| Data and interpretation | Audience/kind/period/format, persisted reports and integrity evidence. Framework mapping is not certification. |
| Current path / context | General form audience/format precedes scope content; Generate & export primary. |
| Proposed continuation | Caller scope initialized in preview, explicit estate-wide choice, then review/export; report title leads history. |
| Carry automatically | Target/group/cohort, snapshot/window/source refs and audience, safe preview choices. |
| Back / Close restores | Same originating target/cohort or report list/preview options. |
| Loading / missing / permission | Unsupported format, unavailable scope, read-only export, partial source; no silent estate-wide fallback. |
| Task acceptance | Preview/export reflect caller scope; export is explicit and avoids silently broadening target report. |

### 15. Report detail

| Contract | Requirement |
| --- | --- |
| Decision / intended outcome | Read historical result and its evidence in context. |
| Data and interpretation | Report snapshot score/factors/findings/captured runs/time, export state and live linked state separately. |
| Current path / context | Summary/export/custody/factor/coverage panels; linked records can scatter snapshot evidence. |
| Proposed continuation | Snapshot answer/evidence inspector with context; one export menu; current remediation clearly separate. |
| Carry automatically | Report snapshot/ref IDs, selected finding/run, caller list. |
| Back / Close restores | Same report section/selection; full artifact returns to snapshot. |
| Loading / missing / permission | Missing historical data, newer live status, verification unavailable, export denied. |
| Task acceptance | Primary report evidence preserves historical observation, not latest run; live status never rewrites report. |

### 16. Integrations

| Contract | Requirement |
| --- | --- |
| Decision / intended outcome | Finish chosen optional provider/channel setup in one flow. |
| Data and interpretation | Implemented provider capability/mode, connector credential reference/validation/snapshot/time, channel config/delivery/opt-in status. Configured not working. |
| Current path / context | Multiple provider entry branches and directory plus channels; setup guides/dialogs already contextual. |
| Proposed continuation | Choose provider/mode once; requirements/configuration/result in same flow; rule-created channel returns to unfinished routing. |
| Carry automatically | Provider/mode/connector/channel IDs, safe nonsecret form state, caller rule. |
| Back / Close restores | Same directory row/provider or rule editor; do not persist secrets. |
| Loading / missing / permission | Manual-only, feature denied, credential invalid, sync failure, no attempt, outbound disabled. |
| Task acceptance | Validation result names same provider/mode; notification destination created in context resumes rule without restart. |

### 17. Notifications

| Contract | Requirement |
| --- | --- |
| Decision / intended outcome | Understand a delivery failure and correct its own routing. |
| Data and interpretation | Rules/triggers/destination preview, event vs attempt, provider health/retry/DLQ, config versus sent state. |
| Current path / context | Rules here, channels elsewhere; inline New rule; preview/live batch controls. |
| Proposed continuation | Rule editor can inspect/select channel in place; failure opens exact attempt and relevant channel/config with resume. |
| Carry automatically | Rule/channel/event/attempt IDs, triggers, safe draft and affected retry scope. |
| Back / Close restores | Same failure/rule filter and draft; Cancel makes no delivery. |
| Loading / missing / permission | No attempt vs disabled vs failure, retry uncertainty, permission/config gates. |
| Task acceptance | Failed delivery activation shows reason and exact destination config; explicit retry does not duplicate unknown outcome. |

### 18. Audit log

| Contract | Requirement |
| --- | --- |
| Decision / intended outcome | Inspect exact recorded action without searching another page. |
| Data and interpretation | Event time/actor identity/role/resource/metadata/hash. Audit decision not proof fix applied. |
| Current path / context | Existing row selection renders metadata drilldown; external support View arrives unfiltered. |
| Proposed continuation | Preserve inline inspector; accept exact incoming event/resource/time selection; recorded change plus context/evidence. |
| Carry automatically | Event/resource IDs, actor/time, safe caller filters. |
| Back / Close restores | Same ledger query/date/sort/page/row/scroll. |
| Loading / missing / permission | No events/no matches, missing event ID, sensitive resource redaction and denied access. |
| Task acceptance | Support View selects actual event; row inspection never requires a second search or unverifiable change claim. |

### 19. Release evidence (auditor)

| Contract | Requirement |
| --- | --- |
| Decision / intended outcome | Explain a specific release gate and supporting artifact. |
| Data and interpretation | Release/profile evidence inventory, acceptance/schema/integrity/external signoff distinctions and missing kinds. |
| Current path / context | Gap ledger and inventory/attestation separate; truncated missing-kind summary. |
| Proposed continuation | Select gate opens requirement/source/invalid reason/action beside ledger; complete gap list available. |
| Carry automatically | Release/profile/kind/artifact/attestation version and source scope. |
| Back / Close restores | Same ledger filter/selected requirement. |
| Loading / missing / permission | Accepted invalid artifact, absent external signoff, missing kind vs unavailable read. |
| Task acceptance | Selecting invalid accepted artifact shows why it fails; no metadata validity becomes customer launch approval. |

### 20. Settings

| Contract | Requirement |
| --- | --- |
| Decision / intended outcome | Complete one account/security change with local feedback. |
| Data and interpretation | Tenant identity/session facts, service-account scope/status, vault metadata, retention units/impact; one-time secret vs stored list. |
| Current path / context | Four tabs with task forms and technical facts; sensitive confirmation/output source-inspected. |
| Proposed continuation | Task-focused local editor/result; related audit context can open inspector; preserve safe drafts between sections. |
| Carry automatically | Tenant/task/credential identity, scopes/expiry/retention and safe fields. |
| Back / Close restores | Same tab/task after audit/inspection; do not restore secrets from storage. |
| Loading / missing / permission | Dirty/busy/error, expired/revoked key, missing tenant, read-only mutation, retention consequence. |
| Task acceptance | Save/revoke/rotate shows authoritative own object result and clear impact without page reset. |

### 21. Support

| Contract | Requirement |
| --- | --- |
| Decision / intended outcome | Escalate exact investigation or open its related event. |
| Data and interpretation | Configured owner/contact and coverage, subscription-derived counts/as-of, recent event references. Contact not configured is real limitation. |
| Current path / context | Individual View opens the general audit ledger without its event context. |
| Proposed continuation | Current target/check/finding references prefilled in support draft; View resolves its own event. |
| Carry automatically | Safe target/run/finding/event refs, declared scope, nonsecret notes, actual configured channel. |
| Back / Close restores | Same investigation/draft and originating list context. |
| Loading / missing / permission | Unconfigured contact, stale counts, inaccessible event; no auto-message or fabricated SLA. |
| Task acceptance | View opens selected event; escalation retains refs and only sends after explicit authorized action. |

### 22. Plan & usage / Billing

| Contract | Requirement |
| --- | --- |
| Decision / intended outcome | Understand current plan limit/access and permitted next step. |
| Data and interpretation | Plan/contract/effective dates, usage window/count/limit, entitlement source; unknown usage not 0/unlimited. |
| Current path / context | Read-only plan/usage and grant source; no payment workflow. |
| Proposed continuation | Inspect metric/entitlement explanation in context; configured plan/support destination with account refs. |
| Carry automatically | Tenant/plan/feature/usage window/as-of; caller account task. |
| Back / Close restores | Same plan section; external contact only intentionally. |
| Loading / missing / permission | Usage unavailable/exceeded, add-on disabled vs no observation, renewal unknown. |
| Task acceptance | User explains actual remaining/unknown usage and feature availability without mistaking it for configured protection. |

### 23. Public landing

| Contract | Requirement |
| --- | --- |
| Decision / intended outcome | Understand outside-in value and enter correct flow. |
| Data and interpretation | Product promise, illustrative verdict fields/demo, current direct-check scope and evidence boundaries. No customer metrics inferred from illustration. |
| Current path / context | Marketing sections and request/login/demo links; implementation keys in example. |
| Proposed continuation | Human workflow/outcome example, distinct Request access/Login/Demo; no object taxonomy needed. |
| Carry automatically | Chosen intent and safe desired destination; demo clearly synthetic. |
| Back / Close restores | Return to meaningful landing section; production sign-in not replaced with demo. |
| Loading / missing / permission | Intake disabled, auth config unknown, missing public contact. |
| Task acceptance | Visitor chooses actual access/demo path and understands no required credentials or automatic discovery. |

### 24. Customer sign-in

| Contract | Requirement |
| --- | --- |
| Decision / intended outcome | Sign in through actual deployment auth and resume authorized intent. |
| Data and interpretation | Auth mode/role only developer lanes, credential/IdP/recovery state and safe return destination. |
| Current path / context | Production/developer modes; recovery subflows exist; current source exceeds old screenshot baseline. |
| Proposed continuation | Mode-specific entry with preserved safe destination; concise recovery, no role selection in production. |
| Carry automatically | Allowlisted intended route/entity and nonsecret email; transient credentials only. |
| Back / Close restores | Back/recovery returns same sign-in intent safely; no dead redirect loop. |
| Loading / missing / permission | Expired session, auth discovery outage, invalid credential, blocked access, rate limit. |
| Task acceptance | After authorized login requested entity is restored if permitted; unsafe/denied destination has clear fallback. |

### 25. Request access

| Contract | Requirement |
| --- | --- |
| Decision / intended outcome | Request reviewed access and keep returned reference. |
| Data and interpretation | Organization/contact/plan/region/use and review state, returned request ID. Requested plan not entitlement. |
| Current path / context | Current confirmation already links status with ID; form can hydrate submitted reference. |
| Proposed continuation | Preserve ID-prefilled confirmation/status, clearer real next stage/recovery; only request missing fields. |
| Carry automatically | Nonsecret request ID and safe submitted summary; no invented activation/invite. |
| Back / Close restores | Back to submitted confirmation or intended sign-in; no duplicate intake from retry. |
| Loading / missing / permission | Intake disabled, validation/read error, rate limit, submitted not active. |
| Task acceptance | Check status from confirmation never requires typing ID again; submission not portrayed as active account. |

### 26. Access request status

| Contract | Requirement |
| --- | --- |
| Decision / intended outcome | Know recorded stage and next permitted step. |
| Data and interpretation | Request ID/review/provisioning/invitation status and safe public fields. Stage/date only when returned. |
| Current path / context | Query-ID trim and automatic lookup already supported; manual field fallback. |
| Proposed continuation | Keep reference continuity; readable lifecycle/next action and configured lost-reference recovery. |
| Carry automatically | Request ID nonsecret within allowed privacy; status source time. |
| Back / Close restores | Same request after login/back or retry; no secret token persistence. |
| Loading / missing / permission | Not found versus failed lookup/rate limited; status privacy and no invented ETA. |
| Task acceptance | Existing ID link loads correct request; approved/provisioned/invited/active meanings distinguished. |

### 27. Invitation password setup

| Contract | Requirement |
| --- | --- |
| Decision / intended outcome | Activate valid invitation with clear token/password handling. |
| Data and interpretation | Transient invitation token/account context where authorized, password requirements and one-time activation outcome. |
| Current path / context | Token query prefilled and stripped already; manual token fallback; password fields and feedback. |
| Proposed continuation | Preserve safe token handling; local requirements/errors and authoritative activation next step. |
| Carry automatically | Transient token in memory only; nonsecret desired auth destination. |
| Back / Close restores | Invalid/expired flow reaches real recovery; no password/token restored from persistent draft. |
| Loading / missing / permission | Used/expired/invalid invite, policy/confirm error, uncertain submission and success. |
| Task acceptance | Valid link does not require retyping token; secret removed from URL and never in saved navigation state. |

### 28. Missing or unavailable route

| Contract | Requirement |
| --- | --- |
| Decision / intended outcome | Recover without concealing the requested context. |
| Data and interpretation | Unknown route/entity, denied access and expired auth are different; no record inference. |
| Current path / context | Unknown hash explicit state; some role gates redirect with notice. |
| Proposed continuation | Explain reason; offer authorized caller/list/entity parent and retain safe intent where useful. |
| Carry automatically | Safe requested route/entity/return ref; no secret URLs. |
| Back / Close restores | Original authorized filter/list if possible, canonical home on cold unknown link. |
| Loading / missing / permission | 404/403/auth/network differentiated; stale/deleted row fallback. |
| Task acceptance | Recovery does not silently show healthy/default entity or erase all investigation context. |
