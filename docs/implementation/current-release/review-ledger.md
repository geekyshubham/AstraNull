# Independent review and failure ledger

## Uncommitted-change review (2026-10-04)

The checkout initially contained only untracked current-release files. Matching tracked changes are in `stash@{0}`, and a later complete candidate exists in the `current-release-recovery` worktree. The user subsequently instructed Codex to fix whatever is failing. The full matching candidate was restored into the primary checkout, preserving the stash, recovery worktree, and the initial checkout backup at `/tmp/astranull-review-original-backup`. Final checks run against this restored checkout with the review fixes included.

| ID | Finding | Status / evidence |
| --- | --- | --- |
| REVIEW-01 | Two simultaneous observation inserts could raise unique violation, then issue a lookup in an aborted transaction (`25P02`). | Fixed using `ON CONFLICT DO NOTHING`, re-reading the winner, and validating every matching identity. Real Postgres regression proves identical requests replay and different requests sharing a nonce return 409 while the surrounding transaction remains usable. |
| REVIEW-02 | Concurrent creates of the same active origin binding or retest lineage could fail with a unique violation. The initial checkout also replayed a binding with a different scope. | Fixed with conflict-safe insertion and exact scope/pair checks. The app-role regression verifies one binding, one audit, exact timestamp preservation, scope conflict, and one immutable retest intent. `tests/integration/current-release-history-concurrency.test.mjs`: 5/5, zero skips. |
| REVIEW-03 | A failed inspector legacy-record fallback stored `refKey` instead of the scope-qualified `loadKey`, so the renderer kept showing loading instead of the error. | Fixed in `evidence-inspector.tsx`. The browser regression verifies that a legacy fallback returning 503 displays Evidence unavailable, exits loading, retries successfully, and issues no mutating request. |
| REVIEW-04 | New frontend components reference absent exports and AbortSignal support; backend tests require absent API/service integration. | Fixed by restoring the matching tracked wiring and latest new files. The primary checkout now passes typecheck, lint, portal lint, safety, production build, and 9 strict contracts. Final full-suite verification follows below; historical recovery results are not used to certify the latest fixes. |

| REVIEW-05 | The findings HTTP controller silently discarded unknown query parameters and duplicate filters instead of rejecting them. | Fixed at the HTTP boundary. The integration regression checks unknown, internal `client`, and repeated parameters (including a repeated blank), verifies 400 with the exact field, and proves no list read occurs for rejected queries. |
| REVIEW-06 | Declaration and origin-binding chronology used millisecond timestamps despite six-digit retained history. A preceding observation could be accepted within the same millisecond. | Fixed using normalized UTC timestamps at microsecond precision. Regressions cover observation and completion before declaration/binding, an exact boundary, and the future-skew boundary. |
| REVIEW-07 | Postgres customer finding patches forwarded server fields, allowing a note edit to set or clear `closed_at` or rewrite evidence/verdict references. | Fixed with the documented status/assignee/notes boundary. The app-role writer regression verifies that malicious server fields are ignored, closure is server-stamped, and a note edit cannot erase an existing closure. |



| REVIEW-08 | The default Node runner used all reported CPUs, making wall-clock performance gates fail from competing test files. | Fixed by serializing files in `npm test`, `test:unit`, and the Make unit/integration targets. The 1,500/2,000 ms grouping budgets and all race assertions remain unchanged. Explicit parallelism inside concurrency regressions is preserved. |

## Final verification in the primary checkout

**Review complete.** The final ordinary `npm test` command passes **4,764/4,764** (4,325 first-lane cases and 439 integration cases), zero failures, cancellations or skips. `/tmp/astranull-review-final-npm-serial.log`. All REVIEW-01 through REVIEW-08 findings above are resolved and regression-verified. The original stash and recovery worktree remain intact.

- Full Node test inventory, with both lanes serialized: **4,764 passed** (4,325 unit/Node E2E/provenance cases and 439 integration cases), zero failures, cancellations, or skips. `/tmp/astranull-review-final-serial.log`.
- Full Chromium browser/a11y suite with the DOM scale case enabled: **360/360 passed**, zero skips, 10.8 minutes. `ASTRANULL_PORTAL_SCALE=1 npm run test:portal-playwright`; `/tmp/astranull-review-browser.log`.
- Scale checks: **14/14 passed**, zero skips, including real Postgres with 100,000 findings and 10,000 target groups. `/tmp/astranull-review-scale.log`.
- Strict contracts: **9/9 passed**, zero skips. `/tmp/astranull-review-final-contract.log`.
- Typecheck, repository lint, portal lint, safety, production build, and staged whitespace check passed. `/tmp/astranull-review-final-build.log` contains the rebuilt production assets.
- Concurrent verification attempts are retained in `/tmp/astranull-review-final-full.log` and `/tmp/astranull-review-final-node.log`: timing failures and intermittent service-account HTTP failures occurred there; the unchanged performance and HTTP checks passed in isolation and in the complete serial run. No test thresholds or assertions were relaxed. A repeat of the original ordinary command reproduced the same two grouping timing failures without the browser running. The default test command now serializes files; its final ordinary `npm test` result is 4,764/4,764, zero failures or skips.

G1 visual approval, G3 usability research, and production release signoff remain separate from this code review and local commit.

Historical implementation-wave review follows. Its preliminary statuses are retained as a work record; the current review and final verification above supersede them.

Review in progress. Findings below are against landed code and must be rechecked after the owning worker finishes; partial code is not a completed feature.

| ID | Owner / file | Observation / required invariant | Status / evidence |
| --- | --- | --- | --- |
| BASE-01 | Grok baseline / waf-posture-api.test.mjs | Seven existing connector-create integration failures. Fix stale fixture if contract correct; preserve gates. | Assigned, baseline-tests.log |
| NAV-01 | Claude foundation / lib/nav-state.mjs | `filters` accepts arbitrary regex-valid keys, rather than a fixed allowlist. Navigation persistence must exclude arbitrary metadata and credentials; enumerate supported filter keys and test unknown/secret keys. | Open preliminary review |
| NAV-02 | Claude foundation / lib/evidence-inspector.mjs, route-params.ts | New helpers preserve every pre-existing query parameter. Safe inspector/return links must keep defined route/filter fields and drop unknown/secret params; do not carry invitation/auth tokens. | Open preliminary review |
| PUBLIC-INT | Claude foundation / App.tsx, router.tsx | Public worker can export unavailable-route UI and accepts safe next/reason; foundation must wire auth-expiry intent and NotFoundPage exports without public-file edits. | Pending integration |

Native Claude `/design` project access remains unavailable without separate consent. Installed Design & Taste and other handoff skills are in use; this does not block local implementation. Human visual approval/research: Not run.

Further landed inspector review:

| ID | Owner / file | Observation / required invariant | Status / evidence |
| --- | --- | --- | --- |
| EI-R01 | Claude foundation / EvidenceInspectorHost resolver | Any non403/401 resolver error triggers legacy exact-record fallback, including500/400/relationship404. Restrict fallback to an explicitly unsupported-route condition (or remove now that backend ships resolver); retain original fetch failure and Retry. No relationship/permission bypass. | Open preliminary |
| EI-R02 | Claude foundation / fallbackContextFromRecord | Check-result fallback permits missing target_id/check_id, then fills subject from URL hints. Missing binding must be partial/unavailable, never asserted matching relationship. | Open preliminary |
| EI-R03 | Claude foundation / ObservationBlock + fallback integrity | Every nonverified integrity state renders Recorded digest only even when no digest exists. Distinguish absent digest/not verified/failed verification/recorded digest and real stored verified result/time. | Open preliminary |
| EI-R04 | Claude foundation / outcomeTone | `detected` treated as success/green. Provider presence is neutral attribution, distinct from measured blocking/effectiveness. | Open preliminary |

Independent reproduction confirms NAV01 arbitrary `unrelated_metadata` persists and NAV02 retains synthetic auth_token/unknown query. Values were synthetic. Focused WAF integration independently passes63/63; full baseline failure may be test isolation contamination and remains under Grok diagnosis.

| EI-R05 | Claude foundation / fallbackContextFromRecord | Null provider confidence passes Number(null) finite test and appears as the string null instead of Not recorded. Independent synthetic reproduction confirmed. | Open preliminary |
| PUB-R01 | Claude public / sanitizeReturnHash | Allowed key value regex excludes `%` and `|`, while canonical finding-group key is `<URI-encoded check>|<URI-encoded issue>`. Returning through sign-in loses exact selected group. Validate the canonical key with its existing decoder and bound it, preserving actual group identity. Preserve other agreed safe inspector/selection context where supported. | Open preliminary |
| TYPE-01 | Claude foundation | Mid-integration tsc currently reports ProviderLogoId mismatch plus target-detail imports of removed AllChecksPanel/EdgeProtectionCard. Expected during rewrite; must be resolved before browser/build gate. | Pending final source integration |

Backend resolver preliminary review (new service landed, tests/wiring pending):

| ID | Owner / file | Observation / required invariant | Status / evidence |
| --- | --- | --- | --- |
| BE-E01 | Grok evidence / integrityFor | Treats arbitrary evidence metadata.verified_at as verified custody; one verified row also upgrades the whole set. Only authoritative stored verification, exact covered refs, method/result/time may establish verified status. Customer metadata must not assert custody. | Open P1 |
| BE-E02 | Grok evidence / loadSnapshot + loadEvidenceMap | Finding originRun and evidence rows lack strict same target/check/run relationship checks. Validate recorded linkage; missing bindings stay partial, conflicting binding must not display other scope. | Open P1 |
| BE-E03 | Grok evidence / selectLater | Later runs with missing bindings and nonfinalized verdicts can be selected. Require exact target/check/tenant and appropriate finalized evidence-backed result; no substituted lifecycle proof. | Open P1 |
| BE-E04 | Grok evidence / report primary | Chooses report.run_ids[0] as primary without explicit primary relationship. Keep captured refs together/alternatives and historical summary; do not invent a primary record. | Open P1 |
| BE-E05 | Grok evidence / provider entry | Returns method label and empty explanation/evaluation without recorded family signals. How identified must expose safe matching source/CNAME/address/fingerprint proof, independent family time/corpus/conflict/confidence; no generic method alone as primary proof. | Open P1 |
| BE-E06 | Grok evidence / projectSide | Merges scalar fields from multiple events; missing explicit operation/response correlation can fabricate a paired story. Select exact referenced event/operation, scope target/check, preserve alternatives or Not recorded. | Open P1 |
| BE-E07 | Grok evidence / boundReads | Postgres missing dependency methods can fall back to dev store. Fail closed for missing PG reads; no persistence-mode mixing. Audit/provider exact reads must be wired in both stores. | Open P1 |
| BE-E08 | Grok evidence / boundedEvents | Event cap applied after getRunEvents reads everything. Bound the underlying read/query, disclose truncation and evidence ref caps instead of silently hiding referenced records. | Open P2 |

These issues must be sent to assigned worker and verified after its current write/test pass, never marked complete because worker reports success.

| EI-R06 | Claude foundation / EvidenceInspectorHost | Loaded display keyed only by refKey, while scopeKey tenant/user/role changes trigger useEffect later. Same ref can display previous scope's model during new render. Include scope in committed/readable load key and synchronously discard old model on scope change; test role/tenant switch with delayed response. | Open P1 |
| DECL-INT01 | Claude foundation / patchTargetDeclaration | Backend typed purpose max200; frontend slices to120 on Save. Editing only owner on an API-created purpose >120 chars can silently truncate it. Align actual bounds and preserve valid existing fields; errors retain draft instead of silent crop. | Open P2 |

## Broad regression pass

`npm test` firstlane:13failures beforeintegrationstage. Source log `/tmp/astranull-current-release-orchestration/integrated-npm-test.log`. Classified:3stalecompiled-public-copy/oldauthroutepins (frontendfoundation/public), 4Postgresmockqueryshape drift (targetbackendowner), subscriptionas_of additivekeys (reportowner), inventorydeclaration additivefield (targetowner), WAFprovenance fixture missingexplicittenant (targetowner), 2providerproofpushToken undefined whilefinalhardening inprogress (evidenceowner). Do not weaken safetychecks; effectivecurrentverification must remain correct (newanalyticsSQL currentlyusesrawlatestverification andneedscontrollerownerreview).

Independent live assembled-app read (fresh isolated synthetic server60938): analytics returns5hosts and5not_checked buckets; screenshot/snapshot dashboard distinguishesUnknown5 correctly. Actual GET/v1/test-runs/run_checkout_1 has verdict:null, while dashboard Targetposture says PASSED ·1OPEN. Historical fixture inline/last-verdict fields mustnotbe shownas evidence-backedPASS whenauthoritativeverdict absent. Treatas unsupported/retainedclaim, keepopenfinding. Backend/FE ownermustreconcile dashboard/target runs_recent vsgetRun source insteadofrawunbackedfallback. This isnotan arithmeticfix orliveproviderclaim.

`git diff --check` flags extraEOFblanklines inrefined/findings-refined.css andservices/reports.mjs; assignedownersclean beforefinalgate. Targettestworker touched provenancefixtureoutsidepriorallowlist; outputisnotaccepteduntila narrowlyassignedfixturecheck reruns andconfirms onlyrequiredtenantstamps, preservingotherworkers.

## Independent history review, final integration wave

- HIST-HTTP: Real observation/origin HTTP and Postgres runtime injection pending D; passive scan GET must always remain side-effect-free.
- HIST-SCOPE: Review exact approved binding scope carried into signed job; selected multi-port/path binding must still execute that exact scope. Read-only Grok review assigned; not accepted as resolved by foundation tests.
- HIST-COMPARE: Compare provider identity as well as detected/not_detected outcomes; two different detected providers must not silently render unchanged. Review assigned.
- HIST-PRECISION: Verify retained timestamps/cursors preserve source precision consistently between JS and SQL. Review assigned.
- FIND-PAGE: Findings list currently count=loaded-page, limit-only; C assigned exact server filters/page/total in both stores. Frontend foundation integration follows.
- A11Y-ROW: Incomplete broad browser log stopped85/320 and exposes nested-interactive finding artifact rows. Foundation assigned real semantic/keyboard fix; do not claim a320-test pass.
- CONTRACT-HIST: Independent contract run5/7 passes;2 target-detail cases reject undocumented retained_family_states/comparable_changes/origin_bindings in profile and coverage. Extend explicit schema, preserving strict validation.
- ROOT-WRITERS: Independent18/18 history tests, zero skips including two ephemeral PG cases. Static lint/portal/safety all pass. Report helper boundary now pure lib/reportSnapshot with no dev import of PG; report trailing whitespace clean.

Root confirmed HIST-SCOPE, HIST-PRECISION and HIST-COMPARE in local synthetic imports: bound job has no bound Host/SNI, legitimate multi-scope binding rejected, wrong-target simulated observation renders reachable, microsecond order inverted, provider A→B still unchanged. Finalization also still reads today's catalog expected behavior. Exact reproduction and fix criteria: `/tmp/astranull-current-release-orchestration/root-history-confirmed-review.md`. These remain open until backend owner fixes and root reruns. No application edits by root.

## Recovered-tree independent checks

Root recovered typecheck/lint/portal-lint/safety pass;62 focused evidence/navigation/analytics/report/profile tests pass withzero skips. Strict contract gate needs newcomparison_gaps schemas (HTTPowner assigned), not a relaxed validator. Earlier test claims remain provisional after originalcheckout reset and deterministic recovery.

JOB-RECOVERY-P1: current buildSignedProbeJobRecord allows run.origin_binding_id nonempty with missing provenance_json.origin_scope and silently emits an unbound host_sni job from target.metadata.protected_host. Independent no-network reproduction returns approved_scope:null, logical_host:different.example. A bound legacy/repair run with missing/invalid approved scope must fail closed (explicit error, no job/dispatch), while genuinely unbound legacy jobs remain supported. Assigned to job owner at follow-up; no root application edits.

UI-DOCK-R01: Root viewed recovered dashboard/inspector native screenshots. At1502pxdock theavailablemainwidth shrinks butdashboardnestedtwo-columnlayout stillusesviewport breakpoint; prioritycopywraps2words/line andtablemandatoryoutcomeoffscreen. Needscontainer/dock-aware reflowwhilepreserving1360dock/drawer/sheet contract; assignedfrontendfollowup, notclosedbyaxescorealone. Missingproofnorefs onlegacybaselinefindingiscorrect explicitmissingdata, notan invitation toinventprimaryrefs.

## Final backend and core review disposition

Authoritative latest disposition supersedes preliminary statuses above. Root independently verified the recovered worktree: final-independent-npm-test.log4318unit/E2E+433serialintegrationpassed withzero failures/skips; final-independent-scale.log14enableddev/PGscale checks pass; strictAPIlineage/history contract9cases pass; job/HTTP14 andreadmodel36focusedcases include actualapp-rolePG, zero skips. No source guard weakened.

Closed: BASE-01 (properper-processisolation plusbaselinefixturetenant attribution); NAV-01/02, PUB-R01, PUBLIC-INT andTYPE-01 (safeallowlists/intent/currentroute wiring; nativeandunitchecks); EI-R01..06 andDECL-INT01 (unsupported-onlyfallback, strictrelationships/integrity/null/family presentation andsynchronousscope isolation, exacttypedbounds); BE-E01..08 (storedtrust/refscope/laterresults/frozenreportrefs/providerproof/unpairedsummaries/failclosedPG/boundedunderlying reads); JOB-RECOVERY-P1 (missingboundapprovedscopefailsbeforejob andPGrecoverycannotdispatch/doesnotorphan); HIST-SCOPE/HIST-PRECISION/HIST-COMPARE andFIND-PAGE (signedscope/layerobservations/microseconds/comparison provenance andsingleSQLfullpredicatecount/list, severity/statuslegacy parity). Source details andtest names remain inworker backend/UXdocs; the root logs are independentverification.

FT-TDfixture correction preservedownedProtectedpositive andaddedforeign/tenantlesssameAssetIDnegative; onlythreeexistingWAFchildtenantstamps were added. Targeteligibility tests nowassertmissingproofnot_runnable_now andserver-recordedDNSpositive, preservingmetadata spoof rejection. Opengroupcounts areexactOpen, Activebucketseparate; workspaceuniquetotalnevergroupassociationssum.

Still open: UI-DOCK-R01 actualavailable-widthreflow; finalwholebrowser run aftermigratinglegacycurrentretainedspecs isrunning. No pass claimed for an unfinished browserprocess. HumanG1approval/G3usability andlive-provider/productionexercisesNotrun. No commit/stage/push/deployment.

## Final local technical closure

UI-DOCK-R01 closed: content-width reflow stacks dashboard sections and preserves mandatory table columns. Root viewed before/after candidates and independently ran39 affected browser cases with scale enabled: allpass,zeroskips. Root115 affected frontend units and final build/type/lint/portal/safety/whitespace pass. All recorded local implementation/review issues are closed. Full browser351pass0fail1gatedskip preceded last targeted changes; gatedcase enabled passed final39. No unsupported full-suite repeat claim. Durable evidence: verification-report.md. HumanG1/G3 and external production gates remain explicit, not local implementation blocks.
