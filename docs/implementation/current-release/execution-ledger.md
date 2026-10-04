# Current-release execution ledger

Local implementation authorized 2026-10-04 by attached orchestrator brief. No commit/push/deployment. Initial status: only `?? docs/feedback/` (165 handoff files). Original handoff preserved.

Harness verification: Claude Code 2.1.288, `--model opus --effort high`, response `claude-opus-5-5`; Grok CLI 1.0.46, discovered `grok-4.7`, `--reasoning-effort high`, response canonical `grok-4.7-build`. Codex owns contracts, coordination and independent review; no application implementation.

## Ownership

Wave 0 is read-only for both workers; each owns only its `/tmp/astranull-current-release-orchestration/*-contract-result.md`. Exact implementation ownership assigned after reconciliation. Shared manifests/lockfiles reserved; PROGRESS.md/API docs/backend migrations will be assigned to Grok, frontend and UI tests to Claude.

## Requirements

| Requirement / acceptance | Current behavior → intended outcome | Dependency | Writable owner | Evidence | Status / unresolved |
| --- | --- | --- | --- | --- | --- |
| `dashboard` / [page acceptance](../../feedback/dashboard.md) | Existing page reviewed in handoff → complete scoped task and correct states | Assessment pending | Claude UI; Grok required contracts (exact paths pending) | Not run | [~] implementation |
| `targets` / [page acceptance](../../feedback/targets.md) | Existing page reviewed in handoff → complete scoped task and correct states | Assessment pending | Claude UI; Grok required contracts (exact paths pending) | Not run | [~] implementation |
| `target-groups` / [page acceptance](../../feedback/target-groups.md) | Existing page reviewed in handoff → complete scoped task and correct states | Assessment pending | Claude UI; Grok required contracts (exact paths pending) | Not run | [~] implementation |
| `target-group-detail` / [page acceptance](../../feedback/target-group-detail.md) | Existing page reviewed in handoff → complete scoped task and correct states | Assessment pending | Claude UI; Grok required contracts (exact paths pending) | Not run | [~] implementation |
| `target-detail` / [page acceptance](../../feedback/target-detail.md) | Existing page reviewed in handoff → complete scoped task and correct states | Assessment pending | Claude UI; Grok required contracts (exact paths pending) | Not run | [~] implementation |
| `checks` / [page acceptance](../../feedback/checks.md) | Existing page reviewed in handoff → complete scoped task and correct states | Assessment pending | Claude UI; Grok required contracts (exact paths pending) | Not run | [~] implementation |
| `check-detail` / [page acceptance](../../feedback/check-detail.md) | Existing page reviewed in handoff → complete scoped task and correct states | Assessment pending | Claude UI; Grok required contracts (exact paths pending) | Not run | [~] implementation |
| `test-policies` / [page acceptance](../../feedback/test-policies.md) | Existing page reviewed in handoff → complete scoped task and correct states | Assessment pending | Claude UI; Grok required contracts (exact paths pending) | Not run | [~] implementation |
| `policy-detail` / [page acceptance](../../feedback/policy-detail.md) | Existing page reviewed in handoff → complete scoped task and correct states | Assessment pending | Claude UI; Grok required contracts (exact paths pending) | Not run | [~] implementation |
| `findings` / [page acceptance](../../feedback/findings.md) | Existing page reviewed in handoff → complete scoped task and correct states | Assessment pending | Claude UI; Grok required contracts (exact paths pending) | Not run | [~] implementation |
| `finding-detail` / [page acceptance](../../feedback/finding-detail.md) | Existing page reviewed in handoff → complete scoped task and correct states | Assessment pending | Claude UI; Grok required contracts (exact paths pending) | Not run | [~] implementation |
| `finding-group-detail` / [page acceptance](../../feedback/finding-group-detail.md) | Existing page reviewed in handoff → complete scoped task and correct states | Assessment pending | Claude UI; Grok required contracts (exact paths pending) | Not run | [~] implementation |
| `evidence-detail` / [page acceptance](../../feedback/evidence-detail.md) | Existing page reviewed in handoff → complete scoped task and correct states | Assessment pending | Claude UI; Grok required contracts (exact paths pending) | Not run | [~] implementation |
| `reports` / [page acceptance](../../feedback/reports.md) | Existing page reviewed in handoff → complete scoped task and correct states | Assessment pending | Claude UI; Grok required contracts (exact paths pending) | Not run | [~] implementation |
| `report-detail` / [page acceptance](../../feedback/report-detail.md) | Existing page reviewed in handoff → complete scoped task and correct states | Assessment pending | Claude UI; Grok required contracts (exact paths pending) | Not run | [~] implementation |
| `integrations` / [page acceptance](../../feedback/integrations.md) | Existing page reviewed in handoff → complete scoped task and correct states | Assessment pending | Claude UI; Grok required contracts (exact paths pending) | Not run | [~] implementation |
| `notifications` / [page acceptance](../../feedback/notifications.md) | Existing page reviewed in handoff → complete scoped task and correct states | Assessment pending | Claude UI; Grok required contracts (exact paths pending) | Not run | [~] implementation |
| `audit` / [page acceptance](../../feedback/audit.md) | Existing page reviewed in handoff → complete scoped task and correct states | Assessment pending | Claude UI; Grok required contracts (exact paths pending) | Not run | [~] implementation |
| `settings` / [page acceptance](../../feedback/settings.md) | Existing page reviewed in handoff → complete scoped task and correct states | Assessment pending | Claude UI; Grok required contracts (exact paths pending) | Not run | [~] implementation |
| `support` / [page acceptance](../../feedback/support.md) | Existing page reviewed in handoff → complete scoped task and correct states | Assessment pending | Claude UI; Grok required contracts (exact paths pending) | Not run | [~] implementation |
| `subscription` / [page acceptance](../../feedback/subscription.md) | Existing page reviewed in handoff → complete scoped task and correct states | Assessment pending | Claude UI; Grok required contracts (exact paths pending) | Not run | [~] implementation |
| `release-evidence` / [page acceptance](../../feedback/release-evidence.md) | Existing page reviewed in handoff → complete scoped task and correct states | Assessment pending | Claude UI; Grok required contracts (exact paths pending) | Not run | [~] implementation |
| `landing` / [page acceptance](../../feedback/landing.md) | Existing page reviewed in handoff → complete scoped task and correct states | Assessment pending | Claude UI; Grok required contracts (exact paths pending) | Not run | [~] implementation |
| `login` / [page acceptance](../../feedback/login.md) | Existing page reviewed in handoff → complete scoped task and correct states | Assessment pending | Claude UI; Grok required contracts (exact paths pending) | Not run | [~] implementation |
| `signup` / [page acceptance](../../feedback/signup.md) | Existing page reviewed in handoff → complete scoped task and correct states | Assessment pending | Claude UI; Grok required contracts (exact paths pending) | Not run | [~] implementation |
| `signup-status` / [page acceptance](../../feedback/signup-status.md) | Existing page reviewed in handoff → complete scoped task and correct states | Assessment pending | Claude UI; Grok required contracts (exact paths pending) | Not run | [~] implementation |
| `set-password` / [page acceptance](../../feedback/set-password.md) | Existing page reviewed in handoff → complete scoped task and correct states | Assessment pending | Claude UI; Grok required contracts (exact paths pending) | Not run | [~] implementation |
| `not-found` / [page acceptance](../../feedback/not-found.md) | Existing page reviewed in handoff → complete scoped task and correct states | Assessment pending | Claude UI; Grok required contracts (exact paths pending) | Not run | [~] implementation |
| EI-01…10 | One-action exact primary evidence, original vs retest, safe loading/redaction, restored focus | Joint contract | Pending exact paths | Not run | [~] implementation |
| TF / docs20–23 | Exact named actions, immutable entity relationships and scoped return state | Joint contract | Pending exact paths | Not run | [~] implementation |
| PROFILE / docs06–09 | Independent provider attribution, declarations and tested dimensions | Joint contract | Pending exact paths | Not run | [~] implementation |
| ANALYTICS / doc07 | Server cohort/count/list parity across pagination | Joint contract | Pending exact paths | Not run | [~] implementation |
| DIRECT | Target/check selection → reviewed bounded execution → evidence → remediation/retest | Joint contract | Pending exact paths | Not run | [~] implementation |
| G2 | Technical/browser matrix: themes, widths, keyboard, zoom, motion, states | Joint contract | Pending exact paths | Not run | [~] implementation |

## Review/failure ledger

No implementation reviewed yet. Human composition approval and representative-user research: Not run; no approval fabricated. Production gates remain independent.

## Baseline verification (before application edits)

- web:typecheck, lint, lint:portal, safety, web:build: passed.
- test:contract: 7/7 passed.
- Full npm test: unit/E2E first lane passed; integration lane has 7 pre-existing failures in `tests/integration/waf-posture-api.test.mjs` WAF connector API (create returns 400 vs expected 201). Detailed output at `/tmp/astranull-current-release-orchestration/baseline-tests.log`. Assigned for backend investigation; do not weaken safety gates to satisfy stale fixtures.
- Claude native read-only consultations used the same verified `claude-opus-5-5` model (checked session records). A stalled read-only shell wait was terminated so assessment can finish.
- User explicitly requested Claude Design as well as handoff skills; supplemental instruction is in `/tmp/astranull-current-release-orchestration/frontend-design-instructions.md` and will be included in all frontend implementation briefs.

## Independent wave 1 ownership

- Claude public worker: `apps/web/react/src/pages/public-pages.tsx`, `public-landing.css`, new `tests/unit/current-release-public-ui.test.mjs`, `tests/e2e/journeys/current-release-public.spec.mjs`, `docs/ux/current-release-public.md`. Six public pages and recovery subflows; existing APIs only, independent of new protection/evidence contracts.
- Grok baseline repair: `tests/integration/waf-posture-api.test.mjs` only. Source safety gates remain authoritative.
- Shared frontend/evidence and backend application implementation remain pending joint-contract report reconciliation.

## Core implementation ownership (wave 2)

Frontend foundation owns shared inspector/navigation/root+target/inventory/dashboard/findings files and new current-release inspector/target tests; customer-page Claude owns page-components/governance/detail-pages/library/integrations/refined-policy files and new customer-page tests; public Claude remains separate. Exact allowlists stored in `/tmp/astranull-current-release-orchestration/frontend-{foundation,customer-pages,public}.md`. Grok core exclusively owns `src/`, new migrations0063+, backend current-release test families, docs/api.md and ADR0011. Baseline Grok owns existing waf-posture-api test only. Shared manifests/locks untouched; PROGRESS.md reserved for later docs worker. All requirements [~] while under implementation; no completion claimed. Reconciled contract: [contracts](contracts.md).

Local Postgres harness availability independently checked via `resolvePostgresHarnessAvailability` (no Docker startup): available. New parity tests must use ephemeral databases and actual RLS. Browser baseline captured and viewed at `/tmp/astranull-current-release-orchestration/dashboard-before.png`; existing ownership-in-defense-path/mandatory run navigation confirms handoff baseline. Browser QA task space7 uses isolated seeded server61750.

## Backend bounded passes

Evidence resolver worker now owns only new evidenceContext, server route, validation/audit/report read adapters as needed, API section and new evidence tests. Target-profile Grok worker separately owns target declarations/contracts/services, coreCatalog and portal target hydrators, edgeDetectionPresenter, migration0063, profile tests and ADR0011; its exact allowlist is in backend-target-profile-slice.md. It may not edit server/validation repositories/API docs. Wiring follows after resolver owner finishes. Analytics/history/lineage remain next passes.

Independent analytics Grok owns only NEW declaredHostAnalytics lib/service/repository, new analytics tests and analytics backenddoc. It may not edit any existing source/server/runtime/migration; integration waits for current source owners. Exact allowlist in backend-analytics-foundation.md.

## Continuation / integrated review

Human user reiterated continue. First passes cover all28 retainedpages; implementation remains [~] until integratedcontracts/tests are verified. Public16/browser, foundation40/browser+a11y, customer21/browser are worker evidence; root independently verified38 backendfocusedtests including3 localPG cases withzero skips. Root typecheck, portal lint and rebuiltbundle passed before continuation. RealPG endpoint independently confirmed local127.0.0.1:5432.

Wave ownership: analyticsC now owns server/runtime/API docs andtargetGroups/coreCatalog LIST readmethods plus auditreads. TargetB reviews MUTATION/detail/profile/schema only; reportingE owns reportservice/repo/adapters and supporttimestamp fields. HistoryD owns newhistory/origin/lineage modules, migration0064, edgeStore andscanreadonlymode; itmustnot yetwrite evidence-read/validationRepo files ownedby proofA. ProofA finalnarrowpass owns evidenceContext/getRunEventsread/helperrepo readmethods. Frontendfoundation/customer/public owners remainasassigned, exactprompts in /tmp. Futurehistorywriterintegration andfrontend actualAPIconsumption remainpending.

## Final integration wave (11:39 local)

- History D writers finished: server-controlled run stamps, signed-result observation append in the ingest transaction, monotonic current detection, explicit same-pair retest intent and per-finding closure. Root independently ran18 history/writer tests, including real app-role Postgres, with zero skips (`independent-history-writers.log`).
- D now exclusively owns server/runtime/0064 schema reconciliation/history API docs and a new HTTP integration test. C exclusively owns findings list predicate/pagination/count parts in findings/validation adapters and repository. Root-owned mocks are assigned to D only for new sequential history reads.
- Claude foundation owns actual history/origin/lineage UI consumption and its own accessibility fixes. Customer Claude owns final customer regressions and the check-detail case in portal-truth; public Claude owns only its forgot-password case in that file. Those are disjoint hunks, not concurrent whole-file replacements.
- Evidence Grok is doing a read-only independent history/execution-scope review. It owns only its /tmp review report. No source write ownership.
- Root independent lint, portal lint and safety passed. Contract gate has2 failures: new protection_profile/coverage history fields need explicit schema documentation; do not relax schema validation. Broad npm test round2 is running and is not yet accepted as a pass. All28 entries remain[~] while final integration/verification is unfinished; G1 visual approval and G3 user research remain Not run.

## Backend harness change authorized by user

User explicitly requested OpenCode Go GLM5.3Flash to avoid exhausting Grok. Interrupted only the two task-owned active Grok workers (history HTTP and job fidelity), preserving partial source edits. Verified OpenCode1.18.16, exact discoveredmodel `opencode-go/glm-5.3-flash`, authenticated Go provider, successful smoke session `ses_efa6718c7ffeGEAxkzs3hAh2av`, catalog-supported `--variant high`. Backend remainingwork split into exclusive HTTP/runtime/schema owner, bound-job/finalization owner, and pure-history hardening owner. Prompts `opencode-{http-handoff,job-scope-handoff,history-hardening}.md`. No Grok continuation afterswitch. ClaudeCodeOpus5.5High remainsfrontendowner.

OpenCode Go worker metadata independently confirmed providerID opencode-go, modelID glm-5.3-flash, variant high. Four sessions paused after completed tool calls for about10minutes, with pending assistant requests and no errors/parts. Task-owned processes were interrupted and resumed once with documented --pure (process-only external-plugin disable; no settings/auth changes). Same model/variant/session ownership. Findings resume used recovered actual session ID after a Session not found reference correction. No alternate model fallback. Remaining required integration/review work still active.
\n## Recovery / isolated continuation\n\nAt12:32:27 a Git reset moved the originalcheckout toHEAD; no suchdirectcommand was found in recordedworker calls. Taskwriters stopped. Preserved immutable44MiB harness snapshot archive and hashmanifest. Restored102trackedauthoredfiles and240new/handofffiles (including165originalfeedbackfiles) to /Users/checkred_admin/.codex/worktrees/current-release-recovery/astranull. Originalcheckout untouched by recovery; currentwork lives inattachedmanagedworktree atbaselinee34ccd27. No commits/staging/push/deploy. NewCLI sessions areexplicitlyscopedto recoveryroot; oldrootread-only. BackendremainsOpenCodeGoGLM5.3FlashHigh with --pure; frontendClaudeCodeOpus5.5High mandatorydesignskills. Allpre-resettest evidenceisprovisionaluntilrecoveredtreeverified.\n
Recovered-tree rootverification:62core contracts,9strictAPIshape contracts,14job/HTTP tests (includingactualPGmissing-scope recovery) and36readmodel/history/group tests passwithzero skips. Rootcorrectedbroadtestharness: presetASTRANULL_DEV_DATA_DIRwas sharedbyparalleltestfiles, causingan unknown_targetfixturecollision. Withrepositoryper-processhelperisolation(envunsets inheritedpreset), firststage4317/4317passed; serialintegrationstagecontinues. No guard/fixture weakened forrootrunnerissue. RootisolatedworktreeGitstatus/headstable; originalcheckoutremainsreadonly.

## Final result

All28 retained pages and shared customer flows are complete locally; G2technical verification passed. verification-report.md records4751 Node cases,9strict contracts,14enabled dev/PG scale checks,39final affected browser cases and115affected frontend units: zero failures/skips. Full worker browser351pass0fail1gatedskip preceded finaldock changes; gatedtest ran in rootfinal39. Original165handofffiles byte-identical. HEADunchanged/stagingempty; no push/deploy. Work completed in attached recovery worktree. HumanG1candidate approval/G3study remainNotrun; full handoff gates stay[~]accordingly. Earlier provisional entries are superseded by final report and page acceptance matrix.


## Authorized review and commit in the primary checkout

The user requested review, fixes for failures, and a commit once checks pass, then explicitly reiterated “fix whatever is failing.” The matching final recovery implementation was restored into `/Users/checkred_admin/Projects/astranull`; the stash and recovery worktree were preserved. The earlier no-commit/read-only restrictions describe the implementation wave, and are superseded for this requested local review and commit. No push or deployment is requested.

Independent review fixes and current verification are in [review-ledger.md](review-ledger.md). The complete serial Node inventory passes 4,764 cases, the full browser/a11y suite passes 360 cases with the scale gate enabled, contracts pass 9 cases, and scale checks pass 14 cases with zero skips. The current production assets have been rebuilt. G1, G3 and production signoff remain open.

Final ordinary `npm test` completed successfully: 4,764/4,764, zero failures/cancellations/skips (`/tmp/astranull-review-final-npm-serial.log`). The Node test commands now serialize files to keep the unchanged performance guards reproducible. The user-authorized local review is complete; the commit includes the restored implementation and the documented review fixes.
