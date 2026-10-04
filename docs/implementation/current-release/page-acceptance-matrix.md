# Current-release page acceptance matrix

2026-10-04. Maps the 28 retained reviews in [document 21](../../feedback/21-all-page-data-and-task-review.md) to the local implementation candidates. Feedback files stay read-only. Root owns [execution-ledger.md](execution-ledger.md), [review-ledger.md](review-ledger.md), and [contracts.md](contracts.md) and finalizes those after its own checks.

## Gates

| Gate | State |
| --- | --- |
| G1 visual approval | Rendered candidate, pending approval. Screenshots under `/tmp/astranull-current-release-orchestration/` and `/tmp/astranull-frontend-recovery-shots/` are local candidates. No approver, date, or exception record exists. |
| G2 technical verification | **Achieved locally.** Root's independent final backend logs: 4751 Node cases (4318 unit + 433 serial integration, zero failures/skips, `final-independent-npm-test.log`), 9/9 strict contracts (`final-independent-contract.log`), 14/14 scale including real Postgres at 100k findings (`final-independent-scale.log`). Frontend: full 352-test browser set 351 pass / 0 fail / 1 gated scale skip, exit 0 (`/tmp/astranull-frontend-recovery-shots/playwright-all-4.log`); the gated scale case and the affected dock/dashboard flows were subsequently re-verified with the fix in place (`frontend-dock-scale-finish.json`: 46/46 scale-enabled affected files, cohorts 8/8, 423 focused units); root's targeted scale/dock/paging/a11y checks recorded 39/39 (`root-final-browser-checks.log`). Final build, typecheck, lint, portal lint, and safety green after review. The affected flows were verified after the last targeted CSS/dashboard change — a second full 352 pass on the exact final tree was not run. Root's verification report (`verification-report.md`) and ledger close remain root's. |
| G3 usability | Not run. T1–T7 and T9–T14 have no participant results. |

G1 and G3 are human gates and remain open. This matrix records local engineering fulfillment and technical verification only — not production readiness, usability signoff, or visual approval.

## Subsequent primary-checkout verification

The user authorized restoration of the matching implementation and a local commit after review. The current primary-checkout results supersede the historical recovery-only verification below: full serial Node inventory 4,764/4,764; complete browser/a11y suite 360/360 with the DOM scale case enabled; strict contracts 9/9; real Postgres scale checks 14/14. No skips or relaxed assertions. Typecheck, lint, portal lint, safety, build, and whitespace checks pass. See [the review ledger](review-ledger.md) for the code fixes, commands, logs, concurrent-run failures, and final ordinary npm test result. G1 visual approval and G3 usability remain open.

## How to read evidence

**Worker assertion.** A worker JSON report or a `docs/ux/current-release-*.md` / `docs/backend/current-release-*.md` note written by that worker. Counts in those files are the worker's claim.

**Root verification.** Only the independent logs named below. A worker claim that a suite passed is not a root pass. Tests in progress stay open.

Root logs already on disk, before this matrix:

- `/tmp/astranull-current-release-orchestration/integrated-regressions-round2.log`: 4240 tests, 4238 pass, 2 fail, `duration_ms` 51355.759833. Failures: `tests/unit/dev-store-test-isolation.test.mjs` (`tests/unit/postgres-validation-evidence-repository.test.mjs` reached the dev store without `tests/helpers/dev-data-dir.mjs`) and `tests/unit/postgres-portal-ownership-hardening.test.mjs` (extra `SELECT ... FROM target_observations` after edge detection). The ownership sequence is D's file. This wave does not edit it.
- `/tmp/astranull-current-release-orchestration/independent-contract-round2.log`: 7 tests, 5 pass, 2 fail. `FT-SHAPE-01` and `FT-SHAPE-01b` rejected undocumented `retained_family_states`, `comparable_changes`, and `origin_bindings` on `protection_profile` and `coverage`.

Empty worker reports, so no result is recorded from them: `frontend-customer-final-regressions.json`, `frontend-foundation-history-integration.json`, `backend-history-http-integration.json`. The customer final-regression assignment (`frontend-customer-final-regressions.md`) says the broad browser log stopped at 85/320. That suite is not a pass. [Review ledger](review-ledger.md) records the same stop as A11Y-ROW.

Root final backend verification logs (2026-10-04), all independent:

- `/tmp/astranull-current-release-orchestration/final-independent-npm-test.log`: unit 4318/4318 pass, serial integration 433/433 pass, zero failures/cancels/skips, full `npm test` exit 0.
- `/tmp/astranull-current-release-orchestration/final-independent-scale.log`: 14/14 pass, zero skips, real Postgres fixture at 10k groups / 100k findings / 5k targets; index-served reads and budgets pass.
- `/tmp/astranull-current-release-orchestration/recovered-independent-contract-round2.log`: 8/8 pass; the HTTP owner then added the ninth strict finding-lineage contract case (`FT-SHAPE-02b`), which root folds into its final contract run.

Harness attribution: the backend wave started assigned to the Grok CLI and was changed by the human to OpenCodeGo GLM 5.3 Flash (High). The frontend wave is Claude Opus 5.5 (High) using local CLI design skills only (design-taste, ui-ux-pro-max, Impeccable, interaction-design) — no public Design consent and no plugins were used. After the original checkout was Git-reset at 12:32:27, all implementation files were recovered into this isolated worktree (102 authored tracked files plus 165 handoff files); the original checkout stays read-only.

## Scope held out of these 28 pages

Direct-check execution stays on the target. It is not a 29th page ([scope](../../feedback/24-current-release-scope.md)). Standalone Test Runs, single-run detail, and scan/session pages stay deferred (PROGRESS UX-017). Scan backend BE-020 and BE-021 remains. Staff admin and SOC execution UI stay deferred. High-scale stays SOC-gated. WAF/CDN detection is an explicit review, then a start. A target GET does not dispatch a fingerprint or a scan (PROGRESS UX-018; [evidence-target note](../../ux/current-release-evidence-target.md)).

## Page map

Every row records **local implementation done and G2 technically verified** (see Gates for the named logs; per-row evidence names the actual source, tests, and docs). G1 human approval and G3 usability remain open separately and are not recorded here as done. Acceptance ids point at [document 17](../../feedback/17-design-acceptance-and-handoff-gates.md), [document 20](../../feedback/20-cross-page-task-flow-contract.md), and [document 21](../../feedback/21-all-page-data-and-task-review.md).

| Status | Page | Review | Acceptance | Frontend | Backend | Tests and docs (root-verified evidence unless noted) |
| --- | --- | --- | --- | --- | --- | --- |
| [x] | Dashboard | [dashboard](../../feedback/dashboard.md) | TF-01; T1; T2 | `apps/web/react/src/pages/dashboard-page.tsx` | `docs/backend/current-release-analytics.md` (`GET /v1/analytics/declared-hosts`) | `docs/ux/current-release-evidence-target.md`; dashboard panels and exact server-total counts verified in `root-final-browser-checks.log` (FT-DASH-01–04) and `playwright-all-4.log`. Shots: `foundation-evidence/`, dock before/after in `/tmp/astranull-frontend-recovery-shots/`. |
| [x] | Targets | [targets](../../feedback/targets.md) | TF-03; doc 23 missing-data | `apps/web/react/src/pages/targets-page.tsx` | Target list and declaration projection. `docs/backend/current-release-target-profile.md` | Same evidence-target note. Cohort links depend on server filters; verified in the focused and full browser runs. |
| [x] | Target groups | [target-groups](../../feedback/target-groups.md) | Doc 23 | `apps/web/react/src/pages/page-components.tsx` (`TargetGroupsPage`) | Group declaration + `open_findings_count`. `docs/backend/current-release-target-group-counts.md`; migration `db/migrations/0063_target_declarations.sql` | `docs/ux/current-release-customer-pages.md`. Shots: `customer-pages-shots/`; exact server counts covered by the paging/a11y cases in `root-final-browser-checks.log`. |
| [x] | Target group detail | [target-group-detail](../../feedback/target-group-detail.md) | TF-04 | `apps/web/react/src/pages/target-group-detail-view.tsx` | Group and member reads | Evidence-target note. Standalone scan pages stay deferred. |
| [x] | Target detail | [target-detail](../../feedback/target-detail.md) | TF-02; TF-04; TF-06; T2; T3; T5 | `apps/web/react/src/pages/target-detail-view.tsx`; `apps/web/react/src/components/targets/domain-protection.tsx` | `src/lib/targetDeclarations.mjs`; `src/services/protectionProfile.mjs`; `docs/adr/0011-current-release-target-evidence-contracts.md`; history read model in `docs/backend/current-release-history.md` | Evidence-target note. Contract shape: `tests/helpers/portal-schema.mjs`, `tests/contract/portal-shapes.test.mjs` — 9/9 in `final-independent-contract.log`. History API in root's final integration log (433/433). |
| [x] | Vector / check library | [checks](../../feedback/checks.md) | TF-04; TF-05 | `apps/web/react/src/pages/vector-library-page.tsx` | Compatible-check read | Customer-pages note. |
| [x] | Check detail | [check-detail](../../feedback/check-detail.md) | TF-05; EI-01; T10 | `apps/web/react/src/pages/detail-pages.tsx` (`CheckDetailPage`) | `GET /v1/checks/:id` | Customer-pages note. |
| [x] | Validation schedules | [test-policies](../../feedback/test-policies.md) | TF-09 | `apps/web/react/src/pages/refined/policies-refined.tsx` (`PoliciesRefined`) | Schedule PATCH/DELETE | Customer-pages note. |
| [x] | Validation schedule detail | [policy-detail](../../feedback/policy-detail.md) | TF-09; T10 | `apps/web/react/src/pages/detail-pages.tsx` (`PolicyDetailPage`) | Schedule entity read | Customer-pages note. |
| [x] | Findings queue | [findings](../../feedback/findings.md) | TF-07; T9; T12 | `apps/web/react/src/pages/refined/findings-refined.tsx` (`FindingsPage`) | Findings list (`docs/backend/current-release-findings.md`: full-match total from one SQL snapshot, canonical severity classes) | Evidence-target note. FIND-PAGE verified: paging spec in `root-final-browser-checks.log` (exact server totals, one class per filter). |
| [x] | Finding detail | [finding-detail](../../feedback/finding-detail.md) | TF-07; TF-11 scope on retest; EI-01 | `apps/web/react/src/pages/finding-detail-view.tsx` | Evidence context + strict retest lineage (`docs/backend/current-release-history.md`) | Evidence-target note. BE-E01–E08 verified by root's final logs. Lineage contract `FT-SHAPE-02b` in `final-independent-contract.log`. |
| [x] | Grouped finding detail | [finding-group-detail](../../feedback/finding-group-detail.md) | TF-08; T9 | `apps/web/react/src/pages/refined/finding-group-detail.tsx` | Member findings | Evidence-target note. |
| [x] | Evidence artifact detail | [evidence-detail](../../feedback/evidence-detail.md) | TF-18; EI artifact entry | `apps/web/react/src/pages/detail-pages.tsx` (`EvidenceDetailView`) | `GET /v1/evidence-context?entry=artifact` | Customer-pages note. Evidence-target spec 34/34 in the final browser record. |
| [x] | Reports | [reports](../../feedback/reports.md) | TF-12; T14 | `apps/web/react/src/pages/page-components.tsx` (`ReportsPage`) | `docs/backend/current-release-reports.md`; `docs/backend/current-release-analytics.md` | Customer-pages note. Create-error status mapping landed; frozen scope keeps stored snapshots. |
| [x] | Report detail | [report-detail](../../feedback/report-detail.md) | TF-12; T14; EI report entry | `apps/web/react/src/pages/detail-pages.tsx` (`ReportDetailPage`) | Snapshot in `docs/backend/current-release-reports.md`. BE-E04 | Customer-pages note. |
| [x] | Integrations | [integrations](../../feedback/integrations.md) | TF-10 | `apps/web/react/src/pages/integrations-page.tsx` (`IntegrationPage`) | Connector reads | Customer-pages note. `last_attempt_at` / `last_error_at` read "Not recorded" — an intentional, reported source limit, not a development block; no promise of future exposure. |
| [x] | Notifications | [notifications](../../feedback/notifications.md) | TF-11; T13 | `apps/web/react/src/pages/governance-pages.tsx` (`NotificationsPage`) | Notification rules | Customer-pages note. Per-attempt retry beyond metadata-only redrive stays a documented limit; no real-provider delivery promise. |
| [x] | Audit log | [audit](../../feedback/audit.md) | TF-13; T10 | `apps/web/react/src/pages/governance-pages.tsx` (`AuditPage`) | Audit list and `GET /v1/audit-log/:id` in the analytics note | Customer-pages note. Route verified in root's final logs. |
| [x] | Release evidence | [release-evidence](../../feedback/release-evidence.md) | Release-evidence P1/P2 in the customer-pages note | `apps/web/react/src/pages/governance-pages.tsx` (`ReleaseEvidencePage`) | Existing release-evidence inventory read | Customer-pages note. Copy states this is not launch approval. |
| [x] | Settings | [settings](../../feedback/settings.md) | TF-15 | `apps/web/react/src/pages/page-components.tsx` (`SettingsPage`) | Settings APIs already in the tree | Customer-pages note. |
| [x] | Support | [support](../../feedback/support.md) | TF-14; T10 | `apps/web/react/src/pages/page-components.tsx` (`SupportPage`) | Support snapshot time in `docs/backend/current-release-reports.md` | Customer-pages note. No automatic send. |
| [x] | Plan & usage | [subscription](../../feedback/subscription.md) | Subscription review #1–#3 | `apps/web/react/src/pages/page-components.tsx` (`SubscriptionPage`) | Subscription summary | Customer-pages note. |
| [x] | Public landing | [landing](../../feedback/landing.md) | TF-16 | `apps/web/react/src/pages/public-pages.tsx` (`PublicLandingPage`); `public-landing.css` | Public site config | `docs/ux/current-release-public.md`. Shots: `public-evidence/`. |
| [x] | Customer sign-in | [login](../../feedback/login.md) | TF-16 | `public-pages.tsx` (`LoginPage`) | Existing auth modes | Public note. Final build in the full browser run. |
| [x] | Request access | [signup](../../feedback/signup.md) | TF-16 | `public-pages.tsx` (`SignupPage`) | `POST /v1/signup-requests` | Public note. |
| [x] | Access request status | [signup-status](../../feedback/signup-status.md) | TF-16 | `public-pages.tsx` (`SignupStatusPage`) | Signup-request read | Public note. |
| [x] | Invitation password setup | [set-password](../../feedback/set-password.md) | TF-16 | `public-pages.tsx` (`SetPasswordPage`) | Invitation activate | Public note. |
| [x] | Missing or unavailable route | [not-found](../../feedback/not-found.md) | TF-18 | `public-pages.tsx` (`PortalUnavailablePage`) | None new | Public note. Foundation wires the three kinds. |

Shared inspector and navigation, used by the customer pages above: `apps/web/react/src/lib/evidence-inspector.mjs`, `apps/web/react/src/components/evidence/evidence-inspector.tsx`, `apps/web/react/src/lib/nav-state.mjs`. Acceptance: EI-01–EI-10, T6, T9, T12. Doc: evidence-target note.

## Worker-claimed test files

These files exist. Passing them is a worker assertion in the UX notes, not a root result. Root round 2 is the suite log above (4238/4240).

| Surface | Files named by the worker note | Worker-claimed size |
| --- | --- | --- |
| Foundation | `tests/unit/current-release-inspector.test.mjs`, `tests/unit/current-release-navigation.test.mjs`, `tests/e2e/journeys/current-release-evidence-target.spec.mjs`, `tests/a11y/current-release-inspector.spec.mjs` | Pass 3 note: inspector+navigation 59, journey 22, a11y 17, plus an owned unit set of 178. Pass 2 note cited 47, 14, and 15. |
| Customer pages | `tests/unit/current-release-customer-pages.test.mjs`, `tests/e2e/journeys/current-release-customer-pages.spec.mjs` | Note: 39 source contracts, 25 journeys. Earlier JSON reports cited 31/17 and then 186 unit tests plus 30 journeys. |
| Public | `tests/unit/current-release-public-ui.test.mjs`, `tests/e2e/journeys/current-release-public.spec.mjs` | Note: 16 journeys. `frontend-public-final-regression.json` asserts unit 67/67, public spec 16/16, forgot-password 1/1, from a tree mirror because that worker did not rebuild the tracked bundle. |
| Target profile | `docs/backend/current-release-target-profile.md`, ADR 0011 | Earlier review JSON asserted a focused unit, one real RLS case, parity, and keyset before history fields existed. That is not the round-2 suite. |
| Analytics and reports | `docs/backend/current-release-analytics.md`, `docs/backend/current-release-reports.md` | `backend-analytics-final-api-tests.json` and `backend-report-regression-finish.json` assert focused passes. The report JSON also records 215/216 on `postgres-service-adapters` with one failure outside that ownership. |
| Findings pagination | C's modules | `backend-findings-pagination.json` asserts 49 unit tests and 1 Postgres app-role test. Ledger FIND-PAGE stays open until root closes it. |
| History HTTP | D's modules and `docs/backend/current-release-history.md` | No result JSON. |

`frontend-customer-api-integration.json` says its 320-test Playwright run was still going when the report was written. Do not treat that file as a completed run.

## Open dependencies

All former development-pending dependency rows are resolved and covered by the independent logs and the root review ledger (NAV, EI, BE-E, DECL, CONTRACT-HIST, isolation, ownership sequence, HIST-HTTP/SCOPE/COMPARE/PRECISION, FIND-PAGE, report create status, tracked bundle, dashboard posture/server-truth counts, A11Y-ROW, UI-DOCK R01). Root finalizes the review ledger; no row here claims a ledger close on root's behalf. What remains open is deliberately not a development block:

| Status | ID | Record |
| --- | --- | --- |
| [~] | G1 | Rendered candidate pending human approval. |
| [~] | G2 | Achieved locally; root's verification report (`verification-report.md`) and ledger close remain root's. |
| [~] | G3 | Not run. |
| [~] | Connector last attempt | `last_attempt_at` / `last_error_at` read "Not recorded" — an intentional, reported source limit in `docs/ux/current-release-customer-pages.md`, not a development block. No promise of future exposure. |
| [~] | Notification delivery limits | Per-attempt retry beyond metadata-only redrive and real Slack/Teams/email/webhook delivery drills remain documented operational limits; no future-delivery promise is recorded here. |
| [~] | Postgres-mode browser runs / screen-reader sessions | Not run (no failure recorded). Named in the frontend completion record as not-run coverage. |

## UI-DOCK R01 (resolved)

The docked-inspector dashboard fix (UI-DOCK R01) landed: the dashboard stacks into one readable column when the inspector is docked (layout keyed to the dashboard's own available width; table minimum 32rem so all columns render), and the scale summary reads the real server totals (the enabled FT-DASH-04 case now seeds 100,000 real findings with the 5,000-target denominator served by the server, never a loaded-page count). Root reviewed the before/after screenshots (`dock-before-*.png`, `dock-after-*.png` in `/tmp/astranull-frontend-recovery-shots/`) and the assigned checks passed.

## Final root backend verification (2026-10-04)

Root's independent final backend checks, after all writer waves finished:

- Combined Node run: 4751/4751 pass, 0 fail, 0 skipped, 0 cancelled (unit 4318 + serial integration 433; `final-independent-npm-test.log`). Full `npm test` exit 0.
- Strict contracts: 9/9 pass (`final-independent-contract.log`), including the ninth case `FT-SHAPE-02b` (strict finding lineage with `latest` status/finalized/completed_at).
- Postgres scale: 14/14 pass, zero skips, dev + real-Postgres fixture with 100k findings (10k groups, 5k targets); index-served reads and query budgets pass (`final-independent-scale.log`).
- Typecheck, lint, portal lint, safety, and schema checks green after review; root's independent final diff/head/staging/feedback hash stable.

## Frontend browser record (2026-10-04)

- Full Playwright set: 352 tests — **351 pass, 0 fail, 1 gated scale skip** (`/tmp/astranull-frontend-recovery-shots/playwright-all-4.log`, exit 0, 8.6m). This run predates the last targeted dock/dashboard CSS and server-count change.
- That skipped scale case was subsequently enabled and the affected flows re-verified with the fix in place (`frontend-dock-scale-finish.json`): enabled real-DOM scale case (100k findings) passes, dashboard-affected browser files 46/46 with nothing skipped, cohorts 8/8, focused frontend units 423/423, typecheck/lint/lints/safety/build pass. Request budget unchanged (30 of 45).
- Root's targeted independent browser checks — scale, dock, paging, a11y, dashboard panels (FT-DASH-01–04) — recorded **39/39 passed** (`root-final-browser-checks.log`).
- Accuracy note: the affected flows were verified **after** the last CSS/dashboard change; a second full 352-test pass on the exact final tree was not run and is not claimed.
- G1 and G3 were not run (human gates).

## This wave's focused rerun (historical, superseded by the final root logs above)

Pages stay `[~]`. Root has not rerun the full suite.

```
ASTRANULL_DEV_DATA_DIR=/tmp/astranull-docs-contracts-34682 ASTRANULL_NO_PERSIST=1 node --test \
  tests/unit/dev-store-test-isolation.test.mjs \
  tests/unit/postgres-validation-evidence-repository.test.mjs \
  tests/contract/portal-shapes.test.mjs
```

Result: 47 tests, 47 pass, 0 fail, `duration_ms` 240.788. Exit 0.

- `tests/contract/portal-shapes.test.mjs`: 8 pass (`FT-SHAPE-01`, `FT-SHAPE-01b`, `FT-SHAPE-01c`, `FT-SHAPE-02` through `FT-SHAPE-06`).
- `tests/unit/dev-store-test-isolation.test.mjs`: 5 pass, including the store-reachability guard.
- `tests/unit/postgres-validation-evidence-repository.test.mjs`: 34 pass (repository cases plus finalization transaction ownership). Mock pool. No live Postgres in this file.
