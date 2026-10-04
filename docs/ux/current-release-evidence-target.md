# Current release: shared evidence inspector, target workspace, inventory, dashboard and findings

Status: implemented locally on 2026-10-04 under the orchestrator's explicit implementation authorization. Human design approval (G1) and representative user research (G3) are **Not run**. The technical checks below do not stand in for either.

Design read: operational evidence console for security and SOC operators. Operate mode, dials variance 3, motion 3, density 7. Existing AstraNull Option A (pure black dark, light theme, Space Grotesk, Inter, JetBrains Mono, single orange accent, frost hairlines) is unchanged. No new tokens except `--inspector-width` and `--z-inspector` (between dropdown 40 and drawer 50).

## Shared evidence inspector (EI-01 to EI-10)

| Piece | File | Contract |
| --- | --- | --- |
| Ref, hash state, query, view model, fallback | `apps/web/react/src/lib/evidence-inspector.mjs` (+ `.d.mts`) | `EvidenceInspectorRef = { entry, finding_id?, target_id?, check_id?, test_run_id?, family?, evidence_id?, report_id?, audit_id? }`. IDs must match the server rule `^[A-Za-z0-9_.:-]{1,128}$`; `family` is `waf`, `cdn`, `cloud`, `dns` or `origin_hosting`. |
| Root host | `components/evidence/evidence-inspector.tsx` | Mounted in `App.tsx` only when a session exists (after `AppShell`), so public pages and role gates are unchanged. Reads the address on cold load, Back/Forward, hash changes and in-page opens. |
| Panel primitive | `components/ui/inspector-panel.tsx` | Docked column at 1360px and wider (main content pads by `--inspector-width`), modal drawer from 700px, full-width sheet with a Back button below 700px. Native `<dialog>` for drawer and sheet (focus trap, Escape). |
| Page hooks | `components/evidence/use-inspector.ts`, `inspector-sequence.ts` | `useInspectorRef`, `useOpenInspector`, list return state, and the bounded Next/Previous sequence a page publishes. |

Address: the inspector adds `inspect=<entry>` plus `ev_finding`, `ev_target`, `ev_check`, `ev_run`, `ev_family`, `ev_evidence`, `ev_report`, `ev_audit` to the current hash. `buildEvidenceInspectorHref(ref, '/app#audit')` gives a cross-page address. Opening pushes one history entry (Back closes before leaving the list); Next/Previous replaces it. Close returns focus to the trigger recorded by `data-focus-key`.

Reads: `GET /v1/evidence-context` with IDs only. Read failures stay distinct:

| Response | Shown as |
| --- | --- |
| 403 | Access required (with the permission), nothing fetched another way |
| 401 | Sign in again |
| 404 with `state: not_found` | No longer available; nothing substituted |
| 404 without `state` (context route not deployed) | The only case that falls back to an exact record read (`/v1/findings/:id`, `/v1/test-runs/:id`, `/v1/targets/:id`, `/v1/evidence/:id`, `/v1/reports/:id`). The record must state its own binding: a run without `target_id` and `check_id`, a target payload without its id, or an artifact without the hinted run is shown as **Relationship not recorded**, never matched from the address. Request and response are hidden; Retry stays available. |
| 400, 500, 502, 503 or network failure | Evidence unavailable + Retry (never "no evidence", never a fallback read) |
| `unavailable_reason: no_refs` | Supporting evidence not recorded (entry-specific copy) plus the originating record IDs |

Integrity copy follows the recorded state: `verified` with a time and method; `verified` without a time reads as not verified; `failed` reads Verification failed; `recorded_digest` reads Digest recorded, not independently verified; anything else (including the current server value `not_recorded`) reads No integrity record. Evidence IDs the server lists in `missing_evidence_ids` are marked "referenced, record not loadable". Provider entries render the server's `subject.proof` (methods, matched signals, CNAME chain, address attribution, fingerprints), recorded confidence (null reads Not recorded), conflict and corpus; provider presence uses a neutral tone, never a passing one.

A committed inspector load is keyed by the reading scope (tenant, user, role) and the ref, so after a role or tenant switch the previous scope's model is unreadable in the same render and only the new scope's response can land.

The initial view keeps the answer and proof together: identity line (target, check, observed time, external scope), outcome and limitations, expected versus observed, request and response summary, provenance (original evidence, then any later same-target same-check result labelled as not replacing it), and a collapsed technical record. Integrity reads "Recorded digest only" unless the server reports a verification. An open finding whose original outcome reads as passing gets an explicit disagreement note. Late responses are discarded by a tenant/user/role plus ref generation and an `AbortController`. No inspection path issues POST, PATCH, PUT or DELETE, reads a validation scan, exports, verifies custody or sends.

Actions in the inspector are navigation only: open this check on the target (hidden when already there), open full finding, review retest (goes to the finding's review step), open artifact record.

## Navigation and return state

- Sidebar: Targets before Target groups; Check library, Validation schedules, Findings; account group (Settings, Support, Plan & usage). Test runs leaves the sidebar but `#runs` still resolves.
- `lib/nav-state.mjs`: a fixed filter-key allowlist (`q`, `search`, `status`, `severity`, `owner`, `group`, `kind`, `tag`, `verification`, `family`, `family_status`, `service_role`, `criticality`, `owner_status`, `freshness`) plus sort, page, selection, scroll and focus, in `sessionStorage` under `astranull.nav.v1:<tenant>|<user>|<role>:<route>`, 30 minute TTL. Unknown keys, raw metadata and credential-shaped values (JWTs, bearer strings, provider keys, invitation/reset codes, long high-entropy runs) are never stored. Other scopes are cleared on identity change. Used by Findings and Targets.
- Address rewrites (`buildEvidenceInspectorHref`, `stripInspectorParams`, `replaceRouteParams`) keep only defined route, filter, selection and inspector parameters with bounded values (`sanitizeRouteParams`); unknown keys and credential names or values are dropped instead of copied forward. Entity ids, `tab`, `check`, canonical finding-group `key` and list filters survive.
- Live lists (`components/evidence/use-stable-list.ts`): Findings and the target's execution history hold their displayed snapshot while the pointer is over the list, focus is inside it, or the inspector is open. Newer same-scope rows wait behind a fixed "Newer results arrived · Show updates" notice that does not shift layout; counts and summaries are computed from the held snapshot and say "held as of". Explicit filter, sort and page changes apply the newest rows; a tenant, user, role or route change replaces the snapshot at once. During a live multi-check run the check queue keeps its captured order and category openness.
- Access and missing records: a route the role cannot open shows a persistent access-denied page on its own address (no fallback swap, nothing from it is hydrated). Unknown routes show the public `PortalUnavailablePage` not-found kind; a missing target shows record-missing with Back to targets. Sign-in redirects (boot, stored expiry, re-auth) carry the intended route only through the public `buildLoginReturnUrl` sanitizer; `SignupStatusPage` and `SubscriptionPage` receive config.
- Address predicates win over remembered filters: `#findings?status=open`, `#targets?verification=unverified`.

## Target workspace (TF-02 to TF-06, direct-check flow, docs 06 and 09)

Tabs Overview, Validate, Findings, Changes & history, kept in the address (`tab`, `check`). Legacy aliases resolve: `protection` and `edge` to Overview, `runs` to Changes & history, `checks` to Validate.

- Header: identity, ownership, declared context (purpose, roles, owner, criticality with "inherited from group" where the server says so; an explicit note when the server reports no declaration), tags, one primary action.
- Edit context: inline focused form; sends only changed fields so untouched inherited values are never cleared (the server treats explicit null or [] as a clear that blocks inheritance). Bounds match the server (purpose 200, owner 80) and are validated with counters; values are never cropped. Dirty cancel asks for confirmation; Escape cancels.
- Starts and detection require proven ownership. `isTargetRunEligible` now returns true for every target, so the workspace no longer treats reported eligibility as permission.
- Coverage renders the server `coverage` totals and the profile `dimensions` table (application, origin lockdown, network and transport, DNS, operations): evaluated, conclusive, not run, stale and excluded per dimension. It is labelled coverage, not outcome; a rounded 0% with at least one conclusive pair reads "<1%".
- Overview: one prioritized next step (prove ownership with the target's own TXT record, the highest-severity open finding with View evidence, or plan the first check), then protection observations, then recorded results.
- Protection observations: one row per family from its own source (`protection_profile.families` first, else the legacy `edge_detection` row of the same family). CDN never borrows the WAF vendor; DNS provider and origin hosting stay Unknown without their own source; sources appear only when recorded; no Anycast, header or agreement claims. Each row opens the provider inspector. Marker blocking is shown separately with no percentage at a zero denominator. Origin exposure reads Not tested unless the profile records a status (the legacy `not_exposed` default is ignored).
- Coverage: the server `coverage` object when present; otherwise labelled counts over compatible catalog checks with no percentage.
- No probe on load: the automatic edge-fingerprint start was removed. Detect WAF and CDN opens a review with the target and bound, then starts. DNS re-checks run only after the user chose Check now.
- Validate: one check queue grouped by category; the selected check expands in place with its bound, last result and View evidence. Review and start shows the exact target and check, upper bound, ownership and server gates before the existing `POST /v1/test-runs`. Review all uses the existing `POST /v1/validation-scans`. A linked check that is not compatible is reported, never replaced by another.
- Changes & history: recorded executions with View evidence (no run or scan detail navigation), observation history when the server exposes it (explicit not-available message otherwise), ownership transitions.

## Inventory (Targets)

Summary separates declared target records, distinct hostnames (normalized; IPs, CIDRs and endpoints counted separately), ownership verified and ownership pending. "Ready for validation" is gone. Each row leads with the target and its primary action (Open, or Verify ownership for pending targets), so the action is reachable at 375px without horizontal scrolling. Last validation reads "Not available in inventory" when the field is absent and "Not checked" when it is present and empty. Clear filters appears with active filters and in the filtered empty state. Dashboard cohorts arrive as server predicates (`family`, `family_status`, `service_role`, ...); the page fetches `/v1/targets` with that predicate and refuses to show the full inventory as the cohort when the server cannot filter.

## Dashboard

Priorities first: KPIs (readiness with its scope, declared records plus distinct hostnames, ownership pending, open findings), then What to fix first (View evidence opens the exact finding inspector) beside target posture, then declared-host WAF and CDN observations from `GET /v1/analytics/declared-hosts` only (Unavailable when the route is missing; WAF add-on rollups are not used), then recent checks (rows open the check-result inspector) and the readiness explanation. The defense-path strip, which inferred stages in the browser, was removed. Every count links to a list with the same visible predicate.

## Findings

The refined presentation is the only customer view; `?variant=` links still resolve. Each finding row opens its original evidence beside the queue in one action; Escape or Back restores filters, page, scroll and focus. Group detail uses Finding group and Affected targets; every member has its own View evidence and the inspector steps through members with bounded Previous and Next (no wrap, never the lead finding's proof). Finding detail: View original evidence in the header, original versus later lineage, artifacts labelled cited or run-level with no per-artifact bundle export, sibling evidence through the inspector, and a separate Review this retest step (also reachable as `?retest=review`) before the existing retest request.

## Verification run (local, synthetic, isolated `ASTRANULL_DEV_DATA_DIR`)

Pass 2 (review fixes), all against the in-process API with simulated probes and dev-headers auth; no external traffic, no `.data` writes:

- `node --test tests/unit/current-release-inspector.test.mjs tests/unit/current-release-navigation.test.mjs`: 47 pass (adds NAV-01, NAV-02, EI-R01..R06 and DECL-INT01 cases).
- Updated existing tests to the current contract, keeping their safety and identity checks: `portal-route-datasets`, `target-detail`, `targets-portal-contract`, `portal-executive-language`, `dashboard-metrics` (unit, all pass); `portal-target-run-all.spec` and `portal-refined-findings-groups.spec` (browser, 11 pass).
- `tests/e2e/journeys/current-release-evidence-target.spec.mjs`: 14 pass. Adds a delayed refresh landing while a row is hovered (row does not move; explicit Show updates applies), a refresh while inspecting (inspector and selection stay), a role switch with the new evidence read held (previous scope payload not shown), credential-like address params dropped on inspector open, not-found / record-missing / persistent access-denied (no audit reads for the denied role), and long identifiers at 640px (1280px at 200% zoom) in both themes with no page or inspector overflow.
- `tests/a11y/current-release-inspector.spec.mjs`: 15 pass. Axe WCAG 2.1 AA serious/critical on the inspector (docked, drawer, sheet), the target workspace at 375/768/1024/1440 in dark and light, keyboard open and Escape return focus, visible focus on the next control, reduced motion. This pass fixed a light-theme tab-count contrast of 4.45:1 found by the matrix.
- `npm run lint`, `npm run lint:portal`, `npm run web:typecheck`, `npm run web:build`: pass (build output is an ignored artifact for the orchestrator to verify).
- Screenshots: `/tmp/astranull-current-release-orchestration/foundation-evidence/{before,candidates,after,after-pass2}`.

## Server cohorts, profile honesty and access (pass 3)

- Dashboard declared-host coverage reads `GET /v1/analytics/declared-hosts?family=waf|cdn&unit=normalized_hostname|declared_target`. The section has a Count by toggle (Distinct hostnames / Declared target records). Each row shows Detected, Not detected, Inconclusive, Stale and Conflicting signals separately. "Unknown or not checked" sums the explicit `not_checked` and `not_recorded` segments with `unknown_count` (which is unknown only), and each part keeps its own link. The meta line shows both units for the same scope, the `as_of` time, "scope not confirmed as current" when `scope`/`historical` disagree, and a notice when the segments do not add up to `denominator`. Incomplete reads say Unavailable; an empty scope says Not applicable.
- Every segment link is built from the server `list_query`, keeping only the `/v1/targets` allowlist plus the unit. The link opens `#targets?...`, which renders `TargetCohortList` in place of the inventory:
  - It fetches `/v1/targets?<filters>&limit=50`, pages through server cursors (Previous/Next), and labels the count as "Showing a to b of TOTAL distinct hostnames / declared target records" with both units for the same scope.
  - Refresh on page one sends `cohort_version`. A 409 `cohort_changed` re-reads the same filters without it and says the set changed, without claiming a snapshot. A 409 `cursor_clock_mismatch` / `cursor_filter_mismatch` or a 400 `invalid_cursor` restarts at page one with the filters unchanged.
  - Other 400s (unsupported filter) are shown as rejected; the full inventory is never substituted.
  - Aliases `search`, `group`, `target_group`, `verification`, `role` and the unit tokens `normalized_hostname`/`declared_target` are canonicalized. `verification` stays the inventory's own client filter, so the dashboard "Ownership pending" count keeps its parity.
- A hostname row that stands for several declared targets (`analytics.member_count > 1`) lists every `target_ids` member with its own Open link and says none is chosen. Ownership, last validation and group read "Per declared target" for such rows, and a family disagreement between members is labelled.
- Findings accept `target_group_id`, `target_group` or `group`, and apply the server predicate (`/v1/findings?target_group_id=`). The page states that status and severity counts cover the returned findings only.
- The route sanitizer adds audit `actor`, `category`, `resource`, `from`, `to` (ISO date or datetime only) and cohort keys. `AuditPage` now receives `config`.
- Target profile:
  - Coverage cells show Unknown and Partial counts.
  - Pairs with `live_external: false` and a `retained` record are listed under "Recorded, not counted as current live coverage" with their reason (simulation, manual or customer declaration, missing check or scenario version, ...). The matching check-queue row carries a "Not live evidence" badge.
  - The origin row keeps `assurance` as recorded ("none" means no origin lockdown is claimed). Recorded reachability is shown with its tested target, scenario and limits.
- Inspector operation facts: `request_summary.request_count` renders recorded "Requests sent" and "Requests simulated" (a missing count reads Not recorded, never 0). Provenance renders kind plus live or not-live status. Provider proof renders the server's string arrays (methods, matched signals, CNAME chain, address attribution, fingerprints).
- Access:
  - A denied route keeps its address and shows the persistent access-denied page. No timed fallback redirect.
  - Every hydration path is gated on `routeAllowedFor`.
  - Sign-in intent passes only through `buildLoginReturnUrl`; staff surfaces and external IdPs are excluded.
- Coarse pointer: the back, group and overview group links on the target workspace meet 44px. Finding detail keeps "Export evidence", and the artifact table no longer prints raw artifact IDs (they stay available in the inspector).

Pass 3 verification (isolated store, simulated probes):
- Units:
  - `current-release-inspector` + `current-release-navigation`: 59 pass.
  - Owned unit set including `react-portal-auth` and `portal-role-dataset-access` (rewritten to assert persistent denial, gated hydration and sanitized intent instead of the old fallback redirect): 178 pass.
- Journey spec: 22 pass. A second, separately seeded block adds:
  - a dashboard segment opening the exact cohort with count parity in both units;
  - cursor paging, plus a real server clock-mismatch reset;
  - a real `cohort_changed` after a store insert;
  - a shared hostname with two declared targets;
  - a role switch keeping filters;
  - an unsupported filter;
  - the findings `group` alias using the server predicate;
  - audit params kept through inspector rewrites, with credential params dropped.
- a11y spec: 17 pass. Adds dashboard coverage and the cohort list at 375 and 1440 in both themes.
- `portal-truth` unknown-route and denied-route cases pass.
- Screenshots: `foundation-evidence/after-pass3`.

## History, origin relations and retest lineage (pass 4)

- **Changes & history** opens with what changed, from `docs/backend/current-release-history.md` shapes:
  - "Current state by layer" reads `protection_profile.retained_family_states`. The last completed observation and the latest failed attempt are shown separately; a later failure says it does not replace the completed observation.
  - "Confirmed changes" lists `comparable_changes` with their direction. "Not compared" rows come from the observation route's `comparison.comparison_gaps` (newest page only) with the reason, such as a changed check definition, corpus or scenario.
  - "Observation history" pages `GET /v1/targets/:id/observations` newest first through `next_cursor` (Load older observations), with a layer filter (`hist_family`). An expired cursor restarts at the newest page with the filter kept.
  - The selected observation (`obs`) stays selected across paging and filtering, and says when it comes from an earlier page. It shows producer (non-live producers are labelled), versions and finalization, and View run evidence opens the inspector.
  - A missing route (bare 404, or 503 `postgres_route_not_wired`) reads "not available from this server yet".
- **Origin relations** appear only for targets that can take part (the server's binding rule):
  - **Hostname / non-IP URL:** Declare origin relation lists only existing declared IP or IP-URL targets with `dns_verified` or `user_confirmed` proof. They are read through `/v1/targets?kind=ip|url`, a bounded read that says when it is truncated. Unverified ones are named but not selectable, and nothing is discovered. Optional port and path are validated. The review shows the exact protected and origin IDs. `POST /v1/origin-bindings` sends `{ protected_target_id, origin_target_id, scope? }` only. Archive goes through `POST /v1/origin-bindings/:id/archive`.
  - **Origin IP:** lists the relations that name it. Review origin check requires choosing one approved `host_sni_bypass` check; the server's catalog has several and none is picked for you. It sends `{ check_id, target_group_id, target_id, origin_binding_id }` with no host or destination override.
  - Reachability is shown only when the profile names a finalized bound observation, and always as "not an origin lockdown or capacity assurance".
  - Read-only roles see relations without controls.
- **Finding lineage** comes from `GET /v1/findings/:id`:
  - Original evidence, explicit retests (`lineage.retests`, with the most recent marked) and later runs of the same target and check without retest intent are shown apart. Each run opens its own result in the inspector, with no run-detail hop.
  - Closure shows `closed_at` and says closure is not proof of a fix and never closes other targets.
  - Review retest sends `retest_of_finding_id` with the finding's exact target and check.
- **Artifact rows are no longer `role=button`:** a row click is a pointer convenience, the View button is the only keyboard target, and focus returns to it. This fixes the axe `nested-interactive` error.
- **Dashboard posture** counts a run only when it names a recorded verdict (`verdict.id`, `verdict_id`) or evidence. A completed status or a bare verdict string reads "Not recorded". An earlier backed verdict behind a newer unbacked run is labelled "Earlier run; newest has no recorded verdict".
- Passive scan polling from the target page sends `advance=false`; the server's scan GET is already read-only.

Pass 4 verification:
- Owned unit set: 186 pass. Adds origin role, candidates, scope, error mapping, observation presentation, lineage, wiring, and dashboard unbacked and earlier-verdict cases.
- Journey spec: 33 pass. A third, separately seeded block adds:
  - layer state, a confirmed change, a version gap, paging and a stable selection;
  - a failed read with Retry;
  - declaring a relation (only the verified origin offered, invalid port rejected, exact body, archive);
  - a read-only role;
  - an origin check with an explicit approved check and exact body, plus the disabled state with the real catalog;
  - retests vs later runs, with the retest body carrying the finding, and a closed finding;
  - keyboard and focus on artifact rows;
  - unbacked dashboard runs;
  - axe at 375 and 1440 in both themes on all of these.
  - While dev-JSON `serviceDeps.targetHistory` is unwired, the observation and binding routes are called first and fall back to the same exported services only on 503 `postgres_route_not_wired`. Run starts are captured and never dispatched.
- a11y spec: 17 pass.
- Cross-owner specs touching these pages: 96 pass.
- Screenshots: `foundation-evidence/after-pass4`.

Not run: Postgres-mode browser runs, assistive-technology (screen reader) sessions, G1 design approval, G3 user research. Still missing from the backend:
- read-only scan reads (`advance=false`);
- a findings list total;
- observation history (`/v1/targets/:id/observations` stays a graceful 404);
- origin bindings.

## Findings paging, origin check choice and real history routes (recovery pass, 2026-10-04)

- **Findings list is server-driven** (`docs/backend/current-release-findings.md`). Status chips are exact single-status server totals (no multi-status predicate is sent; "Active", "Risk decisions" and "Closed" are display groups only). "Each finding" pages the server (`limit` 25/50/100, `page`), shows "Showing x to y of total" and "Page n of pages", and Next follows `has_more`. Search, severity and group are server predicates. "Grouped by issue" reads 200 per page only on request ("Read the next N findings") and labels groups partial until every match is read. Group detail reads members by exact `check_id` the same way. The dashboard and Findings "Open" counts are the server `status=open` total.
- **Exact counts without redundant reads.** Status chips and the dashboard open overview first read one 200-row page. When the server says that page holds every match (`total` reached, no `has_more`), the per-status and per-severity counts are taken from those rows with the server's own effective status and severity class. Otherwise each count is its own server total. The request-budget spec's route walk, including its Check library target selection, measures 30 `/v1` requests against a budget of 45 (26 before exact counts).
- **Stable list keyed on the rows on screen.** The live-update hold is keyed on the predicate of the displayed envelope (which lags the requested one while a read is in flight), so the answer to a filter, page or "read more" request applies at once and is never parked behind "Show updates". Same-predicate refreshes are still held while the pointer, focus or inspector is on the list.
- **Linked predicates are exact.** `#findings?target_group_id=…&status=…` (from Target groups or anywhere else) replaces remembered search, filters and page, also when it arrives while Findings is open, and keeps an unknown or archived group visible in the group filter.
- **Origin check choice comes from target-scoped reads.** The global `GET /v1/checks` intentionally excludes setup-input checks, and that guard is kept. On an origin IP target the section reads `GET /v1/targets/:id/compatible-checks`, keeps the `setup_required` pairs, reads each with `GET /v1/checks/:id`, and offers only definitions whose `probe_profile.kind` is `host_sni_bypass`. On an IP origin those are `origin.direct_reachability.safe`, `origin.direct_bypass.safe` and `waf.origin_bypass.safe`; the hostname-only `origin.host_sni_bypass.safe` is not offered. Loading, failed (with Retry) and empty states are distinct, and Review stays disabled until a real definition is chosen. The review shows the definition's `max_requests` bound.
- **Origin relation scope conflicts.** Declaring the same protected and origin pair with a different port or path returns `409 scope_conflict` with `existing_id`. The review closes, the form keeps its choices, and an alert names the existing relation and says nothing was changed; nothing is updated or replaced implicitly. The identical scope is an exact replay (`replayed: true`) and reads "already recorded; nothing changed".
- **Severity is a server class.** Severity filters and dashboard buckets use the server's canonical classes (`S2` is `high`, `moderate` is `medium`, unrecognized is `unknown`); each class is one query, so aliases are never counted twice.
- **History routes are real.** Dev JSON now wires `serviceDeps.targetHistory`; the journey's 503 fallback to exported services is removed. The real route serves `comparison_gaps` (CDN `check_version_changed`, DNS `provider_not_recorded` for `detected` rows with no vendor) and `provider_changed` changes with `before_provider`/`after_provider`; both render with their reason labels.

Recovery pass verification, final tree and final compiled bundle (isolated `ASTRANULL_DEV_DATA_DIR`, real dev API, no probes, no fallbacks or interception for the status contract):
- `web:typecheck`, `lint`, `lint:portal`, `safety`, `web:build`: pass. `git diff --check` on owned paths: clean.
- `tests/unit/current-release-findings-ui-paging.test.mjs`: 25 pass. Focused frontend unit set (23 files): 417 pass.
- `current-release-findings-paging.spec`: 11 pass. `current-release-evidence-target.spec`: 34 pass, including the inspector block on the baseline `state`-only finding and a real `409 scope_conflict` plus exact replay. `current-release-customer-pages.spec`: 27 pass. `portal-finding-count-truth-source.spec`: 1 pass. `tests/a11y/current-release-inspector.spec`: 17 pass (the first test once timed out on a cold Vite start in the full run and passed on rerun).
- Final full Playwright set (352 tests, final tree and final bundle, `/tmp/astranull-frontend-recovery-shots/playwright-all-4.log`): 351 passed, 0 failed, 1 skipped (the env-gated `ASTRANULL_PORTAL_SCALE=1` scale assertion in `portal-dashboard-overview-panels`). Focused frontend unit set (23 files): 420 pass. Earlier interim runs and the prior "remaining failures" list are superseded by the migrations below.
- Old specs migrated to the current-release contracts (owned from this pass), without deleting or loosening their intent:
  - `portal-executive-clarity`: the dashboard has no defense path (forbidden by `portal-executive-language.test.mjs`); it asserts the targets-first KPIs against `GET /v1/analytics/declared-hosts` and the `status=open` total, every WAF and CDN segment link name and href against the server segments, no cloud, origin or blocking claim in the observations region, and no raw codes. Overflow at 375, 768, 1024 and 1440 on Dashboard and Target detail is unchanged. Target detail asserts identity, ownership, declared context, group link, ownership proof in Target facts, compatible checks, and a real declaration-only (E1) catalog run reading "Declaration only" with "No live traffic was sent for this check."; the server `runs_empty_reason` renders once with no repeated body.
  - `vibe-annotations-verify`: local layout only (the vibe-annotations server is not needed and no approval is recorded). Removed annotations stay removed, no presentation switch, exact `Scope › Target detail` breadcrumb with the current page marked, a `Targets` back link, and single-column workspace geometry (title, tabs, panel, facts on one left edge, inside the viewport) at 1440 and 375.
  - `portal-provenance` dyn-04: a configured WAF posture (protected, then drift) changes `waf_posture` in the API but never appears as WAF detection or blocking; the WAF family stays "Not checked". An observation from the explicit `internal_simulation` producer updates the WAF layer history as "Detected … Not live evidence" and is not promoted into current detection.
  - `portal-state-coverage`: a real 404 shows the shared record-missing state on the same address; a 403 shows access denied; a 500 with leaky text shows "Target details could not load." with Retry, the safe server copy, and none of the raw text; Retry then loads the real target.
  - `portal-validation-scan`: scan GETs are passive, so the live case asserts that polls alone change no stored step, then progresses the scan only through the explicit system runner tick, one active step at a time. Launcher, exact-target review, request bounds, Stop with reason, terminal polling stop, scheduling and auditor read-only cases are kept. The standalone scan page itself is unchanged.
- Product fix from this migration: a failed target read showed the raw server `error` text for a 5xx and looked like an empty state. It now uses the safe copy and a distinct alert with Retry (`lib/target-detail-api.ts`, `pages/target-detail-view.tsx`).
- Screenshots after the final build: `/tmp/astranull-frontend-recovery-shots/*.png`, including the target failed-read state at 1440 dark and 375 light.

Not run: Postgres-mode browser runs, screen reader sessions, G1 design approval, G3 user research.

## Dashboard beside the docked inspector, and the served scale case (recovery pass, 2026-10-04)

- **Width-aware dashboard.** The dashboard is a size container (`.dashboard-page { container: dashboard / inline-size }`) and its breakpoints read its own width, not the viewport: below 880px the fix list and the posture table stack (each needs about 320px and 520px), below 720px the readiness and findings split panes stack, and below 480px rows go single-column. The dashboard's three-column tables use a 32rem minimum instead of the shared 780px table minimum, and keep their own scroll region below that. The 1360px dock breakpoint is unchanged. Measured with the dock open at 1440px: before, a 229px fix column (139px titles) beside a posture table clipped by 443px; after, one column at 638px, 548px fix titles, two 311px metric columns and no clipped table. At 1512px: 247px before, 596px titles after, nothing clipped. Brand, fonts, header, focus and scroll behaviour are unchanged; no card surface was added.
- **Authoritative declared scope.** Declared targets and distinct hostnames come from the server `units` of the declared-host analytics already read for the observation cohorts (no added request). The ownership-verified count uses the loaded rows only when they are that whole scope; otherwise it sums exact `verification_state` totals. Cohort link names now format counts the way they are shown ("5,000").
- **Served scale case.** `portal-dashboard-overview-panels` FT-DASH-04 runs with `ASTRANULL_PORTAL_SCALE=1`: 10,000 groups, 5,000 targets and 100,000 real finding rows (every third open, 33,334, matching the state rollup). It checks a bounded 50-row page with the full 5,000 total and separate record and hostname units, the dashboard metrics (5,000 declared, 33,334 open), the exact WAF cohort list (1 to 50 of 5,000), and the open-findings link reaching the same 33,334 total with real paging.
- **Verification:** `current-release-dashboard-dock.spec` 7 of 7 (docked 1440 and 1512 in both themes: keyboard open, single-column readable context, unclipped table with the verdict column on screen, axe, Escape returns focus to the trigger and keeps the scroll position, two columns again after closing; undocked 375 sheet, 768 and 1024 drawers with no overflow and focus restored). With scale enabled, the dashboard-affected browser files pass 46 of 46 (overview panels including FT-DASH-04, executive clarity, request budget, truth source, findings paging, dock, current-release a11y), plus the cohorts block 8 of 8. Focused frontend unit set: 423 pass. Typecheck, lint, portal lint, safety, diff check and the final build pass. Screenshots: `/tmp/astranull-frontend-recovery-shots/dock-before-*.png`, `dock-after-*.png` and `dashboard-undocked-*.png`.
