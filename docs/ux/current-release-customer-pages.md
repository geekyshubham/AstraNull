# Current-release customer pages: implementation note

2026-10-04. This note covers the customer pages implemented in the current-release slice. It records what was built, which acceptance items each page addresses, and what is still blocked.

Authority applied:
- AGENTS.md and ADR-0008 (outside-in only)
- PRODUCT.md and DESIGN.md: pure-black option A, the existing fonts, orange accent, theme tokens and shared primitives
- docs/feedback/24 (scope) and docs/feedback 19–23 (task contracts)
- the per-page reviews
- docs/implementation/current-release/contracts.md

**Status:**
- No human visual approval is claimed.
- No representative user research was run.
- G1 (visual approval) and G3 (task study) remain **Not run**.

## Design inputs

**Design read:** Operate-mode customer console pages for security and compliance engineers. The language is calm and restrained, on the existing AstraNull system. Dials: variance 3, motion 3, density 6.

**Skills used:**
- Design & Taste: Operate pre-flight and interaction states
- Impeccable product register: shape, clarify, harden, adapt and polish references
- installed interaction-design
- UI/UX Pro Max design-system search

**UI/UX Pro Max output, accepted:**
- flat surfaces, no gradients
- 150–200 ms transitions
- visible focus and reduced motion
- tables that scroll inside their region
- checks at 375, 768, 1024 and 1440 px

**UI/UX Pro Max output, rejected:** the Matrix-green palette, the Plus Jakarta font and the landing pattern. DESIGN.md wins.

**Candidate review:**
- Candidates were rendered with the isolated-store Playwright helpers in both themes at 375, 768, 1024 and 1440 px.
- 200% zoom was emulated as 640 CSS px wide, which is equivalent to 1280 px at 200%.
- A seeded long group name exercised long content.
- Screenshots are local review evidence under `/tmp/astranull-current-release-orchestration/customer-pages-shots/`. They are not committed.
- "Before" is the retained current-app evidence in `docs/feedback/evidence/`.

**Critique passes changed these:**
- Schedule columns broke inside words. Next-run icons sat on their own line.
- Phones now stack schedule rows as labelled cards through the shared `.rf-stack-table`.
- Next-run instants now show the year when it differs from the current year.
- Check detail: the clipped safety-bound badge became text, and the two tables were stacked.
- Long group names no longer push columns off-screen.
- Check-library fit moved next to the vector name.
- Report snapshot grid rebalanced.
- Neutral facts no longer use the orange `info` tone. Configured and enabled are muted.
- Audit date filters restyled.
- Settings tab panels are now actually hidden. The shared `.tab-panel` display rule overrode `hidden`.
- Release evidence filter field sizing fixed. The ledger of attached records moved above the full missing-kind list.

## Pages

| Page | What changed | Acceptance addressed |
| --- | --- | --- |
| Target groups | Name first, with purpose and copyable ID. Explicit "Owner not declared" and "Criticality not declared". "Latest result" names the check, target and time. "Targets with a result" is shown as N of M from recent runs; "None checked" is never shown as healthy. No group is preselected for Add target. Search and archived toggles live in the URL. Inline field errors. "Open findings" per group is the server's `open_findings_count` from `GET /v1/target-groups` (exact `open` status, stored group or member target; in-progress findings belong to the Active bucket and are not counted), linked to `#findings?target_group_id=<id>&status=open`, whose total equals the count; a missing field reads "Not recorded", never 0. The workspace KPI is `GET /v1/state` `open_findings` (status open, each finding once), never a sum of group counts, which can overlap. A focused link inside a row keeps its own Enter. | target-groups P2 #1–#3; doc 23 missing-data vocabulary |
| Check library | One presentation, with the variant switch removed. Target-first selector, deep link `#checks?target=`, no substitution. Three separate counts: catalog vectors, runnable checks, and checks that fit the target. The last is the count of safe checks from `GET /v1/targets/:id/compatible-checks`, shown as "Checking" or "Unavailable" until it loads. Advanced filters collapsed, with an active-filter summary and Clear. Review lists the mapped checks and links to the exact check detail with target context. Launch keeps the existing review → confirm → POST and rechecks gates on the server. | checks P1 #1, P2 #2–#3; TF-04, TF-05 |
| Check detail | Exact `GET /v1/checks/:id`, with not-found (no substitution) and error-with-Retry states. Target compatibility comes from `GET /v1/targets/:id/compatible-checks` (loading, error, not-found, compatible or not), and "Schedule this check" is offered only when the server says the caller target is compatible. Caller context from `policy`/`target` parameters, with Back to schedule or target. Plain sections for what is sent, observed and evaluated. Where it can run (kinds, setup, bounds). Latest result names its target and time, with a staleness note at 30 days or more. Results open the shared evidence inspector, not run detail. Taxonomy sits under Technical details. "Schedule this check" carries the check and a compatible target. | check-detail #1–#3; TF-05; EI-01 (check_result entry) |
| Validation schedules | Refined presentation is the only one. Check name links to `#check-detail?id=…&policy=…&target=…`. Timing uses the recorded IANA timezone plus viewer time. Next run comes only from server `next_run_at`, never a cadence projection. Each row states why it is or is not dispatching. Edit, Pause/Resume (only from active or paused) and Archive call the real PATCH/DELETE. Edit changes only mutable fields; the binding is read-only, with a dirty-close guard. Create adds a timezone field, a day selector, a check search and a review list of the exact records. State filter is in the URL. | test-policies #1–#3; TF-09 |
| Schedule detail | "Will this schedule run?" with reason, next run and viewer time. Immutable binding links. Dispatch gates named by effect; an optional safe window is information, not "missing". Contextual Edit, Pause, Resume and Archive that refresh this entity. Dispatch history opens the evidence inspector. Explicit 404 versus load-error states. | policy-detail #1–#3; TF-09 |
| Reports | Audience or framework mapping (SOC operational kind excluded) → period → scope (whole workspace, selected target groups, or selected targets) → explicit Review → Generate → snapshot preview → explicit Export. A caller `?group=` or `?target=` preselects that exact ID. An ID not visible in the workspace stays listed with "Nothing else was selected in its place" and a Remove action, and blocks review. Scoped modes, the per-report ID limit, the declared-member cap and the run capture limit come only from the report capabilities (`capabilities.scope.fields`, `max_ids`, `declared_members_cap`, `capture.runs_when_run_ids_omitted`). If capabilities are missing, scoped modes are disabled and the caller ID is stated as not applied, with no silent switch to whole workspace. `POST /v1/reports` sends exact `target_group_ids` or `target_ids` arrays and omits them for the whole workspace. It sends no scalar aliases and no `run_ids` scope. Scope errors (HTTP 400: `unknown_target_group`, `scope_too_large` and the others) are shown with the server's exact IDs and limits. Choices are kept. The review states that a scoped report has no readiness score (the published formula is workspace-wide). The history Scope and Generated columns come from `summary.scope`/`summary.as_of`. | reports P1 #1, P2 #2–#3; TF-12 |
| Report detail | Reads only the stored snapshot: scope (group names from `group_refs`), bounded period, declared members, `run_capture`, every stored run ID with its `runs_snapshot` row, the `findings_snapshot` table, every `evidence_ids` reference (artifact inspector), and declarations. "Open findings at generation" reads `findings_snapshot.open_total`. A null score shows the recorded reason ("the published readiness formula covers the whole workspace") and is never replaced by 0 or the dashboard value. Reports without `snapshot_frozen` carry a legacy banner and are never filled in from current data. "Current status" stays a separate live section. One Export menu (JSON, Markdown, HTML). "Verify custody" is an explicit POST. | report-detail #1–#3; EI report entry |
| Artifact detail | Integrity ladder: recorded hash, locally computed, server verification, not verified. Server verification now comes from the authoritative `primary.integrity` of the read-only `GET /v1/evidence-context?entry=artifact`; a top-level `verified` field is no longer trusted. A finding is linked only through explicit `evidence_ids`, never run proximity. Back goes to Findings or the finding, not the removed `#evidence`. Distinct read-failure, denied, not-found and metadata-only states. | evidence-detail #1–#3; TF-18 |
| Integrations | Connector table shows mode, state meaning, last successful sync and last attempt. "Validate" is now "Check configuration (does not contact the provider)". Poll runs on click and reports back in a status banner that states bounded read-only requests were sent with the stored credential. Disable copy fixed. Directory grouped by credential polling and manual metadata, with configured connectors first. Dirty-close guards on setup dialogs; a typed credential is discarded, never stored. | integrations #1–#3; TF-10 |
| Notification channels | Enabled/Disabled and "Last attempt" labels. `?focus=<rule id>` focuses and highlights the exact channel from a failure. | notifications #1; TF-11 |
| Notifications | Summary separates channels, delivered, failed or retrying, and recorded-not-sent. Selecting an attempt shows reason, attempt n of max, event, rule and a "Fix channel configuration" link to that rule. Retry needs a dry-run preview, then explicit confirmation that states duplicate risk and metadata-only mode. Retry-scheduled and unknown outcomes offer no retry. Routing can target a new or an existing channel (PATCH merges triggers and keeps the stored destination). Non-secret draft is kept; the destination is never kept. Bulk recovery is preview first. | notifications P1 #1, P2 #2–#3; TF-11 |
| Audit | Server-driven. `GET /v1/audit-log` takes the exact `actor`, `action` and `resource` filters, plus `since`/`until` built from whole days in the viewer's timezone, `cursor` and `limit=50`. The page shows the server `total`, with Newer/Older cursor paging. An incoming `#audit?event=` or inspector `audit` reference that is not on the current page is read by `GET /v1/audit-log/:id` and labelled "Loaded by exact ID; it is not on the current page of results." A 404 reads "does not exist in this workspace. Nothing else was selected in its place.", and errors offer Retry lookup. Filters are kept in the URL (`actor`, `category` for the action, `resource`, `from`, `to`). An inverted date range is rejected inline. "Recorded hash" makes no verification claim. Viewer and engineer get the access-required state. | audit #1–#3; TF-13 |
| Settings | Tab in the URL. Panels stay mounted, so safe drafts survive tab changes; vault plaintext fields reset when leaving Security. One-time secret is masked, with Reveal, Copy and a required "I have stored this secret" acknowledgement. Rotate and revoke name the exact account and state the impact; revoke requires typing the name. Scope format is validated. Retention shows units and bounds, and reductions open a review listing old → new per category. | settings P1 #1, #3, P2 #2; TF-15 |
| Support | Configured contact only, otherwise an administrator fallback, with no SLA. The snapshot shows `as_of` and its `as_of_source` clock. Counts are qualified, e.g. "Open findings, whole workspace (snapshot)". Each recent event shows `timestamp` per `timestamp_source`: the legacy `created_at` alias is marked "(legacy time field)", and a missing time reads "Time not recorded". Event "View" goes to `#audit?event=` for audit-readable roles only, and Audit resolves it by exact read. Copy-only summary with a credential-like note guard. No automatic sending. | support #1–#3; TF-14 |
| Plan & usage | Titled "Plan & usage". Units and windows per metric. Unknown never shows as zero or unlimited. Deferred high-scale usage widgets removed. Feature access is Available or Unavailable, with a reason and "what access does not mean". Next step is a configured contact or administrator. | subscription #1–#3 |
| Release evidence | Four separate dimensions: inventory, contract validity, external signoff, profile. Full missing-kind list with a filter; owner shows "Not recorded". Accepted-but-invalid records are flagged. Selecting a record shows why it fails, from missing and forbidden fields. Copy and JSON exports state that this is not launch approval. | release-evidence P1 #1, P2 #2–#3 |

## Address state

All page state written to the address goes through the foundation's sanitizing `replaceRouteParams`, so unknown or credential-like parameters are dropped. Keys used, all on the shared allowlist:

- Schedules: `status` (dispatch filter).
- Target groups: `q`, `view=archived`. Count links write `target_group_id` and `status` for Findings.
- Findings: a linked `status`, `severity` or `target_group_id` (aliases `group`, `target_group`) replaces remembered filters and page, also when it arrives while Findings is open. The first filter change removes those keys from the address.
- Check library: `target`, `q`, `page`.
- Check detail: `policy`, `target`. Its "Schedule this check" link uses `check`, `group` and `target`.
- Reports: caller `group` or `target`; it is read once and preselects that exact ID.
- Notifications: `focus` is the selected attempt. Integrations: `focus` is the channel opened from a failure.
- Audit: `event`, `actor`, `category` (action), `resource`, `from`, `to`.
- Settings: `tab`.

## Backend and shared dependencies (not implemented here)

**Backend items:**
- Resolved: `POST /v1/reports` returns 400 for scope errors, and scope capabilities are published on `GET /v1/reports` and `/v1/reports/capabilities`.
- Connector failures are recorded only on Postgres (`last_error_at`); the dev store exposes `last_success_at` alone. "Last attempt" is the newer of `last_success_at` and `last_error_at`, with its outcome. It reads "Not recorded" when the API does not record failures, and "Not applicable" for manual-metadata connectors. It never uses `updated_at` or poll requests. No new endpoint is assumed.
- Notification per-attempt read and single-attempt retry beyond metadata-only redrive. Unknown outcomes stay non-retryable.

**Findings list:** server pagination, filters and totals are integrated (`docs/backend/current-release-findings.md`). Target group counts use the server's `open_findings_count`. Report detail's "open now" section reads `status=open&test_run_id=<run>` per captured run (25 per run, with the remainder counted) instead of the loaded page. Evidence detail says when its finding lookup only covered the loaded page, because the list has no evidence-id predicate.

**Resolved backend dependency:** the list now uses one effective status (trimmed `status`, then legacy `state`, then `open`) in both stores, so the baseline's `state`-only `fnd_checkout_1` counts and filters as open everywhere. Severity filters compare canonical classes (`S2` is `high`, `moderate` is `medium`, anything unrecognized is `unknown`), so the Findings filter offers each class once and the dashboard counts one class per bucket (low includes info).

**Foundation:**
- Resolved: `router.tsx` passes `config` to `AuditPage`, and audit filter keys are on the shared allowlist.
- `portal-truth.spec.mjs` check-detail case: reassign to this owner once foundation is done.

## Tests and evidence (2026-10-04, working tree, isolated `ASTRANULL_DEV_DATA_DIR`)

Checks:
- `web:typecheck`: pass
- `lint`: ok
- `lint:portal`: ok, 0 hardcoded values
- `web:build`: ok; rebuilt for local verification only

Unit tests:
- `tests/unit/current-release-customer-pages.test.mjs`: 41 source contracts.
- With the four coupled suites: 76 of 76 pass.
- Full `test:unit` (previous pass, not rerun after the connector fix): 4,219 of 4,224 pass. None of the 5 failures are owned:
  - `current-release-navigation` finding-detail run-detail hop (foundation)
  - `live-staging-drills` (ops)
  - `postgres-portal-ownership-hardening` (backend)
  - `postgres-tenant-query-audit` ×2 (backend)

Owned Playwright run plus `tests/a11y`, completed after the latest rebuild: 123 of 123 pass. Request budget measured 26.
- `current-release-customer-pages.spec`: 27 of 27. Covers:
  - group-scoped report generation with exact body and preview
  - unknown caller group, and whole workspace sending no scope
  - 400 scope rejection keeping every choice, and unadvertised scope disabled
  - legacy and frozen report detail
  - audit server filters, cursor paging, exact read, 404 and inverted range
  - check detail exact read and compatibility, and check library server fit count
  - connector last attempt: not recorded without recorded failures, the newest outcome (succeeded or failed), and not applicable for manual connectors
  - axe on all 15 pages in dark and light, 200% zoom with reduced motion and keyboard, coarse pointer at 390px
- Updated old suites (current labels and flow, identity and safety checks kept):
  - `portal-confirm-and-feedback`: Check library, no implicit run, connector columns.
  - `portal-role-write-affordances`:
    - Auditor: review flow.
    - Viewer: no Review report or Generate report.
    - Viewer at `#internal-soc` (cold load): the existing gate keeps the address and shows "You do not have access to this page.", with no SOC controls, no SOC nav entry and no `/internal` or SOC requests.
    - Target detail: no Detect controls; the Validate tab shows "Read-only role" with no review, run or start control.
    - Finding detail: no Review retest or Start retest, and no open dialog.
  - `portal-notification-channels`: Enabled/Disabled.
  - `portal-interaction-feedback`:
    - Finding retest is review → confirm. Neither review nor cancel sends a request. A 409 shows an error, never success. Retest POSTs are answered in the browser, so no probe runs.
    - Report export is its own case.
  - `portal-request-budget`: six current sidebar routes plus one Check library target selection. Measured 26 requests three times, under the budget of 45. No "Test runs" entry.
  - `portal-finding-count-truth-source`: "Open findings" header, Findings summary stat and status-tab count.
  - `portal-truth`: check-detail taxonomy case only. Identifiers are hidden until the Technical details disclosure is opened by keyboard.
  - `portal-schedule-controls` and `portal-vector-library`: pass.
- Not completed: the earlier broad 320-test run of journeys, a11y and state stopped at 85/320. It was not rerun in full, so no broad-suite claim is made.

Changed-state screenshots (`/tmp/astranull-current-release-orchestration/customer-pages-shots/turn3/`), 9 states × dark/light × 375/1440, no horizontal overflow:
- reports: group review, unknown caller, generated preview
- frozen report detail
- audit: filtered and exact off-page
- check detail compatibility
- check library fit count
- support timestamps

The critique pass fixed the frozen open-findings count, the unstyled scope search input and the cramped preview values at 375px. No user research or approval is claimed.
