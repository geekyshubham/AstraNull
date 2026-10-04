# Current-release report scope and snapshot

Report generation still uses the existing create and export services. Scope and the generation snapshot are additive fields on `reports.summary_json`. There is no new column and no migration.

Shared helpers live in `src/lib/reportSnapshot.mjs` and are re-exported from `src/services/reports.mjs`: `parseReportCreateBody`, `reportPeriodBounds`, `worldFromListSamples`, `buildGeneratedReportRecord`, `reportExportSources`, `readinessExportText`, `loadDevReportWorld` (dev store only), and the caps `MAX_REPORT_SCOPE_IDS` (100), `MAX_CAPTURED_RUNS` (10), `MAX_SNAPSHOT_FINDINGS` (100), `MAX_SNAPSHOT_EVIDENCE` (100), `MAX_DECLARED_MEMBERS` (100). The module is pure: it does not open a database. Postgres scope rows come from `readReportGenerationWorld` on `src/persistence/postgres/reportRepository.mjs`. That method is optional. It is not part of `REPORT_REPOSITORY_METHODS`. A repository without it still lists the newest 10 runs for an omitted scope, and returns `report_scope_unavailable` for an explicit scope.

`POST /v1/reports` and `GET /v1/reports/:id/export` pass the body through and gate `report:create` / `report:read`. This pass does not edit the server. A scope failure returns `{ error, status: 400, ... }` from the service and writes nothing. The route maps that service error onto the HTTP status.

Inspection (`getReport`, `listReports`) does not write a file, an export audit row, or a notification. Create audits `report.generated` only after the row is stored. Export audits `report.exported`.

## Create body

Existing fields stay: `kind`, `title`, `period`. Omitted scope is the tenant estate (`scope.selection = omitted_defaults_to_tenant`). That is not "zero targets".

Exact scope:

| Field | Rule |
| --- | --- |
| `target_ids` | Omitted: not set. Present `null`, `[]`, a bad id, or a duplicate: `invalid_scope`. More than 100: `scope_too_large`. |
| `target_group_ids` | Same rules. |
| `run_ids` | Same rules. Caller order is kept. `primary_run_id` is always `null`. |

Unrecognized scope keys fail with `unrecognized_scope` and `fields` before any write: `target_id`, `targets`, `target_group_id`, `group_id`, `group_ids`, `groups`, `scope`, `cohort`, `cohort_id`, `cohort_ids`, `window`, `filters`, `filter`, `evidence_ids`, `finding_ids`, `primary_run_id`, `run_id`, `check_ids`, `estate`, `workspace`, `all`, `all_targets`. Other unknown keys are ignored and are not stored or audited.

Other failures, also before insert, audit, or notification: `unknown_target`, `unknown_target_group`, `unknown_run`, `inactive_target`, `inactive_target_group`, `scope_mismatch` (`target_not_in_group` or `group_has_no_requested_target`), `run_outside_scope`, `run_outside_period`, `run_time_not_recorded`. A missing id and another tenant's id use the same unknown code. Explicit group membership above 100 declared targets is `scope_too_large` (`field: declared_members`). A repository that cannot load `readReportGenerationWorld` returns `report_scope_unavailable` for explicit scope and does not guess the estate.

Membership is `targets.target_group_id`. Both target and group ids require every target to sit in one of the named groups, and every named group to contain one of the named targets. Group-only scope expands to active declared members. Target-only scope does not add siblings. Deleted targets and archived or deleted groups are inactive.

## Period

`period` still lives in `summary_json` and is projected to `period`. Omitted or unknown is `not_recorded`. `all-time` is unbounded. `last-7-days` and `last-30-days` are `[as_of - N days, as_of]`. `quarter` is the UTC calendar quarter start through `as_of`. The end source is the generation clock.

Omitted runs outside the window are excluded and counted (`run_capture.excluded_by_period`). Explicit run ids outside the window, or with no `started_at`/`created_at` inside a bounded window, fail closed.

## Snapshot shape

`summary.as_of` is the generation clock. `summary.as_of_source` is `report_generation_clock`.

`summary.run_ids` matches the `reports.run_ids` column. Omitted runs keep the newest 10 by `started_at` or `created_at`, then id. `run_capture` records `total`, `included`, `excluded`, `total_status`, `excluded_by_period`, and `source: test_runs.started_at_or_created_at`. A capped page does not become the estate total: when the total is known, `total` is the full count; when a legacy list cannot count past its cap, `total` is `null` and `total_status` is `unknown`.

`summary.evidence_ids` are the first-seen refs on the included verdicts and finding items. They are not a second estate scan and not a ranking.

`summary.findings_snapshot`:

- `as_of`, `source: findings_at_generation`, `lifecycle: status_at_generation`
- `predicate`: `scope_and_period`, or `scope_and_explicit_run_ids_and_period` when `run_ids` were sent
- `total`, `included`, `excluded`, `excluded_by_period`, `open_total`, `complete`, `total_status`
- `items[]`: `id`, `target_id`, `target_group_id`, `test_run_id`, `check_id`, `title`, `severity`, `status`, `evidence_ids`, `created_at`, `updated_at`

`summary.open_findings` is that full open count, not the length of the capped item list. `open_findings_semantics` repeats `total`, `predicate`, `source`, and `total_status`.

`summary.runs_snapshot` and `summary.verdicts_snapshot` are the included rows at generation. Verdict explanations are scrubbed at capture. `placement_confidence` is not stored. `summary.evidence_summaries.items` are `id`, `test_run_id`, `label`, `created_at` from `evidence_vault` with no metadata. `summary.declaration_snapshot.items` use the stored declaration (`purpose`, roles, owner, criticality) when members were loaded. `summary.sections.protection_profile` is `not_included` / `no_frozen_protection_profile_on_declared_target`.

`summary.snapshot_frozen` is true for a world captured at generation. Export of a frozen report uses `runs_snapshot` and `verdicts_snapshot`. It does not reread live runs, verdicts, or findings. A later finding closure or a newer passing run leaves the stored summary and that export unchanged. A report with no frozen snapshots still exports through the live run and verdict lookup.

`summary.scope` records `mode` (`tenant`, `targets`, `target_groups`, `targets_and_groups`, `runs`), `selection`, the requested ids, `declared_member_ids`, member totals, explicit `group_refs`, and the period bounds. `primary_target_id` and `primary_run_id` are `null`.

## Score

The published readiness formula is tenant-wide. Omitted scope keeps it: a numeric `readiness_score` and factor array when the dev formula or the Postgres state service is available. Postgres report creation without those state dependencies keeps the existing fallback object on `readiness_factors` (`status: postgres_report_readiness_summary_not_wired`) and `readiness_score: null`.

Explicit target, group, or run scope does not reuse that formula. `readiness_score` is `null`, `readiness_factors` is `[]`, `readiness_score_status` is `unknown`, `readiness_score_scope` is `not_target_scoped`, and `readiness_score_reason` is `published_readiness_formula_is_tenant_wide`. There is no second client score.

## Support time

Support audit rows expose `timestamp` and `timestamp_source`. `audit_log.timestamp` wins. A row that only has `created_at` (the Postgres tenant-detail alias of `timestamp`) maps to `timestamp` with `timestamp_source: audit_log.created_at_alias`. When both are missing, `timestamp` is null and `timestamp_source` is `not_recorded`. `summary.as_of` and `support.as_of` use `subscription_summary_clock` (or `not_recorded` on the empty Postgres summary). No SLA, support hours, or contact fields are added.

The support page still reads `recent_audit.created_at`, so event times stay blank until that read uses `timestamp`. `tests/unit/postgres-subscription-service-adapters.test.mjs` asserts `as_of`, `as_of_source`, `timestamp`, and `timestamp_source` (`audit_log.created_at_alias` when the row only has the tenant-detail `created_at`).

## Evidence context

An evidence-context reader can use the stored summary without recomputing today's estate:

- `summary.as_of`, `summary.as_of_source`
- `summary.run_ids` (same as the column; no primary)
- `summary.evidence_ids`
- `summary.findings_snapshot` (`items` plus the total and exclusion fields above)
- `summary.snapshot_frozen` to know the rows are the generation copy
