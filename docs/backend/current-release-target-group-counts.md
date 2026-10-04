# Current-release target group open findings counts

`GET /v1/target-groups` list items carry an authoritative `open_findings_count` per active (and archived-view) group. The count is computed from the whole tenant's findings, never from a capped findings page, so a group can link its full open set to the findings list (`#findings?target_group_id=<id>&status=open`).

## Count definition

`open_findings_count` is the **exact `open` lifecycle only**. This mirrors the portal `isFindingOpen` contract (`apps/web/react/src/lib/finding-lifecycle.mjs`): the effective status is the first non-blank trimmed lowercase value of `status` then `state`, else the `open` fallback, and it must equal exactly `open`.

- `in_progress` is part of the UI **Active** bucket, not the open count, and is excluded here.
- `remediation_pending` was a legacy alias and is not counted.
- Closure statuses (`accepted_risk`, `resolved`, `closed`, `false_positive`, `accepted`) are never counted.
- The group count and its `status=open` findings link must agree: the findings list `status=open` total for the same group equals `open_findings_count`.

A legacy dev-json row recorded with `state` only (no `status`) still counts and filters by its effective status; a row with neither field is the `open` fallback. Postgres `findings.status` is `NOT NULL DEFAULT 'open'`, and the SQL trims and lowercases before comparing.

Group membership for counting is the same predicate the findings list uses for `target_group_id`: a finding counts for a group when its **stored** `target_group_id` is that id **or** its `target_id` is a non-deleted target whose group is that id (same tenant for every branch). A finding can therefore match two groups once (stored group plus a moved member target), so per-group counts are per-finding links, and their **sum is not a unique tenant total** when membership overlaps. Use the state-level authoritative global open count for any overall KPI instead.

## Sources

**Dev JSON** (`src/services/targetGroups.mjs`): one collection pass over the tenant's findings with `isGroupOpenFinding` plus a target-id → group map; no N+1 and no capped page. A zero is an actual counted zero, never "data missing".

**Postgres** (`src/persistence/postgres/coreCatalogRepository.mjs` `listTargetGroups`): one parameterized `SELECT` joins a grouped aggregate (`UNION` of stored-group rows and non-deleted member-target rows, `lower(btrim(f.status)) = 'open'`, tenant-bound at `$1`) onto the group rows. It is a single statement in one query snapshot, not a query per group, and the rows are forwarded by `createPostgresCatalogServices` without stripping the field.

## Shape

Additive only, forwarded as-is by the existing `GET /v1/target-groups` envelope:

```json
{
  "items": [
    { "id": "tg_1", "name": "Counted", "target_count": 1, "loa_state": "signed", "open_findings_count": 3, "...": "existing fields unchanged" }
  ],
  "count": 2,
  "meta": { "empty_reason": null }
}
```

`open_findings_count` is always a finite integer on list items. Missing/unknown lifecycle can only fall back to open or a closure; there is no "not counted" state in this payload, unlike the detail page's distinct missing-field marker.

## Statuses and links

| Finding status | Counted in `open_findings_count` |
|---|---|
| `open` (also padded/case variants, or missing lifecycle) | yes |
| `in_progress` | no (Active bucket) |
| `remediation_pending` (legacy) | no |
| `accepted_risk`, `accepted`, `resolved`, `closed`, `false_positive` | no |

Findings of another tenant never count, even with identical row ids.

## Tests

- `tests/unit/current-release-target-group-counts.test.mjs` — >50-finding whole-tenant counts, shared-predicate membership (moved/inconsistent), exact-open counting with in_progress/closure exclusions, legacy `state` and missing-lifecycle fallback, foreign tenant, real zeros with deleted membership skipped, additive envelope shape.
- `tests/integration/postgres-current-release-target-group-counts.test.mjs` — same predicate through the real app-role RLS pool (`NOSUPERUSER`/`NOBYPASSRLS`), one recorded SQL read with the grouped aggregate (no `f.status IN`, no `LIMIT`), count parity with `status=open` list findings, tenant isolation, zero group, adapter forwarding without a stripped field.
