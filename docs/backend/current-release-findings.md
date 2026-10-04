# Current-release findings list

`GET /v1/findings` reads one tenant-scoped predicate in the dev store and Postgres. The route owner forwards the query below and returns `result.status` when the envelope has `result.error`. This document does not change `docs/api.md`.

## Query

Forward these names only: `q`, `status`, `severity`, `check_id`, `target_group_id`, `target_id`, `test_run_id`, `limit`, `page`.

Omitted `status`, blank `status`, and `status=all` include every stored status. The server does not default the list to `open`. Any other status is `400 invalid_query_value`. Lifecycle values are `open`, `in_progress`, `accepted_risk`, `resolved`, `closed`, `false_positive`, and `accepted`.

The stored row's **effective lifecycle status** is the first non-blank trimmed lowercase value of `status`, then legacy `state`, else the `open` fallback — the same contract as the portal `findingStatus`. A legacy dev-json row recorded with `state` only still matches its lifecycle query (`status=open` matches a `state=open` row, `status=closed` matches `state=closed`), and Postgres trims and lowercases before comparing (`lower(btrim(f.status)) = $n`). The projected fields keep their recorded shape; nothing is rewritten on read.

`severity` still accepts a token matching `^[A-Za-z0-9_.:-]{1,32}$` or `all`, but the comparison is the canonical severity class of the ported `normalizeSeverity` alias map (`findingSeverityClass`): `S1`=`critical`, `S2`=`high`, `S3`=`medium`, `S4`=`low`, `moderate`=`medium`, `info`=`info`, trimmed and lowercased; every other token is the `unknown` class, never `low`. A known alias query matches every stored token of that equivalent class in both directions (`severity=S2` matches `high` rows, `severity=high` matches `S2` rows), and a non-recognized query token selects the actually unknown recorded rows, not every row. PostgreSQL compares the same canonical CASE (`findingSeverityClassSql`), and projections keep the recorded value and detail unchanged. A malformed token is `400`, not a dropped filter. `check_id`, `target_group_id`, `target_id`, and `test_run_id` are exact ids (`^[A-Za-z0-9_.:-]{1,128}$`). An unknown id is `total: 0`.

`q` is a trimmed substring of at most 200 characters. It matches `title`, `id`, `check_id`, `target_id`, `target_group_id`, and `assignee` only. It does not search `notes`, `remediation_template`, evidence, or other metadata. Control characters are `400`.

`limit` is an integer from 1 to 200. The envelope defaults an omitted limit to 50 and an omitted page to 1. `page` is 1-based. `offset` is the array-caller form; when both `page` and `offset` are sent they must name the same row. Unknown names, `limit=0`, and a conflicting offset are `400` (`unknown_query_param` or `invalid_query_value`) with `field`.

`target_group_id` matches a finding whose stored `target_group_id` is that id, or whose `target_id` is a non-deleted target in that group in the same tenant. A deleted target does not extend membership. A same id in another tenant does not match.

There is no 5000-row cap. `count` and `total` are the full match count, including rows outside the loaded page.

## Response

```json
{
  "items": [],
  "count": 0,
  "total": 0,
  "page": 1,
  "pages": 0,
  "has_more": false,
  "limit": 50,
  "meta": { "empty_reason": "No findings have been published for this tenant yet." }
}
```

`items` is the page, scrubbed the same way as finding detail (`notes` and `remediation_template` only). `count` equals `total`. `pages` is `0` when `total` is `0`, otherwise `ceil(total / limit)`. `has_more` is true when later pages exist. A page past the end has `items: []`, the real `total`, and `empty_reason: null`. `empty_reason` is set only when `total` is `0`, and it names the first active filter in this order: target group, target, test run, check, status, severity, search. The unfiltered empty list uses the tenant sentence above.

Invalid queries return `{ error, message, field, status: 400 }` and do not run the list. The route must use that `status` instead of `200`.

`listFindings` stays an array for existing callers. Omitting `limit` returns every match, with no default of 50. The same invalid query throws `FindingListQueryError`. Publication locks (`forUpdate`) stay an exact group, target, and check tuple across every status and do not use this page predicate.

Postgres computes the count and the page in one SQL statement, so both read the same READ COMMITTED statement snapshot even when a concurrent writer commits in between. That single statement binds the tenant id (`$1`) in an explicit `WHERE f.tenant_id = $1` predicate and every filter as numbered parameters; it left-joins a bounded page (`LIMIT`/`OFFSET`) against the full match count so an out-of-range or empty page still reports the real total. The list does not derive a verdict.

## Tests

`tests/unit/current-release-findings-pagination.test.mjs` covers the dev predicate, a page larger than the limit, page 2, group and status parity, canonical severity alias classes plus unknown rows and legacy `state`/missing-lifecycle effective status, search that ignores notes, unknown ids, and invalid queries, and the SQL shape (explicit tenant predicate, trimmed status comparison, canonical severity CASE, no raw `f.severity =`).

`tests/integration/postgres-current-release-findings-pagination.test.mjs` covers the same predicate through the app role, including tenant isolation, the one-statement count/page snapshot, an out-of-range page that keeps the real total, empty totals, severity alias parity (`S1`/`S2`/`moderate` tokens against named classes, unknown-class-only rows), padded open status parity, and list/count page agreement, when the local harness is already up (`tryDocker: false`).
