# Current-release readiness posture and SOC governance gates

`GET /v1/state` publishes `readiness.posture` and `readiness.governance.pending_gates` from `projectReadiness()` in `src/lib/readinessProjection.mjs`. The dev JSON store and the Postgres state adapter (`src/persistence/postgres/stateServiceAdapters.mjs`) call the same projection, so both return the same shape (pinned by `tests/integration/postgres-state-portal-parity.test.mjs`).

## `readiness.posture`

Counts are target/check scenarios (`coverage.unit = "target_check_pair"`), never the check catalog.

| Field | Meaning |
|---|---|
| `pass` | Scenarios with a current, conclusive protected result. |
| `gap` | Scenarios with a current, conclusive exposed result. |
| `not_run` | Applicable scenarios with no observation yet. Equals `coverage.not_run_count`. |
| `review` | Everything else that ran: inconclusive, stale or partial results. |
| `total` | `coverage.applicable_count`. |

`pass + gap + not_run + review === total`. `not_run` is additive. Before this change, never-run scenarios were counted in `review`, so a workspace with no runs showed every scenario as needing review.

Portal rendering (`apps/web/react/src/lib/readiness-posture.ts`, `components/charts/readiness-posture-donut.tsx`):

- The donut paints `not_run` in a muted neutral and never in the warn tone. The footnote reads `{n} of {total} applicable checks have a result this cycle`, where `n = pass + review + gap`.
- An older server that omits `not_run` falls back to `total - pass - review - gap`.
- Without a server posture, the client counts only runs with a recognised verdict. An unrecognised verdict is ignored instead of being counted as review, and when nothing has a verdict, the total is 0 and the empty state shows. The donut never falls back to the size of the check catalog.

## `readiness.governance.pending_gates[]`

| Field | Meaning |
|---|---|
| `requestId` | High-scale request ID, used only to link to `#queue-detail?id=…`. |
| `state` | Request state. |
| `label` | `request.objective`, else `request.reason` (whitespace collapsed, at most 80 characters), else `"High-scale request"`. |
| `missing` | Human-readable gate gaps (counts only). |
| `missing_artifacts` | Required authorization artifact types without an accepted artifact (raw array). |
| `approvals` | Distinct SOC approvers recorded (2 required). |
| `pack_complete` | `true` when every required artifact is accepted and its validity and scope match the request. A gate with no missing artifacts but `pack_complete: false` has an artifact that is expired or out of scope. |

The `soc_readiness` factor `detail` and the governance evidence lines contain no request IDs and no artifact type lists. They name a request by its label (`High-scale request "Checkout launch surge rehearsal"`) and summarise the gaps as counts, for example: `Pending gates remain on 2 high-scale requests: 5 missing accepted artifacts, 2 awaiting SOC approvals (2 required).` The dashboard renders one line per gate with a `Review request` link. Each line names every open gap: missing artifacts, or `Authorization pack incomplete` when nothing is missing but validity or scope does not match, plus `SOC approvals a/2`. Approving, scheduling and executing high-scale requests stay SOC-only on the server. This read model adds no customer action.

No schema migration is needed: both fields are computed at read time from existing request, artifact and approval rows.
