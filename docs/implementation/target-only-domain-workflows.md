# Direct target and domain workflows

Requested 2026-10-08: remove target-group navigation, screens, selectors, columns, links, and workflow requirements. Customers select a declared domain/endpoint or an explicit set of declared domains/endpoints directly.

## Acceptance criteria

- All customer workflows use targets: intake, ownership, checks, assessments, schedules, findings, reports, integrations, exports, and governed test requests.
- No group screen, picker, breadcrumb, column, count, public request field, or customer-visible grouping requirement remains.
- Single-target operations bind to `target_id`; multi-target operations bind to explicit `target_ids`. Opening or selecting domains never dispatches traffic.
- Direct target creation, update, removal, CSV import, and ownership workflows do not need a grouping identifier.
- Existing target IDs, historical evidence, schedules, and audit records survive the transition. Historical storage is not erased to change the customer model.
- Tenant isolation, ownership, subscription, request caps, safe windows, rate limits, concurrency controls, signatures, and SOC approval remain enforced against the selected targets. A model change cannot reset existing execution budgets.
- Reads and previews remain passive. Unsupported target/check pairs and missing setup remain explicit.

## Implementation sequence

1. Inventory every public group dependency and establish the target-only API and domain-selection contract.
2. Add direct target operations and resolve existing execution-policy bindings on the server. Migrate stored selection scope without deleting target/evidence history.
3. Support explicit domain sets in assessment and schedule planning, execution, recurrence, stop, and progress. Evaluate each selected target's policy before dispatch.
4. Replace all customer group selectors with direct domain selection; remove group routes and presentation in navigation, targets, checks, schedules, findings, reports, integrations, exports, and SOC requests.
5. Update current product/API/architecture documentation and `PROGRESS.md`.
6. Verify API and persistence parity, tenant isolation, cross-policy domain sets, safety-budget continuity, ownership, recurrence, Stop, and SOC gates. Exercise all affected browser journeys with no visible group wording or group requests.
7. Commit, deploy through CI, and verify direct domain workflows on the live tenant.

## Implemented locally

- Direct target API selection and direct representations; no customer grouping dataset hydration.
- Group navigation/screens/picker deleted; old bookmarks route to Targets.
- Direct intake/removal/CSV, DNS challenges, and target authorization.
- Explicit multi-domain assessment and scheduling, per-target policy bindings, scoped history and Stop.
- Direct schedule creation retains partial successes and retries failed domains only.
- Target-only findings filters, detail contexts, report scopes, integrations, and coverage matrices.
- Exact selected-target scope for governed requests and artifact authorization.
- Independent domain authorizations with transactional overlap protection (migration 0072); historical custody remains intact.
- Legacy scheduled assessments freeze original domains rather than expanding after intake.
- Local verification is complete; CI rollout and production verification follow the implementation commit.

## Current state

The detection/catalog release (`a845930f`) has deployed successfully. Live detection records one HTTP baseline and bounded DNS work without the previous marker-scan timeout; the live catalog shows 251 definitions and 147 automatic network checks. This target-only change is a separate in-progress migration of the product model.

## Verification

- Full isolated `make verify`: 4,724 unit cases passed; 468 integration cases passed with one explicitly opt-in live-DNS case skipped; 21 Node E2E cases passed. Lint, safety, schema, tenant-query audit, taxonomy, generated catalog and corpus parity passed.
- All 16 API contract tests passed. Typecheck/build and portal lint passed.
- The additional direct detection/OpenAPI contract checks passed (22 cases), including no caller-controlled destination, exact target binding, asynchronous acceptance and direct presentation.
- Browser review covered the full customer journey inventory, followed by reruns of every changed or failing journey. Exact scope, report snapshots, direct intake/CSV/ownership/removal, assessment/recurrence/Stop, permissions, live activity, findings paging/lineage, firewall comparisons, and light/dark accessibility at 375–1440px passed. Legacy group-screen assertions were replaced with direct-domain assertions; stored group compatibility remains tested in backend lanes.
- Legacy bookmarks resolve to Targets; no customer grouping catalog is hydrated. Separate concurrent provider-classifier work is excluded from this implementation commit.

Production rollout remains pending until the CI-triggered deployment and authenticated production checks complete.
