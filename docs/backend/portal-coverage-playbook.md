# Portal behavior-coverage playbook

How to bring one portal source file to strict behavior coverage mechanically. Read `docs/backend/05-test-strategy.md` (receipts and reconciliation) first; this page is the file-by-file procedure.

## What a cell is

The strict gate (`node scripts/validate-existing-behavior-coverage.mjs`) reconciles one cell per `source UI action x route x principal/role x dataset x state x channel`.

| Piece | Where it comes from |
|---|---|
| Source actions | `tests/helpers/portal-action-inventory.mjs` walks the shipped React AST (shell, router, hosts mounted by `App.tsx`). Id = `file#Owner:kind:<hash of the JSX element>`. |
| Roles and routes | Six customer roles, six staff roles, every route the role may open (`canAccessRoute`). Only permitted (role, route) pairs get cells. |
| States | `actionStateApplicability` in `tests/fixtures/portal-action-coverage.mjs`: `success`, `busy`, `empty`, `invalid`, `cancel`, `error-retry`, `denial`, `reload`. Each is `true` (a receipt is required), `false` (not applicable, with a source-derived reason) or `null` (unclassified, blocks the gate). |
| Eligibility | Resolved source guards (`authorizationGuards`) decide which identities get `success` and which get `denial`. |
| Evidence | A receipt from `assertPortalActionCell` after a real browser assertion, attached to a terminal-passing zero-retry Playwright result bound to the current source digest. |

Never hand-mark a cell not-applicable and never emit a receipt without a completed assertion. If a state is `null`, fix the inventory (below), not the test.

## Measure a file

```bash
export PATH=/opt/homebrew/opt/node@26/bin:$PATH
node -e "
import('./tests/helpers/portal-action-coverage.mjs').then(({ buildPortalActionCoverage }) => {
  const coverage = buildPortalActionCoverage();
  const file = process.argv[1];
  const rows = {};
  for (const cell of coverage.cells.filter((item) => item.action.includes(file) && item.applicable !== false)) {
    const key = cell.action.split('#')[1] + ' ' + cell.state + ' ' + cell.applicable;
    rows[key] = (rows[key] ?? 0) + 1;
  }
  console.table(rows);
});" components/layout/app-shell.tsx
```

After a capture, `node scripts/portal-coverage-file-report.mjs <report.json> --file app-shell` prints covered/uncovered/unclassified/not-applicable per file.

## Step 1: make every state classified

A `null` state means the inventory could not prove applicability from source. Check `action.traits` (`unresolvedCallbacks`, `callerBindings`, `authorizationUnresolved`, `authorizationGuards`) and use the rules already implemented before adding new ones.

| Symptom | Existing rule | Where |
|---|---|---|
| `onX` prop forwarded by a shared primitive (`Button`, `Select`, ...) with several callers | `DELEGATING_OWNERS`: the primitive keeps `success`; the other states are not applicable only when every mounted caller resolves, because each caller JSX element is its own inventoried action | `actionStateApplicability` |
| `onX={cond ? handler : undefined}` | A conditional with an absent branch resolves to the other branch; callers omitting the prop are ignored when the control is gated on that prop | `resolveCallbackDeclaration` |
| Control gated on an optional prop no mounted caller supplies | Moved to `excludedActions` as unreachable | end of `buildPortalActionInventory` |
| Permission calls inside `lib/route-access.*` reached through a navigation callback | Route authorization, owned by the `route:*` cells, not action eligibility | `routeAccessPolicy` |
| Boolean prop gate (`showX={cfg && session.principal !== 'staff'}`) | Resolved through the sole caller expression into `{ principals: [...] }` guards | `permissionGuard` |
| `if (flag) actions.push(<Control/>)` | `if` tests are gates (soft: they add guards but never create new unclassified states) | `walk` |
| `canX(session.role)` over a frozen role list | `{ roles: [...] }` guard | `permissionGuard` (`includes`) |
| Child component returns `null` for a principal | Callee early-exit guard is attached at the callsite | `calleeGates` |
| Host mounted in `App.tsx` behind a gate | Host-mount guards apply to controls reachable only through that host | `hostMounts` |
| Control gated on a store a page publishes (`useX` / `usePublishX`) | Routes restricted to components that publish | `storePublishers` |
| Prop invoked inside a primitive helper (`choose(v) { onChange(v) }`), or forwarded through wrappers (`Tabs` -> `TabButton`, `EmptyState` -> `EmptyStateAction`) | Caller bindings follow every supplying caller, recursively through forwarded props | `callerBinding`, `flowValues` |
| Caller omits an optional callback | Counted as `omitted` only when every read of the prop leaves no handler (truthiness test, guarded or optional call, hook deps, intrinsic event attribute, or a child prop that is inert in turn) | `omissionInert` |
| `<X {...obj}/>`, `<X {...props}/>`, `renderX({ ... })` | Spread values resolve through exact objects, the caller's JSX callers, or direct call sites; an escaping function reference blocks | `callerValues`, `spreadValues`, `directCallSites` |
| `props.onX`, `const { a } = props`, `form.onX` where `form` is a prop object | Value flows back to the declaration; the action resolves only when every flow names one declaration (or only setters). A second declaration is a union and stays blocking | `flowValues`, `flowCallback` |
| Hook-returned member (`insights.reload`, `{ ...state, reload }`, `useMemo(() => ({...}))`) or hook tuple (`const [v, setV] = useX()`) | Resolves to the hook's declaration; a spread after the property blocks | `resolveObjectValue(..., members)`, `tuples` |
| Same name declared in two blocks of one function | Resolves to the block holding the reference, otherwise ambiguous (never the last declaration) | `lexicalBindings` |
| `ref.current?.(...)` where the ref only holds `null` or a `new Promise` resolver | Promise settlement; the awaiting caller's action owns what follows | `promiseSettler` |
| Local conditional callback (`const reload = route === 'a' ? a.reload : b.reload`) | Each non-absent branch is invoked, like an inline conditional | `conditionalBranches` |
| `requestSocJson(..., { method: options.method })` | Method read from the exact bound options object; absent means GET | request extraction in `actionTraits` |
| Component rendered only behind identity guards (`if (session.principal === 'staff') return null; ... <InsightsDialog/>`) | Its actions inherit the OR over callers of each caller's element gates, early exits and own inheritance; any unguarded caller path leaves it unrestricted | `inheritedGuard` |

Add a unit test in `tests/unit/portal-action-classification.test.mjs` for any new rule: one fixture proving it resolves, one proving the neighbouring ambiguous case stays blocking. After any inventory change, snapshot all cells before and after (`buildPortalActionCoverage().cells`) and confirm no previously covered cell flipped away from `true`; a flipped covered cell becomes a rejected receipt.

If the source itself is wrong for a role (a real bug), fix it minimally and let the matrix be its regression test. Phase 1 found two: the skip link replaced the page with a not-found route, and a staff session with inspector parameters was signed out by a customer-plane 401.

## Step 2: write the matrix spec

Reuse `tests/helpers/portal-action-matrix.mjs`; do not write per-cell loops.

```js
const matrix = createActionMatrix({ files: ['components/foo/foo.tsx'] });
const drivers = [
  {
    query: { owner: 'Foo', label: 'Save', kind: 'activate' },
    order: ['error-retry', 'success', 'reload'],
    states: {
      success: async (ctx) => [`exact observed outcome`],
      denial: async (ctx) => [`exact observed absence`],
    },
    settle: async (ctx) => ctx.arrive(ctx.route),
  },
];
test(`${identity.label}: foo actions`, async ({ page }, testInfo) => {
  const { failures, requests } = await startMatrixPage(page, identity);
  await runIdentityMatrix(matrix, { page, testInfo, identity, drivers, failures, requests });
});
```

Contract:

- `createActionMatrix` selects the applicable cells for the listed files from source. `runIdentityMatrix` visits each permitted route once with the default `gotoPortalRoute` (or your `arrive`), runs each driver for the states that exist for that identity and route, and records the receipt through `assertPortalActionCell` only after the behavior function returns concrete observation strings.
- A driver is found with `findPortalSourceAction` (`owner`, `label` string or regex, `kind`, `handler`); it must match exactly one action. Match on those, never on the hash id.
- An applicable cell with no driver or no state function fails the test at the end and lists the missing cells, so a new UI control cannot silently escape.
- `ctx` has `page`, `identity`, `route`, `baseUrl`, `failures`, `requests` (`mark`, `since`, `writesSince`), `arrive`, `cell`, plus anything passed through `context`.
- Drivers restore what they change (theme, sidebar, role, viewport, open dialogs). Use `settle` to re-arrive after a driver navigates away.
- Observations are the proof text. State what was asserted (URL, focus, attribute, request method and count), not that a test ran.
- Staff identities share the same drivers: applicable `denial` cells assert absence, zero forbidden requests and an unchanged session.

Local iteration only: `PORTAL_MATRIX_ROUTES=dashboard,targets` limits routes (the completeness assertion is skipped when it is set, so the result can never be mistaken for full coverage), `PORTAL_MATRIX_TRACE=1` prints each cell, `PORTAL_MATRIX_TIMEOUT_MS` shortens the test timeout.

## Behaviors to assert per state

| State | Minimum proof |
|---|---|
| `success` | Exact activation outcome: URL or hash, rendered panel or heading, attribute, storage value, or the request method/path/body. Restore afterwards. |
| `busy` | Hold the response, assert the control is disabled and a second activation sends no second write, then release. |
| `empty` | Serve the `empty` dataset (`restartPortalPlaywrightWithEmptyStore`) and assert the empty-state action. |
| `invalid` | Submit invalid input and assert zero writes and the visible message. |
| `cancel` | Open the boundary, cancel (button, Escape, scrim) and assert zero writes and the retained or cleared draft. |
| `error-retry` | Fail the dependency (persistent fault, not a one-response fault the transport retries), assert the visible failure, retry while failing, heal, retry again, assert recovery and no duplicate side effect. |
| `denial` | Identity lacking the permission: assert the control is absent or disabled and no forbidden request was issued. |
| `reload` | `page.reload` or a direct load of the resulting address preserves the accepted outcome without replay. |

## Mocks that already exist

- Dataset outage: `page.route` on the loader paths returning 503 only while a flag is set; allow those exact responses through `startMatrixPage(page, identity, { allowResponse })` so the strict collector still fails on anything else (see the shell spec).
- Evidence context unavailable or missing: route `/v1/evidence-context` (503 unavailable, bare 404 fallback), with injected URLs allowed in the collector (see the inspector spec).
- Assistant status, jobs and insights: `assistantMocks` in the inspector spec.
- Extra seeded records: `startPortalPlaywrightServer({ liveSource: true, mutate })`.
- No external network. Fonts and favicons are already fulfilled locally by `installPortalBrowserResources`.

## Pitfalls found in phase 1

- `page.goto` to the current URL (or to a different hash on the same path) is not a reload, so the SPA keeps its in-memory data cache. Use `page.reload` when a fresh hydration is the point.
- The harness seeds the session once per tab. After Sign out, dev-headers mode bootstraps a default local session on the sign-in page, so assert that the credential was removed (spy on `removeItem`) and that the previous identity is not restored, not that storage is empty.
- Chromium starts sequential focus navigation at the URL fragment target, so the first Tab after loading `#route` is not necessarily the skip link. Assert off-screen then on-screen on focus.
- `<details>` open state can be driven by data (`open={...}`). Read the state, then toggle toward the wanted state, and re-assert inside `toPass` when a late model render can reset it.
- The source Vite server runs React in development mode, so effects that issue a request can issue two. Assert at-least-one and that every request names the exact id.
- A control that is hidden by the page the user is already on (for example Open run on the same run) needs a different record id in the ref, not a skipped cell.
- Detail routes need the entity ids from `resolvePortalRouteUrl`; list-state routes such as `finding-group-detail` need a real key (build it from the API data with `groupFindings`).

## Verify

```bash
export PATH=/opt/homebrew/opt/node@26/bin:$PATH
node node_modules/@playwright/test/cli.js test tests/e2e/journeys/<spec>.spec.mjs --workers=1 --retries=0
node scripts/validate-existing-behavior-coverage.mjs --capture playwright --out /tmp/cap-foo -- \
  node node_modules/@playwright/test/cli.js test tests/e2e/journeys/<spec>.spec.mjs --workers=1 --retries=0 --reporter=json
node scripts/validate-existing-behavior-coverage.mjs --invocation /tmp/cap-foo.invocation.json \
  [--invocation <other captures>] --report /tmp/portal-report.json
node scripts/portal-coverage-file-report.mjs /tmp/portal-report.json --file foo
```

Capture binds every source and test file digest, so freeze edits before capture and reconcile with all invocations at once. Overall reconciliation exits nonzero until every file is covered; compare per-file counts, `rejected` (must be empty) and `portal.errors`. Run `npm run -s lint`, `npm run -s lint:portal`, `npm run -s web:typecheck` and the unit tests in `tests/unit/portal-action-*.test.mjs`.

Set `PORTAL_INVENTORY_DEBUG=1` while building the inventory to print every caller value that does not bind, with its file, owner and source expression.

## Phase 2 classification result

Inventory-only work (no new receipts), measured with `buildPortalActionCoverage()` before and after:

| Measure | Before | After |
|---|---|---|
| Unclassified action states | 16,022 | 3,140 |
| Required action cells | 33,454 | 33,550 |
| `lib/crud-ui.tsx`, `ui/select.tsx`, `ui/tabs.tsx`, `ui/empty-state.tsx`, `assistant/insights-dialog.tsx` unclassified | 8,412 | 0 |
| `ui/table.tsx` unclassified | 2,832 | 708 |

No covered cell changed. Uncovered `success` cells that no identity could ever reach became `denial` cells: six for soc, auditor and viewer whose resolved callbacks carry `test_policy:write` and `target_group:write` guards, and 410 inherited from render paths (insights dialog and assistant visuals for staff, notification channel dialogs without `notification:write`, the staff-only SOC request view for customers). `DataTable`, `TableLoadError`, `FailureNotice`, `DomainPicker`, `RunPicker` and `TargetCandidatePicker` joined `DELEGATING_OWNERS`: each only forwards event props, so its callers' JSX elements are the inventoried semantic actions.

What still blocks, and why:

| Remaining | Cells | Reason |
|---|---|---|
| `evidence/execution-inspector.tsx`, `targets/probe-activity.tsx` Reconnect/Stop | 1,365 | `readerRef.current?.refresh()` reads a reader cached in a module-level `Map` behind a ref; no exact declaration is provable |
| `ui/table.tsx` `DataTableBodyRow` | 708 | Row `onClick`/`onKeyDown` come from per-table `getRowProps` objects with different effects; needs per-caller action expansion, not delegation |
| Dialog completion callbacks (`ValidationScanLauncher`, `CancelScanDialog`, `RiskAcceptanceDialog`, `ScheduleActions`, `EntryPathCard`, ...) | about 500 | Every caller binds, but to different declarations; unions are refused by design |
| Long tail (`chip.clear`, `inflight.current.delete`, `options.onProgress`, `action.onSelect`, ...) | about 580 | Array-item, ref and per-call option callbacks |

## Order of work for the remaining files

1. Primitives with many callers (`lib/crud-ui.tsx`, `ui/table.tsx`, `ui/select.tsx`, `ui/empty-state.tsx`, `ui/tabs.tsx`): extend delegation to hook-returned and member callbacks first; most of the remaining unclassified cells are `onChange`, `onRetry`, `onCancel`, `insights.reload`, `onAction`, `onConfirm`.
2. Hosts shared by every route (`assistant/insights-dialog.tsx`, `evidence/execution-inspector.tsx`, `targets/probe-activity.tsx`): one scenario per host, matrix over every role and route like the shell.
3. Page files: one spec per page family, using that page's route set only (cells are restricted to routes that reach the component).

## Phase 1 result and remaining estimate

Strict reconciliation over the seven pre-existing receipt specs plus the two matrix specs (source digest `54cac287...`, zero rejected receipts, zero errors):

| Measure | Before | After |
|---|---|---|
| Portal cells covered | 417 | 7,004 |
| Portal cells uncovered (applicable) | 30,879 | 26,810 |
| Unclassified states | 24,578 | 16,022 |
| `components/layout/app-shell.tsx` | 0 covered / 2,160 uncovered / 3,744 unclassified | 3,428 covered / 0 / 0 |
| `components/evidence/evidence-inspector.tsx` | 0 covered / 3,744 uncovered / 864 unclassified | 3,159 covered / 0 / 0 |
| Public/auth | 35 covered / 1,138 uncovered | unchanged |

The uncovered total fell by less than the covered gain because classification turned previously unclassified cells into required cells (and moved others to not applicable). Roughly 33,000 applicable cells remain, in 83 files, plus about 16,000 still unclassified.

Effort per file with the harness: a primitive or host that every role sees costs one spec of 10 to 25 drivers and about 1 to 2 agent-days including inspector work; a page-family file costs a half to one day because its route set is small. Capture time is the practical limit: a role-by-route matrix over about 140 identity-route pairs takes 45 to 60 minutes per spec serially, so split by identity (`-g "customer (owner|admin)"`) and run captures in parallel. Expect about 25 specs for the remaining 83 files, plus 2 to 3 days of inventory work for the callback backlog above (`crud-ui.tsx`, `table.tsx`, `select.tsx`, `insights-dialog.tsx`, `empty-state.tsx`, `tabs.tsx`: about 12,000 of the 16,000 unclassified cells), so roughly 4 to 6 agent-weeks serially, 1 to 2 weeks fanned out across agents.
