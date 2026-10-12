# Backend and Platform Test Strategy

## Local Node test execution

`npm test`, `npm run test:unit`, and the corresponding Make targets run one Node test file at a time. The suite includes wall-clock performance budgets; launching a worker for every reported CPU can make unrelated test files compete with those measurements. File-level serialization preserves the existing performance thresholds and all assertions. Tests for races still create their explicit parallel requests and Postgres transactions inside each test.

The browser suite remains a separate command: `ASTRANULL_PORTAL_SCALE=1 npm run test:portal-playwright`. Run it separately from Node performance measurements when collecting final verification evidence.

## Current outside-in acceptance (2026-10-12)

ADR-0008 and ADR-0019 supersede the legacy agent/install/group scenarios below. Current customer testing declares targets directly, obtains existing scoped authorization, consumes signed external-worker evidence and verifies external-only verdicts, findings and readiness. No customer agent, environment or group selector is required. Previously stopped execution/producers/mechanisms remain unavailable; no fixture or receipt enables them.

- **First navigation:** attach `portal-browser-failures.mjs` before navigation, inject the session and assert the actual mounted shell/heading with the boot overlay removed. Console errors, invalid-hook warnings, page errors, unhandled rejections and failed own-origin modules fail even if a later page mounts. Intentional API fault tests may pair one native zero-source-position/no-JavaScript-argument resource-console error with one explicitly allowed exact URL/status fetch/XHR response; unmatched/repeated diagnostics and module responses still fail, and raw diagnostics remain retained. No recovery reload or retries. `portal-source-startup.spec.mjs` exercises three attempts per cold/shared-overlap/isolated-overlap/define-only/explicit-dependency arm using owned caches; no developer cache deletion. Late dependency discovery must not deliver a second React instance.
- **Catalog:** enumerate definitions and delivery-affecting fingerprints dynamically. Owned protocol fixtures drive actual catalog-signed jobs through reservation, destination delivery, accepted result custody, publication and readiness. Declaration-only, unsupported, additional-scope and SOC-gated cases assert their exact non-execution disposition rather than fabricating wire evidence. Each definition's invocation is distinct; aliases and catalog mappings do not multiply independent mechanisms. Observation-only transport, inert markers and Alt-Svc observations never prove exploitability or capacity.
- **UI:** source-reachable and rendered interactive inventory is distinct from behavioral proof. Cover actual semantic actions/entrypoints and their applicable role/state combinations, including invalid/cancel/busy/failure/retry/reload paths. Shared shell controls are not multiplied by every route/dataset. Callbacks invoked through wrapper parameters (for example `runAction(label, () => requestJson(...))`) contribute their exact requests; unresolved callbacks on any non-anchor action stay blocking (`applicable: null`) even when the action also navigates. Customer and staff roles are separate; route/dataset/presentation assertions do not replace actual endpoint role/scope/tenant authorization tests. Denied writes preserve business state while permitting mandatory denial audits.
- **Cancellation and fault branches:** a cancel branch passes only when the owned peer observes the client's socket close (not merely a settled outcome) well before the signed deadline. Upgraded HTTP sockets are half-open and unmanaged by `http.Server`, so fixtures must read them to observe the client FIN. Reflector timeout/cancel peers still record the exact received payload under its `payload_profile`. DNS fixtures set TC only on UDP replies; a TCP fallback reply is never truncated. Timeout duration is checked against the signed cap plus the authoritative `hardTimeoutSchedulerToleranceMs`, never a shrunken cap or rewritten elapsed time.
- **Public/auth:** `portal-public-auth-action-states.spec.mjs` uses the strict collector with zero retries. Challenge fields (workspace ID, 6-digit authenticator code) are validated locally with no POST; staff sign-in with an unknown auth mode renders a fail-closed notice with no submittable form; a pending staff sign-in cannot be resubmitted by keyboard and retries only on explicit activation. No password/code reaches storage or the URL. Public/auth cells use the separate visitor inventory, never the authenticated role cross-product.
- **Receipts:** `tests/helpers/existing-behavior-coverage.mjs` and `scripts/validate-existing-behavior-coverage.mjs` bind local assertion receipts to source/config/test digests, invocation, concrete completed assertions and terminal zero-retry passing Node TAP or Playwright JSON results. Missing, failed, skipped, retried, stale or unmapped promised evidence is not coverage. A nonpassing/skipped/retried terminal browser case invalidates its entire captured invocation even when that case emitted no receipt; an invalid extra receipt cannot be ignored to manufacture full acceptance. Focused reconciliation is explicitly partial; the full gate fails on missing applicable obligations. These developer-validation receipts are not production sign-offs.
- **Safety and isolation:** use owned loopback fixtures and ephemeral application-role PostgreSQL/RLS, current migrations through 0078, public-DNS opt-in disabled and no provider/signer calls. Never apply held 0079. One accepted probe event can publish a verdict without charging a nonexistent second event; actual ingestion event caps, signed budgets, deadlines, tenant isolation, scan-wide abort and Stop acknowledgments remain enforced.

Final acceptance requires serial current-source npm/Make/contracts, frontend type/lint/build, scale-enabled browser, separate accessibility and isolated full-scale performance gates, unchanged thresholds and complete executed-coverage reconciliation. Passing a subset or prior source revision does not certify the current tree. Real deployment, authorized live targets and operational/human acceptance remain separate.

## Test categories

| Category | What to test |
|---|---|
| Unit tests | Token validation, RBAC, planning, correlation, scoring. |
| Integration tests | Agent registration, probe event ingestion, verdict creation. |
| E2E tests | Onboarding -> install simulated agent -> run check -> view finding. |
| Security tests | Tenant isolation, token leakage, replay, permission bypass, API rate-limit 429 behavior. |
| Load tests | Event ingestion, heartbeats, dashboards, reports. |
| Chaos tests | Agent disconnects, queue delay, probe timeout, partial evidence. |
| SOC workflow tests | Approval gates, kill switch, rejected authorization, stop states. |

## Minimum CI scenarios

1. Create tenant/user.
2. Create target group.
3. Generate bootstrap token.
4. Register simulated agent.
5. Send heartbeat.
6. Start safe run.
7. Emit probe event.
8. Emit agent observed event.
9. Correlate as bypassable.
10. Create finding.
11. Generate report.
12. Verify audit logs.
13. Exceed service-layer API rate limit and assert `429` + `Retry-After`; confirm `/health` remains reachable.

## Service-layer rate limits

Unit tests cover fixed-window reset, per-client key separation, and production fail-closed when `ASTRANULL_RATE_LIMIT_DISABLED=1`. Integration tests use a low `ASTRANULL_RATE_LIMIT_MAX_REQUESTS` on a dedicated server instance so the default operability server is unaffected. Gateway/WAF limits are documented as required production defense-in-depth but are not simulated in CI.

## Agent install matrix

| Platform | Test requirement |
|---|---|
| Ubuntu LTS | deb package + one-line installer. |
| Debian | deb package. |
| RHEL/Rocky/Alma | rpm package. |
| Amazon Linux | rpm package. |
| SUSE | rpm or tarball fallback. |
| Generic Linux | static tarball. |
| Docker | container mode. |
| Kubernetes | Helm DaemonSet and canary Deployment. |

## Completion criteria

Testing is complete when CI proves the entire validation loop and blocks unsafe regressions.
