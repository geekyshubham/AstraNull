# Provider-neutral protection validation review

Dates: 2026-10-07 to 2026-10-08. Scope: the complete uncommitted PV implementation, supporting fixes, migrations, target UI, generated artifacts, tests, and documentation. This is a local review and commit-preparation record; live acceptance and production release are separate.

## Findings fixed

| Finding | Correction | Regression evidence |
|---|---|---|
| Invalid or conflicting source registry entries could produce an arbitrary worker perspective. | Only an absent registry uses the default pool; invalid, empty, or conflicting configured assignments admit no matching worker. | `protection-validation-integration.test.mjs` |
| Null policy order, rule count, or TTL became zero, and snapshot persistence omitted ordering. | Missing numbers remain unknown; both store allowlists preserve valid ordering. | `protection-config-enrichment.test.mjs`, `waf-posture-api.test.mjs` |
| Static marker echo could confirm application bypass. | Confirmation requires nonce-bound identity and a healthy baseline. Static echoes remain suspected. | `pv01-external-observation-semantics.test.mjs` |
| Generic AWS authorization XML could grade as WAF denial. | Removed the generic AccessDenied signature; retain control-specific block markers. | `pv01-external-observation-semantics.test.mjs` |
| Skipped unknown paths prevented saving a finished evaluation. | Permit only skipped, evidence-free unknown path items; other unknown paths fail closed. | `protection-validation-service.test.mjs` |
| Multiple hostname/URL/IPv6 target records inflated unique-host totals. | Normalize hosts independently of target, entry-path, and provider-association counts. | `protection-validation-report.test.mjs` |
| Newer expectations reinterpreted older layer results. | Resolve the expectation pinned by the evaluation. | `protection-validation-report.test.mjs` |
| Capped database reads could appear to describe the complete estate. | Matrix, JSON report, and CSV expose incomplete source input; portal marks the partial matrix. | Report unit tests and browser regression suite |
| Firewall migration findings attached to the pre-change target. | Findings and retest authorization use the explicit post-change target. | `protection-validation-findings.test.mjs` |
| Origin finding retests could lose their binding. | Reject unbound/different-binding retests before dispatch and lineage registration. | Finding/lineage regressions and full run-start suites |
| Concurrent first findings could lose the stronger observation. | Lock tenant/dedupe keys transactionally before reading/upserting, including absent rows. | Real PostgreSQL concurrent weak/strong finding test |
| Late pagination responses contaminated a new target/search list. | Abort and discard old pages with the parent list request; prevent duplicate page loads. | Browser delayed-response/search regression |
| TCP refusal after an open baseline counted as firewall enforcement. | Firewall classifier v3 leaves denial unverified; required-service unavailability needs repeated failure observations. | `firewall-change-acceptance.test.mjs` |
| Control-plane readiness checks could count toward external report eligibility. | Exclude `ops_readiness` and declaration-only checks from external readiness. | Report eligibility regressions |
| A passing WAF scenario could validate an application with unmeasured required layers. | The application stays incomplete until every required layer has measured enforcement. | Report layer-completeness regression |
| Findings with multiple checks could pair a newest run with an unrelated check. | Select the check from the same reference as the newest run/verdict. | Finding evidence-pair regression |
| Demo defaults overrode an explicit per-tenant feature disable. | Explicit tenant flags take precedence over demo defaults; global disable still wins. | Feature-gate integration regression |
| Hosted API and runner did not share PV configuration. | Forward identical feature flags and approved-source registry; defaults remain unchanged. | Runner/Compose wiring regression |

## Verification

Final frozen-code verification passed with no unresolved findings from the review passes. Verification logs are retained locally under `/tmp/astranull-pv-review-20261007/`.

| Gate | Result | Log |
|---|---|---|
| `make verify` | Exit 0: 4,745 unit cases, 459 integration cases, 21 end-to-end cases, 11 dedicated edge-corpus cases; lint, safety, schema, tenant-query audit, taxonomy, generated check library, and corpus parity passed. One opt-in live-DNS integration case skipped. | `make-verify-frozen.log` |
| API contracts | 16/16 passed. | `contracts-frozen.log` |
| Node provenance | 7/7 passed. | `provenance-frozen.log` |
| Complete Chromium/browser/accessibility suite | 394/394 passed, zero skips; portal scale gate enabled. | `browser-complete.log` |
| Frontend typecheck/build | Passed; generated assets rebuilt through the normal pipeline. | `typecheck-frozen.log`, `build-frozen.log` |
| Portal lint | Zero hardcoded portal values. | `portal-lint-last.log` |
| Vector catalog | In sync, 721 rows. | `vector-final.log` |
| Syntax and whitespace | 110 changed/new ESM modules checked; Git whitespace checks passed. | Local review commands |

All 16 captured entry-path/firewall screenshots were inspected at 375, 768, 1024, and 1440 pixels in dark/light. Artifacts are under `browser-artifacts/` in the same local log directory. Sticky shell chrome overlapping long element captures is screenshot capture behavior; the browser suite verifies viewport overflow, scrolling, focus, and accessible states separately.

The complete browser log also includes messages from a concurrently running Vite development session about an invalid hook call; no browser test failed, and the verified product build uses the generated static assets. This review did not alter or stop that unrelated development session.

An initial full run encountered one readiness test returning 403 instead of its expected 503. The unchanged test passed independently and the subsequent full `make verify` passed. Do not claim a fix for that transient failure; retain it in the verification history.

No customer-target probes, deployment, remote notification, or historical-verdict rewrite is part of this review. Local PostgreSQL tests use ephemeral databases and the non-superuser tenant role. Browser fixtures validate UI behavior and do not certify provider effectiveness.

## Remaining release limits

PV tasks remain in progress under the [rollout gates](../backend/protection-validation-rollout.md#open-release-gates). Owned live endpoints, a nonce-bound canary, real pre/post-change evidence, additional provider classes, and hosted PostgreSQL/signed-worker acceptance are required before release certification. Optional declared-signature producers and configuration UI enrichment remain explicitly unsupported; absence of these inputs stays inconclusive.
