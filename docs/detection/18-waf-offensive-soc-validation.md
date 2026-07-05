# WAF Offensive Validation (SOC-Gated)

## Policy

Default WAF posture checks use **safe markers** only. When customers need IONIX-class offensive validation (real SQLi, XSS, RCE, traversal probes), AstraNull provides **SOC-gated offensive suites**.

Customers may **request** offensive validation. AstraNull SOC must approve (two-person), schedule, execute, record results, and close with a post-test report.

Offensive suites are **not** customer self-service. `POST /v1/test-runs` rejects `waf.offensive_*.soc` checks with `403 soc_gated_check`.

## Suite catalog

| Suite ID | OWASP focus | Max requests | SOC check ID |
|---|---|---:|---|
| `sqli_offensive` | Injection | 12 | `waf.offensive_sqli.soc` |
| `xss_offensive` | Injection | 12 | `waf.offensive_xss.soc` |
| `rce_offensive` | Injection | 8 | `waf.offensive_rce.soc` |
| `path_traversal_offensive` | Broken access control | 10 | `waf.offensive_path_traversal.soc` |
| `command_injection_offensive` | Injection | 8 | `waf.offensive_command_injection.soc` |
| `ldap_injection_offensive` | Injection | 6 | `waf.offensive_ldap_injection.soc` |
| `ssti_offensive` | Injection | 6 | `waf.offensive_ssti.soc` |
| `combined_offensive` | Multi-vector bundle | 24 | `waf.offensive_combined.soc` |

Catalog source: `src/contracts/wafOffensive.mjs` (`GET /v1/waf/offensive-suites`).

## Workflow

| Stage | Owner | API |
|---|---|---|
| Request | Customer engineer/admin | `POST /v1/waf/offensive-requests` |
| Authorization pack | Customer + SOC review | `POST /v1/waf/offensive-requests/:id/artifacts` + `POST /internal/soc/waf-offensive/:id/artifacts/:artifactId/review` |
| Approve (2-person) | SOC | `POST /internal/soc/waf-offensive/:id/approve` |
| Schedule | SOC | `POST /internal/soc/waf-offensive/:id/schedule` |
| Execute | SOC | `POST /internal/soc/waf-offensive/:id/start` → creates linked `waf_validation_run` |
| Record results | SOC | `POST /internal/soc/waf-offensive/:id/results` |
| Stop | SOC | `POST /internal/soc/waf-offensive/:id/stop` |
| Report + close | SOC | `POST /internal/soc/waf-offensive/:id/post-test-report` then `POST .../close` |

Required artifact types:

- `customer_authorization_letter`
- `target_ownership_confirmation`
- `emergency_contacts`
- `stop_criteria`
- `waf_offensive_test_plan`
- `staging_isolation_confirmation`

## Safety controls

| Control | Behavior |
|---|---|
| Two-person SOC approval | Same pattern as high-scale requests |
| Authorization pack | Approve blocked until all artifact types accepted |
| Schedule window | Start rejected outside `scheduled_window` |
| Scope hash lock | Target group scope hash must match at start |
| Kill switch | Active kill switch blocks offensive start |
| Staging default | `staging_only` defaults to `true` on intake |
| Evidence minimization | Store pass/fail + hashed summaries only — no raw payloads, bodies, or reusable exploit recipes in API/storage |
| Request caps | Per-suite `max_requests`; combined cap enforced at validation profile normalization |

## Relationship to safe markers

| Mode | When to use | Risk class |
|---|---|---|
| Safe markers (`sqli_marker`, `xss_marker`, …) | Continuous posture, drift, customer self-service | `safe` |
| Offensive suites (`sqli_offensive`, …) | Staging proof, SOC-approved realism, customer escalation | `soc_gated` |

Both modes correlate probe behavior with agent observation. Offensive suites produce `test_material_type: soc_gated_offensive_suite` results.

## Prohibited

- Customer-direct offensive execution via `/v1/test-runs`
- Raw exploit code, POC scripts, or traffic generators in request bodies
- Production offensive runs without `staging_isolation_confirmation` artifact
- Unbounded probe volume outside suite `max_requests`