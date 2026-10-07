# Application Entry-Path and Firewall Change Validation

Status: contract defined (PV-02). The persistence, execution, UI and reporting slices (PV-03 to PV-07) are built on top of it. Decision record: [ADR-0017](../adr/0017-application-entry-path-validation.md). Plan: [provider-neutral protection validation](../implementation/provider-neutral-protection-validation-plan.md).

The canonical code contract is `src/contracts/protectionValidation.mjs` (`PROTECTION_VALIDATION_CONTRACT_VERSION = 'protection-validation-v1'`). Unit tests: `tests/unit/protection-validation-contract.test.mjs`. This document explains the rules. If the document and the module disagree, the module is authoritative, and this document must be corrected.

## Principles

| Principle | Rule |
|---|---|
| Provider-neutral | Commercial CDN/WAF, cloud-native, appliance, reverse-proxy and unknown/custom providers all use one workflow. A provider name is only an evidence label. It is never required, and it is never proof that a control is enforced. |
| Connectors optional | A custom or unidentified provider can complete the full workflow with every connector disabled: declare paths, run reviewed checks, capture a baseline, compare, and inspect gaps. Configuration evidence can explain an observation. It cannot replace an observation, upgrade one, or authorize traffic. |
| Explicit declarations | Entry paths, owners, purposes, expected behavior and required layers are declared by the customer. They are never inferred from tags, logos, CNAMEs, response headers or vendor names. |
| Outside-in only | Every conclusion comes from finalized, signed, external probe evidence (`external_only`), scoped to the tested path, source, scenario and time ([ADR-0008](../adr/0008-outside-in-only-targets-first.md)). |
| Independent layers | `waf`, `cdn_edge`, `network_firewall` and `ddos` are evaluated separately. A WAF block does not prove DDoS capacity or firewall traversal. |
| No stacked attribution | When several layers or edges are stacked, a block or bypass is reported against the path. It is not attributed to an inner layer unless evidence establishes that layer (`attribution: unattributed`). |
| Unknown is a result | Every status has an evidence requirement and an unknown/inconclusive alternative. Timeouts, refusals, TLS failures, generic error pages and UDP silence never establish protection. |

## Entry-path relation

An existing declared target **anchors** the application. Each entry path references another **existing, same-tenant, non-deleted** target.

| Field | Rule |
|---|---|
| `anchor_target_id` | Taken from the route `:targetId`. A body value must match it. |
| `entry_target_id` | An existing same-tenant target. It may equal the anchor only for `primary_route`. |
| `relation_kind` | One of `primary_route`, `alternate_hostname`, `declared_api_url`, `declared_login_url`, `origin`, `fallback_backend_route`. |
| `owner` | 1–120 characters, trimmed, no control characters. |
| `purpose` | 1–500 characters, trimmed, no control characters. |
| `expected_behavior` | `must_be_protected_by_layers` (requires at least one layer), `intentionally_public` (requires zero layers), or `must_not_be_reachable` (layers optional). |
| `required_layers` | A subset of `waf`, `cdn_edge`, `network_firewall`, `ddos`, deduplicated and stored in canonical order. |
| `origin_binding_id` | Required for `origin` and forbidden for every other kind. The binding must be active, in the same tenant, and must join exactly anchor → entry. Origin relations reuse the origin binding's authority and its Host/SNI/port/path scope ([origin execution](../backend/current-release-origin-execution.md)). |
| `status` | `active` or `archived`. Archived relations cannot authorize new checks. |
| `declaration_version`, `declaration_digest` | Set by the server. The digest is a SHA-256 over stable-stringified declaration fields and the version. |

Server-owned fields in a request body (`id`, `tenant_id`, `status`, `declaration_version`, `declaration_digest`, `created_*`, `archived_*`, `contract_version`) return `400 server_owned_field`. The following keys are rejected at any depth with `400 scope_not_declared`: `direct_ip`, `discovered_endpoint(s)`, `endpoint`, `destination`, `host_override`, `sni_override`, `source_ip`, `spoofed_source`, `inferred_from`, `credentials`, `password`, `api_key`, `token`, `secret` and `raw_config`.

Idempotency: the scope key is tenant + anchor + entry + kind + binding. Repeating a write with the same digest replays the record. A different digest on the same active scope returns `409 entry_path_conflict`. The service re-checks target lifecycle and current ownership at execution time (`entryPathAuthorizesExecution`) even when the relation was authorized earlier.

## Behavior expectations (versioned)

**Path validation.** Fields: `anchor_target_id`, `scenario` (a catalog scenario id) and `layer_outcomes`, which maps each layer to `enforce`, `allow`, `not_reachable` or `no_expectation`. The server also sets `expectation_version` and `digest`. `checkExpectationAgainstRelation` flags an expectation that leaves a required layer at `allow` or `no_expectation`, and one that allows traffic on a `must_not_be_reachable` path.

**Firewall change.** Fields:

| Field | Meaning |
|---|---|
| `destination_target_id` | The declared destination target. |
| `protocol` | `tcp` or `udp` with an integer `port`, or `service` with a `service_endpoint` of `{ service, port, path? }`. The path has no query. |
| `expected` | `allow` or `deny`. |
| `source_perspective` | An approved source identifier. |
| `change_id` | The customer's change identifier. |
| `owner` | Optional. |
| `pre_post_mapping` | Optional. Only an explicit customer declaration (`declared_by_customer: true`) can map a pre-change destination to a different post-change destination. An inferred IP change is never comparable. |

## Baselines and evidence references

A baseline is an **immutable** evidence set:

- `kind`
- `tenant_id`
- `anchor_target_id` and `entry_path_id` (path validation only)
- `expectation_id`, `expectation_version`, `expectation_digest`
- `declaration_digest` (required for path validation)
- the exact `target_id`
- `destination_mapping` (firewall only)
- `references[]`
- `captured_at`
- `freshness_window_seconds`: 1 hour to 180 days, default 30 days
- `baseline_digest`

Every reference must be finalized (`run_status` of `verdicted` or `completed`) and must carry `source_perspective` and `worker_id`. A firewall capture groups one baseline per expectation under a `change_id` (`normalizeFirewallBaselineCapture`).

Evidence links are **reference-only**. A link holds only `test_run_id`, `check_id`, `check_version`, `scenario_version`, `verdict_id`, `evidence_ids[]` (up to 32), `target_id`, `observed_at`, `run_status`, `finalized`, `source_perspective` and `worker_id`. Headers, bodies, cookies, raw configuration and credentials are dropped.

## Comparison compatibility

`assessComparisonCompatibility(baseline, candidate, options)` returns `{ comparable, stale, reasons[] }`. The ordered reasons are:

`invalid_baseline`, `invalid_candidate`, `contract_version_mismatch`, `kind_mismatch`, `tenant_mismatch`, `expectation_mismatch`, `expectation_version_mismatch`, `expectation_digest_mismatch`, `anchor_mismatch`, `entry_path_mismatch`, `declaration_digest_mismatch`, `declaration_changed`, `destination_mismatch`, `destination_mapping_missing`, `evidence_missing`, `evidence_not_finalized`, `source_missing`, `source_mismatch`, `check_mismatch`, `check_version_mismatch`, `scenario_version_mismatch`, `candidate_not_after_baseline`, `baseline_stale`, `candidate_stale`.

- A baseline whose stored digest no longer matches its content is `invalid_baseline`.
- **Firewall:** the expectation id, version and digest must match. Same destination, or exactly the declared mapping. The candidate must be captured after the baseline and inside the baseline freshness window. Every `(check_id, source_perspective)` group must exist on both sides with one equal `check_version` and one equal `scenario_version`.
- **Path validation:** a healthy primary route is compared with independently authorized alternate routes under the same anchor and expectation. Captures must fall within one freshness window. Pass `options.currentDeclarationDigests` to detect a declaration that changed after capture (`declaration_changed`). Pass `options.matchBy = 'scenario_version'` when routes use different checks for the same scenario, for example an origin Host/SNI check.
- `options.now` adds `candidate_stale` for old candidate evidence.
- `compatibilityFailureStatus` maps a failure to `stale` when only staleness reasons are present, and to `not_comparable` otherwise.

## Path validation outcomes

`classifyPathValidationItem` is the reference classifier. It uses the PV-01 observation vocabulary: `response_observed`, `application_identity_confirmed`, `explicit_denial_observed`, `no_response`, `transport_error`, `not_tested`.

| Outcome | Evidence requirement | Unknown alternative |
|---|---|---|
| `intentional_public_access` | `intentionally_public` declaration plus an observed response. | `not_tested` |
| `reachability_exposure` | A response on a `must_not_be_reachable` path, or on an `origin`/`fallback_backend_route` whose enforcement was not measured. | `inconclusive` |
| `weaker_observed_enforcement` | A healthy, enforcing primary and partial enforcement of the same scenario on this path. | `inconclusive` |
| `suspected_alternate_application_route` | A healthy, enforcing primary and a non-enforced response without nonce-bound identity. | `inconclusive` |
| `scoped_application_bypass` | A healthy, enforcing primary, a nonce-bound canary identity, and the same scenario not enforced on this path. | `suspected_alternate_application_route` |
| `consistent_enforcement` | Same-scenario enforcement on this path behind an enforcing primary, or explicit denial on a `must_not_be_reachable` path. | `inconclusive` |
| `inconclusive` | Missing, incompatible, timed-out or transport-failed evidence, or no healthy blocked primary baseline. | — |
| `not_tested` | No finalized observation exists. | — |
| `skipped` | In the reviewed plan, but ineligible, unauthorized, cancelled or killed. | — |

Observations come only from recorded response evidence. For non-marker probes (for example `http_head`, `slow_header_probe`, `port_scan_bounded`), an HTTP status of 100 or more is `response_observed`, and 401, 403 or 421 is `explicit_denial_observed`. A refusal, NXDOMAIN, unreachable host, or server-closed connection is `transport_error`, a timeout is `no_response`, and a result with no status and no error is `inconclusive` (`response_evidence_not_recorded`). A direct-origin denial counts as `consistent_enforcement` only when its permitted-path baseline was healthy (origin lockdown confirmed); otherwise the item is `inconclusive` with `origin_lockdown_not_confirmed`. Observation labels say "Origin response observed" only for `host_sni_bypass` attempts; other paths say "Response observed".

Primary-route success never validates an untested alternate route. Partial plans keep `skipped` and `not_tested` items. A customer marker validates enforcement of that marker only (`marker_scope_only`). It does not validate a whole attack family.

## Firewall change statuses

Each side aggregates samples (`aggregateFirewallSamples`) of `service_response_observed`, `reachable_transport_only`, `explicit_denial_observed`, `no_response`, `transport_error`, `udp_silence` or `not_tested` into one side state: `satisfied`, `violated`, `not_observed`, `unverified` or `not_tested`.

| Expected | Satisfied | Violated / not observed | Unverified |
|---|---|---|---|
| `allow` | A valid service response | Explicit denial (`violated`). At least 2 samples of no response, transport error or UDP silence (`not_observed`). | Transport-only connect, a single silent sample, or mixed samples |
| `deny` | Control-specific explicit denial | Any sample with a service response or transport connect (`violated`) | Timeout, transport error, UDP silence |

| Status | Evidence requirement |
|---|---|
| `matched` | Compatible, fresh pre and post evidence with the same side state. Check `expectation_met`: an unchanged failure is `matched` with `expectation_met: false`. |
| `regression` | Pre `satisfied`, post `violated` or `not_observed`. Gap `forbidden_service_newly_reachable` (deny) or `required_service_newly_unavailable` (allow). |
| `improvement` | Pre `violated` or `not_observed`, post `satisfied`. |
| `inconclusive` | Either side unverified or mixed, the baseline side was not tested, or states differ without an observed gap. |
| `not_tested` | No post-change evidence. |
| `stale` | Outside the freshness window. |
| `not_comparable` | Any other compatibility failure. |

A gap is an observed acceptance gap only. No rule id or root cause is invented. A port connection supports a statement about reachability, not about enforcement or inspection. UDP silence remains ambiguous (`udp_silence_ambiguous`). E2 transport observations stay outside readiness coverage ([ADR-0014](../adr/0014-inconclusive-readiness-coverage.md)).

## Layer evidence states

Each path row in the matrix contains one entry per layer. Every dimension is kept separate.

| Dimension | States | Evidence requirement | Unknown alternative |
|---|---|---|---|
| `declared_intent` | `required`, `not_required`, `undeclared` | The explicit entry-path declaration. | `undeclared` |
| `vendor_detection` | `detected`, `not_detected`, `unknown` | An external fingerprint signal. A label alone is not proof of enforcement. | `unknown` |
| `observed_enforcement` | `enforced`, `partially_enforced`, `not_enforced`, `inconclusive`, `not_tested` | A finalized signed run on this exact path, after a healthy permitted baseline. Evidence refs are required. | `inconclusive` |
| `application_identity` | `confirmed`, `suspected`, `not_established`, `not_tested` | A nonce-bound canary for `confirmed`. Generic similarity is at most `suspected`. | `not_tested` |
| `suspected_bypass` | `suspected`, `not_suspected`, `unknown` | A non-enforced response while the primary enforces. | `unknown` |
| `confirmed_scoped_bypass` | `confirmed`, `not_confirmed`, `unknown` | Confirmed identity plus an enforcing primary and a non-enforcing alternate. | `unknown` |
| `evidence_limitations` | A subset of the limitation strings | Always present. `ddos` always includes `not_capacity_assurance`. | `external_only` |

`attribution` is `attributed`, `unattributed` or `not_applicable`. `attributed` requires evidence refs.

## Limitations

Limitation strings: `external_only`, `sampled_public_ingress_only`, `rule_table_equivalence_not_established`, `routing_nat_egress_east_west_not_established`, `not_capacity_assurance`, `appliance_traversal_not_established`, `firewall_traversal_not_established`, `stacked_layer_attribution_not_established`, `transport_reachability_not_enforcement`, `udp_silence_ambiguous`, `marker_scope_only`, `vendor_label_not_proof`, `configuration_evidence_not_behavior`, `untested_paths_not_covered`, `layer_not_measured_by_scenario`.

Required on every item:

- **Path validation:** `external_only`, `not_capacity_assurance`, `firewall_traversal_not_established`, `stacked_layer_attribution_not_established`, `marker_scope_only`, `untested_paths_not_covered`.
- **Firewall change:** `external_only`, `sampled_public_ingress_only`, `rule_table_equivalence_not_established`, `routing_nat_egress_east_west_not_established`, `not_capacity_assurance`, `appliance_traversal_not_established`, `transport_reachability_not_enforcement`.

## Evaluations

`normalizeComparisonEvaluation` enforces these rules:

- Statuses come from the kind's enum.
- Gap kinds appear only on regressions.
- `matched`, `regression` and `improvement` (and every conclusive path outcome) carry evidence refs.
- Items with compatibility reasons can only be `stale`, `not_comparable` or `not_tested` (firewall), or `inconclusive`, `not_tested` or `skipped` (path). Anything else returns `409 baseline_not_comparable`.
- Required limitations are present on every item.
- `summary.accepted` is `true` only when there is at least one item and every item is `matched` or `improvement` with `expectation_met: true` (firewall), or `consistent_enforcement` or `intentional_public_access` (path). Zero evaluated expectations never means success.
- The evaluation is digested over an explicit field list.

## Findings and missing evidence

Product decision, 2026-10-06 ([ADR-0017](../adr/0017-application-entry-path-validation.md), runtime decision 7): results with missing evidence are ignored for findings.

A result has missing evidence when either of these is true:

- Its path outcome is `inconclusive`, `not_tested` or `skipped`, or its firewall status is `inconclusive`, `not_tested`, `stale` or `not_comparable`. This includes items that are not comparable because evidence is absent, unfinished, stale or not in the baseline.
- It has no finalized evidence reference (every referenced run is unfinished, or there are no references).

| Rule | Behavior |
|---|---|
| No finding | `deriveProtectionFindingCandidates` puts the item in `skipped` with reason `unavailable_evidence_ignored`. It creates no finding, at any priority. The `unavailable_evidence` finding class and the `includeUnavailableEvidence` option are retired. |
| No lifecycle effect | A later result with missing evidence never creates, updates, escalates, closes or reopens an existing finding. `planProtectionFindingUpsert` returns `action: "none"` for such a candidate. |
| Never success | A passing outcome without finalized evidence does not count as a passing observation. Unknown results never count toward `validated`, `accepted` or `summary.accepted`. |
| Still visible | The matrix and report keep these results as unknown, inconclusive, stale or not tested, inside the same denominators. Each report conclusion carries `ignored_for_findings`. `unknowns` adds `ignored_for_findings`, `creates_findings: false`, `counts_as_validated: false` and a statement. The CSV adds an `ignored_for_findings` column. |
| Legacy rows | Rows already stored with `finding_class: "unavailable_evidence"` stay readable. The database constraint still allows the value. When conclusive evidence arrives, the finding escalates to the observed class through the normal upsert. |

## Safety

- Creating a relation, expectation, baseline or evaluation never dispatches traffic.
- Only `POST /v1/entry-path-comparisons` with `mode: "start"` and a matching `reviewed_plan_digest` can start runs. It uses the existing signed jobs, destination vetting and pinning, budgets, deadlines, cooldowns, safe windows, cancellation and kill switches.
- Relation metadata, redirects, response headers and discovered endpoints never select a socket destination.
- There is no public observation-write endpoint.
- High-scale execution remains SOC-gated and out of scope.

## Runtime integration

How the slices are composed at runtime (API details: `docs/api.md`, "Protection validation tenant gate and runtime wiring"):

| Concern | Where | Behavior |
|---|---|---|
| Tenant gate | `src/config.mjs` `isProtectionValidationEnabledForTenant`, `src/services/tenantDeploymentFeatures.mjs` | Off by default. `ASTRANULL_PROTECTION_VALIDATION_ENABLED` sets the default, `ASTRANULL_PROTECTION_VALIDATION_ENABLED_TENANTS` overrides per tenant, and an explicit `0` turns every tenant off. Routes return `404 protection_validation_disabled`. |
| Service composition | `src/services/protectionValidationFacade.mjs`, `src/services/protectionValidationRuntime.mjs` | One service per persistence mode: PV-03 storage, PV-04 comparisons (both stores; the same lifecycle code runs over the dev-store and Postgres backends), PV-05 firewall acceptance stored through PV-03 rows, PV-06 matrix/report/findings, PV-08 explanation-only configuration. |
| Firewall evidence | `src/services/protectionValidationFirewall.mjs`, `src/persistence/postgres/firewallEvidenceReader.mjs` | Baselines keep PV-05 observation records (positional encoding in Postgres provenance) so later evaluations can verify `observations_digest`. |
| Source perspective | `src/lib/probeSourcePerspective.mjs` | Resolved on the server from the signed worker id through `ASTRANULL_APPROVED_PROBE_SOURCES`; without a registry every signed worker is the shared pool `astranull-signed-public-worker`. Worker-submitted labels are ignored. |
| Comparison finalization | `registerEntryPathComparisonFinalizedHook` in `src/services/entryPathComparisons.mjs` | When the last item finalizes (run terminal hook) or the comparison is stopped, the frozen evaluation is recorded as a `pvc_` evaluation with its `pvx_` expectation, and findings are derived. Deferred items resume on a 30-second dev-server tick (which also finalizes expired `collecting` runs of running comparisons) or, in Postgres, on the validation-scan runner tick. |
| Postgres comparison lifecycle | `src/persistence/postgres/entryPathComparisonRepository.mjs`, `entryPathComparisonServiceAdapters.mjs`, `scripts/validation-scan-runner.mjs` | Migration `0071`. Per-comparison advisory lock on a 4-connection pool (2 s connect timeout; no connection reads as busy), `lock_version` compare-and-set, a path marked `running` before its run is requested (`start_interrupted` after a crash), `reconcile_seq` when a hook cannot lock. The runner advances due comparisons per tenant, isolates failures per comparison, retries evaluation links, and pauses (never cancels) on the gate. Deferrals stop after 24 h (`deferral_limit_reached`). |
| Findings | `src/services/findings.mjs` `upsertProtectionFindingsFromEvaluation`, `src/persistence/postgres/protectionFindingsRepository.mjs` | Derived only from a newly recorded, digest-verified evaluation; never from reads or replays. Upserts never close findings or siblings. Results with missing evidence create no findings (see "Findings and missing evidence"). |
| Retests | `src/services/protectionValidationRetest.mjs` | Current execution authorization is rechecked before any protection-finding retest run is created, in both stores. |
| Configuration context | `attachConfigurationContext` in `src/services/protectionProfile.mjs` | Target detail adds `protection_profile.configuration` only when WAF posture and tenant connectors are enabled and the caller has `waf:connector_read` (role and API-key scope); otherwise it is `{ configuration_access: "redacted" }` or omitted. It never feeds families, effectiveness, readiness, or coverage. |

### Rollout and rollback

The operator procedure (tenant gate, migration order `0068` → `0069` → `0070` → `0071`, flag disablement, queued-work cancellation, retest requirements, monitoring) is in [protection validation rollout](../backend/protection-validation-rollout.md). In short:

1. Apply the four additive migrations before the build; the PV-01 evidence correction is ungated. In Postgres mode make sure the validation-scan runner (or `test-policy-runner`) runs for enabled tenants with the same PV flag env.
2. Enable named tenants with `ASTRANULL_PROTECTION_VALIDATION_ENABLED_TENANTS`; configure `ASTRANULL_APPROVED_PROBE_SOURCES` before relying on more than one worker pool.
3. To roll back, set `ASTRANULL_PROTECTION_VALIDATION_ENABLED=0`. Routes and UI sections stop; the next advance of a running comparison skips its pending and deferred paths (`protection_validation_disabled`) and starts nothing. Already-started runs remain ordinary runs, cancellable with `POST /v1/test-runs/:id/cancel` or the kill switch. Stored history is retained.
4. Retests of protection findings always recheck authorization, so re-enabling never replays a stale scope.

Monitoring counters: `protection_validation_findings_failed`, `entry_path_comparison_record_failed`, `entry_path_comparison_finalized_hook_failed`, `entry_path_comparison_tick_failed`, `entry_path_comparison_advance_failed`, `entry_path_comparison_conflict`, `entry_path_comparison_lock_unavailable`, `entry_path_comparison_run_hook_failed`, `target_configuration_context_failed`.

## Status-code semantics

Decision record: [ADR-0017 "Status-code semantics"](../adr/0017-application-entry-path-validation.md#status-code-semantics-decision-2026-10-06). Implementation: `src/lib/externalObservationOutcomes.mjs` (semantics `external-observation-v2`), `isBlockedOrChallenged` in `src/lib/outsideInWafScanner.mjs`, `classifyMarkerResponse` in `src/lib/capabilityProbes.mjs`, `src/lib/firewallChangeAcceptance.mjs` (`firewall-acceptance-v2`), and `deriveAttemptObservation` in `src/lib/entryPathComparison.mjs`.

**Control-specific signature (`denial_signature`).** A denial must have one of these signatures; a status code alone never qualifies.

| Kind | Signals |
|---|---|
| `vendor` | Cloudflare `cf-mitigated: challenge`, or a block page showing error code 1020/1006–1012 or "Attention Required! \| Cloudflare" together with `cf-ray`. Akamai "Access Denied" with `Reference #18.`. Imperva "Incapsula incident ID". AWS: a 403 "Request blocked" with `x-amz-cf-id`, or `<Error><Code>AccessDenied`. F5 ASM "requested URL was rejected" with a support ID (any status, including 200). For marker probes only: a new `x-waf-block`, `x-bot-challenge` or `x-sucuri-block` header, or a new vendor-specific block page. |
| `declared` | Customer-declared response: `status_code` plus `body_sha256` or `header {name, value}`, matched exactly. An mTLS rejection counts only when the origin is declared `mtls: true`. Sources are the signed profile fields `declared_origin_lockdown` and `declared_block_signature`. |

**Direct-origin leg (`classifyDirectOriginObservation`).**

| Observation | Outcome | Direct status | Verdict |
|---|---|---|---|
| CDN edge headers (`server: cloudflare` with `cf-ray`, `x-amz-cf-id`, AkamaiGHost, `x-iinfo`) or a CDN/WAF address range | `not_applicable` (`cdn_edge_ip`) | inconclusive | gap, ignored |
| Declared lockdown signature with a healthy baseline | `explicit_denial_observed`, `origin_lockdown_confirmed` | denied | `edge_protected` (scoped) |
| Declared signature, baseline not healthy; or vendor signature | `explicit_denial_observed` | denied | inconclusive |
| 2xx/3xx with a nonce canary echo and a healthy baseline | `application_identity_confirmed` | exposed | `edge_exposed` (bypass confirmed) |
| 2xx/3xx | `response_observed` | exposed | `edge_exposed` |
| 401 | `response_observed` (`authentication_challenge`) | exposed | `edge_exposed`, low severity: "Origin HTTP service reachable directly; authentication challenge observed" |
| 403, 404 or other 4xx without a signature | `response_observed` (`unattributed_denial`) | inconclusive | inconclusive, lockdown unconfirmed |
| 5xx | `response_observed` (`generic_error_response`) | inconclusive | inconclusive |
| 421 | `misdirected_request` | inconclusive | gap, ignored. The single-request budget allows no retry, so the result stays inconclusive. |
| 407 | `probe_path_error` | inconclusive | gap, ignored |
| Timeout, or RST/refusal (`error_reason: connection_refused`) | `no_response` / `transport_error` | inconclusive | gap, ignored |

**Benign WAF markers.** These rules apply to the scanner, class-marker and entry-path probes, evasion probes, WAF enforcement and inspection-limit probes. GET legs read at most 8 KB of the body for signature matching (never stored), so a block page served with HTTP 200 is a block; the WAF enforcement probe sends GET for this reason. HEAD legs see headers only. A marker is graded only against a healthy permitted baseline: 2xx/3xx with no block signature or challenge header. Otherwise the reason is `baseline_unhealthy`.

| Marker response | Result |
|---|---|
| Signature at any status | `blocked`; row records `denial_signature` and `waf_product_hint` |
| Same as baseline, or 2xx/3xx without a signature | not blocked (`allowed`) |
| 401 | inconclusive, `authentication_gate_precedes_inspection` |
| Other 4xx without a signature that differs from baseline | inconclusive, `block_suspected` (`unattributed_denial`); neither enforcement nor a gap |
| 421 / 407 / 5xx | inconclusive: `misdirected_request` / `probe_path_error` / `error_not_attributable` |
| RST or timeout | inconclusive, `rst_or_drop_unattributed` |

**Firewall samples.**
- `deny` expectations:
  - Any HTTP status from a host/SNI probe, including 401, 403 and 421, is `service_response_observed` (violated).
  - `satisfied` needs `icmp_admin_prohibited` (ICMP type 3, code 13). `rst_after_change` describes a refused connection after an open baseline, but never proves firewall enforcement.
  - Every refusal stays unverified for denial. Without an open baseline it carries `rst_without_open_baseline`.
- `allow` expectations: any service response, including 401 and 403, is satisfied. One refused connection remains unverified; repeated failures can establish observed unavailability.
- Exclusions: 407 (`probe_path_error`) and CDN-edge answers are `not_tested` (excluded).
- Version: v1/v2 baselines are not comparable with the v3 classifier and require fresh capture.

**Entry-path legs.** On comparison relations (not reachability-only), a non-primary leg with an unsigned 401, 403/404 or 5xx and no graded enforcement is inconclusive with the leg reason. On `must_not_be_reachable` relations, any HTTP response (401, unsigned 403, 5xx) is `reachability_exposure`; a declared or vendor signature is `consistent_enforcement`. On `intentionally_public` relations, 2xx/3xx/401 is `intentional_public_access`, an unsigned 403 or 5xx is inconclusive, and a signed block is `denial_on_public_path`. A 421, 407 or CDN-edge leg is inconclusive and ignored.

**Legacy records.** Stored `external-observation-v1` records are re-read under the v2 status mapping, with the limitation `legacy_status_only_denial_reclassified`. The stored rows are not edited. A v1 status-only denial never confirms lockdown or enforcement.

**Test fixtures (synthetic, modeled on the 2026-10-06 `aistripped.com` observations).**
- Baseline 200 with XSS and SQLi markers returning 200 and no `cf-mitigated`: not blocked.
- Cloudflare anycast `104.21.61.235` returning 403 `error code: 1003`: `not_applicable` (`cdn_edge_ip`).
- A Cloudflare 403 for a mismatched Host: `not_applicable`.
- A TLS failure on the anycast address: `transport_error`, excluded.

## Final review round (2026-10-06)

Decision record: [ADR-0017 "Final review round"](../adr/0017-application-entry-path-validation.md#final-review-round-2026-10-06). Staging evidence: [protection-validation-staging-evidence-2026-10-06.md](../backend/protection-validation-staging-evidence-2026-10-06.md).

**Evasion probes (`waf.evasion_*.safe`, 1.1.0).** Sequence: permitted baseline (no marker), the untransformed marker, then the transformed marker. Each response is graded with the shared marker rules above against the permitted baseline.

| Condition | Result |
|---|---|
| Permitted baseline not 2xx/3xx, signed, or failed | inconclusive, `permitted_baseline_not_healthy`; the baseline signature is recorded in `permitted_baseline.denial_signature` |
| Untransformed marker allowed | inconclusive, `baseline_marker_not_blocked` |
| Untransformed marker not graded (401, unsigned 4xx, 5xx, drop) | inconclusive, `baseline_marker_not_graded` |
| Untransformed marker signature-blocked, transformed allowed | `external_allowed`, `evasion_bypass_suspected: true` |
| Both signature-blocked | `external_blocked` |
| Transformed not graded or transport error | inconclusive, `transformed_marker_not_graded`; never `external_allowed` |

A login URL that answers 401 to everything, a healthy page with unsigned 403 markers, and an outage returning 503 are all inconclusive (previously `external_blocked`, which correlated to `edge_protected`).

**Declared login and API paths.** Both relation kinds only run GET/HEAD-only probe kinds (`waf_class_marker_probe`, `waf_evasion_marker_probe`, `waf_enforcement_probe`, `http_head`); other scenarios are ineligible with `login_path_state_change_risk` or `api_path_state_change_risk`. The generic `marker` scenario and generic marker checks select `waf.entry_path_login_marker.safe` or `waf.entry_path_api_marker.safe` ([check library](02-check-library.md)). Every encoded, content-type and padded variation names its plain reference marker and is graded only when that reference was signature-blocked; otherwise it is excluded from enforcement. A signed denial on the permitted baseline is `explicit_denial_observed` (so a `must_not_be_reachable` path the edge blocks is `consistent_enforcement`), and an attempt whose leg answered without usable evidence keeps its gap outcome (for example `not_applicable`) in `attempts[]`.

**Missing evidence in projections.** WAF effectiveness ignores inconclusive marker rows instead of voiding the definitive ones. Reports select, per firewall expectation, the newest evaluation that sampled it; unsampled items carry `post_change_not_sampled`.

**Probe result meaning.** `tls_audit`: a completed handshake is a TLS-profile result (`protected`, or `exposed` with the issues), never "blocked at the edge". `port_scan_bounded`: only 80/443 open is `allowed_as_expected` with no finding; the 5-second job is split across the ports still to sample. `l3.forbidden_tcp_port.safe`, `l3.forbidden_udp_port.safe` and `l3.ipv6_reachability.safe` accept `tcp` (`host:port`, `[IPv6]:port`) targets; a bare IPv6 literal is never split.

**Still open.** No producer fills the signed `declared_origin_lockdown`/`declared_block_signature` profile fields from customer declarations yet; the status-code rule has not been applied to `probeBotChallenge`, `probeRateLimitSequence` or the HTTP method-policy status list (product decision); live re-runs of these fixes are outstanding.


## Review corrections, 2026-10-07

See [ADR-0017 review correction](../adr/0017-application-entry-path-validation.md#review-correction-2026-10-07) and the [review record](../implementation/provider-neutral-protection-validation-review.md). Firewall classification v3 never treats a refused connection as proof of enforcement, even after a formerly open baseline. Static marker echoes cannot confirm application bypass. Reports retain pinned expectations, count unique normalized hosts independently from target records, and expose incomplete capped source input. Concurrent finding derivation serializes by tenant/dedupe key before reading, so a stronger first observation cannot be lost to a simultaneous weaker insert.
