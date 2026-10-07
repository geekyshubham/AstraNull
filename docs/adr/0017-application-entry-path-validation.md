# ADR-0017: Provider-neutral application entry-path and firewall change validation

## Status

Accepted (2026-10-06) as the PV-02 contract decision. The implementation slices (PV-03 to PV-09) remain in progress. Read with [ADR-0008](0008-outside-in-only-targets-first.md), [ADR-0014](0014-inconclusive-readiness-coverage.md), and the [current release scope](../feedback/24-current-release-scope.md).

## Context

Customers want to know three things:

- whether every way into an application is protected, not only the primary hostname;
- whether a firewall change or migration preserved the intended allow/deny behavior;
- whether these answers hold regardless of which vendor or appliance sits in front of the application.

Before this decision, AstraNull could validate a single declared target and a declared protected-host → origin binding. Three things were missing:

- a way to group the alternate routes into one application;
- a versioned expectation to compare against;
- an immutable before/after record.

Vendor connectors are optional and often unavailable, so the answer has to come from outside-in evidence.

## Decision

1. **Explicit entry-path relations.** An existing declared target anchors an application. Each entry path references an existing same-tenant target with one of these relation kinds: `primary_route`, `alternate_hostname`, `declared_api_url`, `declared_login_url`, `origin`, `fallback_backend_route`. Each relation records `owner`, `purpose`, `expected_behavior` and `required_layers`. Relations are declared, never inferred from tags, logos, CNAMEs, headers or vendor names. Origin relations must reference an active origin binding and reuse its authority and Host/SNI/port/path scope. They do not duplicate it.
2. **Independent layers.** `waf`, `cdn_edge`, `network_firewall` and `ddos` are separate layers. For each layer, the following are separate fields:
   - declared intent;
   - vendor detection;
   - observed enforcement;
   - application identity;
   - suspected bypass;
   - confirmed scoped bypass;
   - evidence limitations.

   Every state has an evidence requirement and an unknown/inconclusive alternative.
3. **WAF success is scoped.** A successful WAF block or marker result does not prove DDoS capacity, firewall traversal, or protection of untested routes or attack families. When layers are stacked, a block or bypass is not attributed to a specific inner layer unless evidence establishes it.
4. **Provider neutrality.** A custom or unidentified provider completes the same workflow with all connectors disabled: declare, run reviewed checks, capture a baseline, compare, and inspect gaps. Provider names are optional evidence labels. Configuration evidence can explain an observation. It cannot upgrade untested behavior, authorize traffic, or overwrite historical external results.
5. **Versioned expectations, immutable baselines.**
   - Path-validation and firewall-change expectations carry `expectation_version` and a SHA-256 `digest` over stable-stringified fields.
   - Baselines reference only finalized signed runs, verdicts and evidence ids, each with a recorded source and worker identity. Each baseline pins the expectation version and digest, plus the declaration digest for path validation.
   - Every baseline has a freshness window and a baseline digest. Evidence links are reference-only.
   - A declaration change cannot reinterpret an older baseline.
6. **Compatibility before conclusions.** `assessComparisonCompatibility(baseline, candidate)` must return `comparable: true` before a firewall item can be `matched`, `regression` or `improvement`, or a path item can be conclusive. These all make the pair incomparable:
   - incompatible versions, expectations, sources, checks or targets;
   - an undeclared destination change;
   - unfinished, missing or stale evidence.
7. **Bounded statuses.** Path outcomes:
   - `intentional_public_access`
   - `reachability_exposure`
   - `weaker_observed_enforcement`
   - `suspected_alternate_application_route`
   - `scoped_application_bypass`
   - `consistent_enforcement`
   - `inconclusive`
   - `not_tested`
   - `skipped`

   Firewall statuses: `matched`, `regression`, `improvement`, `inconclusive`, `not_tested`, `stale`, `not_comparable`. Gap kinds: `forbidden_service_newly_reachable`, `required_service_newly_unavailable`. Firewall reports always state `sampled_public_ingress_only`, `rule_table_equivalence_not_established`, `routing_nat_egress_east_west_not_established` and `not_capacity_assurance`. Zero evaluated expectations is never success.
8. **Least-privilege API.** The routes reuse four existing permissions. No new role or permission is added.

   | Permission | Used for |
   |---|---|
   | `target_group:read` | Reading declarations. |
   | `target_group:write` | Writing declarations, capturing baselines and recording evaluations. These write paths never dispatch traffic. |
   | `evidence:read` | Reading the matrix and comparisons. |
   | `test_run:start` | The reviewed entry-path comparison start. It is the only route that can dispatch traffic. |

   There is no public observation-write endpoint.

## Contract location

- Code: `src/contracts/protectionValidation.mjs` (`protection-validation-v1`).
- Spec: [detection/23](../detection/23-application-entry-path-validation.md).
- API: the "Application entry paths and firewall change acceptance" section of [`docs/api.md`](../api.md).
- Tests: `tests/unit/protection-validation-contract.test.mjs`.

## Consequences

| Positive | Negative |
|---|---|
| One workflow for every provider, including unknown or custom ones, with no credentials. | Without a nonce-bound canary, alternate routes can only be *suspected*, not confirmed as a bypass. |
| Each conclusion can be reconstructed from referenced, digested, immutable records. | Pre/post migrations need an explicit customer mapping when the destination changes. Inferred IP changes are not comparable. |
| Stale, partial, incompatible and unknown states stay visible instead of being folded into a pass. | Full rule-table, routing, NAT, egress and east-west equivalence and volumetric capacity stay out of scope. They need separately governed work. |
| Existing signed jobs, origin gates, budgets, kill switches and SOC controls are reused unchanged. | Additional tables, services and UI (PV-03 to PV-07) are required before customers can use the workflow. |

## Out of scope

- Mandatory vendor connectors.
- Automatic IP inventory discovery.
- Agents and environments.
- Arbitrary destination, Host or SNI overrides.
- Source spoofing.
- Reusable attack tooling.
- Automatic rule deployment.
- Unrestricted or high-scale execution, which remains SOC-gated.

## Runtime integration decisions

Recorded when the slices were wired together (details: detection/23 "Runtime integration").

1. **Tenant gate, default off.** The workflow ships behind `protection_validation` (`ASTRANULL_PROTECTION_VALIDATION_ENABLED` and per-tenant overrides). An explicit `0` is a global rollback switch; disabling never deletes retained history.
2. **Server-side source perspective.** A run's source perspective comes from the signed worker id through an approved registry (`ASTRANULL_APPROVED_PROBE_SOURCES`). Without a registry, all signed workers form one shared pool. Worker-submitted labels are ignored, so a source cannot be self-declared.
3. **One firewall classifier.** Firewall baselines and comparisons use the PV-05 classifier and are stored as PV-03 rows; baseline entries keep their observation records so later evaluations can verify them.
4. **Findings from recorded evaluations only.** Findings are derived when an evaluation is first recorded, never on reads or replays, and never close existing findings. Protection-finding retests always recheck current authorization.
5. **One comparison lifecycle on both stores (updated 2026-10-06).** Entry-path comparisons run the same lifecycle code on the dev store and on Postgres (migration `0071`). Postgres uses a per-comparison advisory lock, a compare-and-set `lock_version` on every save, and a `reconcile_seq` request when a run-finished hook cannot take the lock. Postgres has no in-process ticker: the validation-scan runner (also run by `test-policy-runner`) advances due comparisons per tenant, settles runs that finished under another worker's lock, and retries evaluation links. A failing comparison is recorded and skipped so it never starves the tick. Deferrals do not count as start attempts and stop after 24 hours (`deferral_limit_reached`). A lock connection that cannot be obtained reads as "busy", so a hook falls back to a reconcile request instead of being lost. The runner pauses on the tenant gate and never cancels; only the API process, which reads the full server config, cancels on the gate. The `503 postgres_route_not_wired` response remains only for a runtime with a missing dependency.
6. **Disablement stops queued work.** When the gate is off for a tenant, a running comparison's pending and deferred paths are skipped with `protection_validation_disabled` on the next advance; started runs stay ordinary cancellable runs. Operator procedure: [protection validation rollout](../backend/protection-validation-rollout.md).
7. **Results with missing evidence are ignored for findings (product decision, 2026-10-06).** These results never create a finding:
   - path outcomes `inconclusive`, `not_tested` and `skipped`;
   - firewall statuses `inconclusive`, `not_tested`, `stale` and `not_comparable`, including evidence that is absent, unfinished or not in the baseline;
   - any item without a finalized evidence reference.

   The `unavailable_evidence` finding class and the `includeUnavailableEvidence` option are retired. These results also never update, escalate or close an existing finding, and never count toward pass or success. They stay visible as unknown or not tested in the matrix and reports, inside the same denominators, and report conclusions mark them `ignored_for_findings`. Rows already stored with the legacy class stay readable and can escalate when conclusive evidence arrives. Rationale: a finding is a work item, so it must be backed by an observed gap. Missing evidence is a coverage problem, and the report already shows it as one. This follows the comparable products in the research below: SafeBreach keeps "No result" and "Inconsistent" apart from prevented/missed, GoTestWAF leaves unresolved requests out of its score, and Burp treats repeated errors as unattributed rather than as a block. Details: [detection/23](../detection/23-application-entry-path-validation.md#findings-and-missing-evidence).

## Status-code semantics (decision, 2026-10-06)

The product owner asked us to research how comparable products interpret HTTP status codes and to follow that practice. Before this decision, AstraNull treated a bare 401, 403 or 421 as an "explicit denial". As a result, an application login challenge or a CDN edge 403 could count as origin lockdown, and an HTTP reply on a port that should be firewalled could count as "deny satisfied". Details: [detection/23 "Status-code semantics"](../detection/23-application-entry-path-validation.md#status-code-semantics).

1. **A status code is never a denial on its own.** `explicit_denial_observed` now requires a control-specific signature, recorded in `denial_signature`. A signature is one of:
   - a vendor block marker (Cloudflare `cf-mitigated: challenge` or a 1020/1006–1012 or "Attention Required" block page; Akamai "Access Denied" with `Reference #18.`; Imperva incident ID; AWS CloudFront WAF "Request blocked" with `x-amz-cf-id`; F5 ASM "requested URL was rejected" with a support ID);
   - a customer-declared response (status plus body hash or header, matched exactly);
   - for firewalls, ICMP administratively prohibited. A TCP refusal, even after an open baseline, does not establish firewall enforcement.
2. **Status mapping without a signature.**
   - 401 is a response with reason `authentication_challenge`.
   - 403, 404 and other 4xx are a response with reason `unattributed_denial`.
   - 5xx is a response with reason `generic_error_response`.
   - 421 is a new `misdirected_request` outcome and 407 a new `probe_path_error` outcome. Both are evidence gaps.
   - A refusal is `transport_error`, refined as `connection_refused`.
   - A timeout is `no_response`.
3. **Origin lockdown only from a declared lockdown response.** `origin_lockdown_confirmed` requires all of:
   - a customer-declared lockdown signature on the direct leg (for example an ALB fixed `403 Access denied` or a header), or an mTLS rejection on an origin declared for mTLS;
   - a healthy 2xx/3xx permitted-path baseline.

   An undeclared 403 leaves lockdown unconfirmed (inconclusive). A 401 means the origin HTTP service is reachable directly and an authentication challenge was observed (suspected exposure, low severity). A vendor block signature is a denial but not lockdown.
4. **CDN-edge guard.** A direct-origin answer that carries CDN edge headers, or comes from an address in a CDN or WAF range (pinned cdncheck data), is `not_applicable` (`cdn_edge_ip`). It is not an origin observation.
5. **Evidence gaps are ignored.** `not_tested`, `no_response`, `transport_error`, `misdirected_request`, `probe_path_error`, `not_applicable`, an unhealthy baseline and `response_evidence_not_recorded` never become pass, fail or partial. They are shown only as coverage gaps with a reason code. This extends decision 7.
6. **WAF benign markers.** A marker counts as blocked only with a signature; without one:
   - 2xx/3xx is not blocked;
   - 401 is `authentication_gate_precedes_inspection`;
   - another 4xx that differs from the baseline is `block_suspected`, which counts neither as enforcement nor as a gap;
   - 421, 407, 5xx and RST/timeout are inconclusive.

   Grading requires a healthy, unsigned permitted baseline.
7. **Firewall deny expectations follow Nmap port semantics.** Any HTTP status, TLS reply or banner means the service is reachable, so a deny expectation is violated. Silence and TCP refusals stay unverified for enforcement, regardless of whether the pre-change baseline was open.
8. **Entry-path legs** use the same per-leg classifier. On comparison relations, an unsigned alternate-leg 401, 403/404 or 5xx is inconclusive. On `must_not_be_reachable` relations, any HTTP response is `reachability_exposure`, and only a declared or vendor signature is `consistent_enforcement`. On `intentionally_public` relations, 2xx/3xx/401 is public access.
9. **Versioning.**
   - Observation semantics are now `external-observation-v2`. Stored v1 records are re-read under the v2 status mapping and never edited; a v1 status-only denial never confirms lockdown.
   - The firewall classifier is now `firewall-acceptance-v2`. v1 baselines are `check_version_mismatch` and need a fresh capture.
   - Affected check versions were bumped: the host/SNI checks and `waf.fingerprint.safe` to 1.2.0; the WAF enforcement, inspection-limit and class-marker checks to 1.1.0; in the final review round, all 41 `waf.evasion_*.safe` checks to 1.1.0 and `l3.firewall_exposure_scan.safe` to 1.1.0.

Sources:
- Standards: [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html) (401/403/404/407/421 semantics) and [Nmap port states](https://nmap.org/book/man-port-scanning-basics.html).
- Cloudflare: [421](https://developers.cloudflare.com/support/troubleshooting/http-status-codes/4xx-client-error/error-421/), [origin protection](https://developers.cloudflare.com/fundamentals/security/protect-your-origin-server/), [challenge detection](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/).
- Other vendor documentation: [nginx `ssl_verify_client`](https://nginx.org/en/docs/http/ngx_http_ssl_module.html), [AWS ALB restricted to CloudFront](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/restrict-access-to-load-balancer.html), [AWS WAF custom responses](https://docs.aws.amazon.com/waf/latest/developerguide/customizing-the-response-for-blocked-requests.html), [Akamai Origin IP ACL](https://techdocs.akamai.com/origin-ip-acl/docs/set-up-origin-ip-acl).
- Open-source tools: [Imperva site-protection-viewer](https://github.com/imperva/site-protection-viewer/blob/master/settings.js), [CloudFlair](https://github.com/christophetd/CloudFlair), [cdncheck](https://github.com/projectdiscovery/cdncheck), [Nuclei waf-detect](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/technologies/waf-detect.yaml), [wafw00f](https://github.com/EnableSecurity/wafw00f/blob/master/wafw00f/main.py), [identYwaf](https://github.com/stamparm/identYwaf/blob/master/identYwaf.py), [Fastly wafefficacy](https://github.com/fastly/wafefficacy).
- Commercial products: [Cymulate](https://cymulate.com/resources/cymulate-waf-solution-brief/), [SafeBreach](https://www.safebreach.com/blog/safebreach-for-security-control-validation/), [Detectify](https://support.detectify.com/support/solutions/articles/48001268915-scans-blocked-by-waf), [Qualys WAS](https://success.qualys.com/discussions/s/article/000006299), [Burp Scanner](https://portswigger.net/burp/documentation/scanner/burp-scanner-error-reference) and [ZAP authentication](https://www.zaproxy.org/docs/desktop/start/features/authentication/).
- The live observations of `aistripped.com` (the user-designated test target) were captured by the research pass on 2026-10-06. They are reproduced only as synthetic unit fixtures; the tests send no traffic.

## Final review round (2026-10-06)

Review findings and the `aistripped.com` staging run led to these additional decisions. Evidence: [staging evidence](../backend/protection-validation-staging-evidence-2026-10-06.md), [rollout](../backend/protection-validation-rollout.md#staging-evidence-2026-10-06).

1. **Every marker probe reads signatures, not status codes.** The evasion probe used its own status list (400/401/403/405/406/409/413/414/429/431/501/503 = blocked). It now uses the shared signature grading, always sends a permitted baseline, and stays inconclusive unless that baseline is healthy (2xx/3xx, unsigned) and the untransformed marker was signature-blocked. A transport error on a variant is excluded, never `external_allowed`.
2. **Body signatures are visible.** GET marker legs (class-marker, entry-path, evasion, inspection-limit POST variants, and the WAF enforcement probe, which now sends GET instead of HEAD) read at most 8 KB of the body for signature matching and never store it. A block page served with HTTP 200 (F5 ASM) is a block. HEAD legs (host/SNI and scanner origin) cannot see bodies, so a customer declaration that relies on a body hash only matches on GET legs; use a header-based declaration there.
3. **A signed denial on a marker leg's permitted baseline is a denial.** The probe records `permitted_baseline.denial_signature`; the comparison reads it as `explicit_denial_observed`, so a `must_not_be_reachable` path the edge blocks is `consistent_enforcement`, matching the host/SNI path.
4. **Declared API paths get the login safety rule.** Declared login and API URLs only run GET/HEAD-only probe kinds (`waf_class_marker_probe`, `waf_evasion_marker_probe`, `waf_enforcement_probe`, `http_head`). Anything else is ineligible with `api_path_state_change_risk` or `login_path_state_change_risk`. The new `waf.entry_path_login_marker.safe` and `waf.entry_path_api_marker.safe` checks (1.0.0) carry the login/API variations.
5. **Missing evidence is ignored, not scored.** Inconclusive marker rows no longer void definitive rows in WAF effectiveness, and a later firewall evaluation that never sampled an expectation does not hide an earlier sampled result. This applies decision 7 and status-code decision 5 to the remaining projections.
6. **Probe results describe what they measured.** A completed TLS handshake is a TLS-profile result, not an edge block. A port scan that finds only 80/443 open is the expected web service, not a firewall exposure.
7. **Rendered UI review.** The protection-validation pages were reviewed in a real browser at 375/768/1024/1440 px in both themes, keyboard-only and with reduced motion; 11 rendering defects were fixed and pinned in `tests/e2e/journeys/protection-validation.spec.mjs`. A human sign-off is still outstanding.


## Review correction (2026-10-07)

Firewall comparison classification is `firewall-acceptance-v3`. Version 2 incorrectly accepted a TCP refusal after an open baseline as firewall denial. A closed port can receive probes and respond without a listening application; this differs from filtering ([Nmap port states](https://nmap.org/book/man-port-scanning-basics.html)). A refusal now stays transport evidence. One failure cannot establish required-service unavailability; repeated failures may establish an observed availability regression. Older baselines need fresh capture and are not rewritten.

A generic AWS storage `AccessDenied` XML response is not a WAF signature. A static marker echo is supporting identity evidence, but only a nonce-bound canary over a healthy baseline confirms an application bypass. Configured invalid/empty source registries admit no workers; an absent registry alone uses the shared public pool.

Evaluation projections use their pinned expectation rather than a newer layer declaration. Reports deduplicate normalized hosts independently of target records and mark capped input as incomplete. Origin finding retests must preserve the original binding. Unknown paths that were skipped without evidence can be retained in a comparison evaluation without becoming execution authority.
