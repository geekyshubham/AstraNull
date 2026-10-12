# Verified capability audit remediation

## Provenance and scope

Implementation authorized after the plan-only request by the explicit instruction to start and finish implementation. Source audit: `AstraNull_Verified_Capability_Audit.html`, SHA-256 `e5fd4a1fd6c0c4f791d7bae15cc79e00707178de072c0a661851290678d96e0a`. Planning snapshot `206d5182179d8eeae1f205703b18617dfec2b286`; implementation baseline `b720102ddfc7dfc92c0bc88de28db26b338150c4`. The audit is historical source-review input, not deployed certification. Original 251 definitions/38 engines/721 vector rows and E1/E2/E3/E4 counts describe that snapshot; current inventories are versioned separately.

No new cloud/read-only integrations, origin telemetry, customer agents/environments, mandatory discovery, SOC/governed workflows, partner execution, unmanaged traffic, or safety bypasses. Existing gates and integrations remain intact. “Environment” means the authorized declared targets. No customer/public probes, hosted deployment, live notification sends, production migrations, commits or pushes are authorized by this implementation.

Status vocabulary: **confirmed defect**, **already corrected**, **locally verified**, **partly implemented**, **external acceptance**, **excluded by scope**, **assessment only**. Local acceptance is separate from deployment. “Locally verified” means the confirmed current-platform repair and its applicable local gates passed, not that missing producers, excluded directions or external acceptance were delivered. G08 remains partly implemented; external acceptance is never closed by local fixtures.

## G01–G54 exhaustive disposition

| ID | Audit issue | Disposition | Code owner / sources | Regression anchors | Acceptance / remaining boundary |
|---|---|---|---|---|---|
| G01 | One verdict/evidence contract | locally verified | Detection: `src/lib/externalObservationOutcomes.mjs; src/lib/readinessVerdicts.mjs` | `tests/unit/pv01-external-observation-semantics.test.mjs` | Versioned observations never turn a status, timeout, fingerprint or incomplete leg into protection. |
| G02 | Fix rate, bot and GraphQL verdicts | locally verified | Detection / protocol: `src/lib/capabilityProbes.mjs; src/lib/probeEvidenceTiers.mjs` | `tests/unit/capability-probes.test.mjs; tests/unit/safe-network-probes.test.mjs` | Rate/bot/GraphQL samples remain observation-only without a specific approved healthy comparison. |
| G03 | Fix HTTP/2 protection claims | locally verified | Detection / protocol: `src/lib/capabilityProbes.mjs; src/lib/probeEvidenceTiers.mjs` | `tests/unit/capability-probes.test.mjs; tests/unit/safe-network-probes.test.mjs` | HTTP/2 SETTINGS are E2; no reset/CONTINUATION/HPACK flood or resilience claim. |
| G04 | Fix evasion mechanism truthfulness | locally verified | Protocol: `src/lib/vectorProbes/evasionProbes.mjs; src/contracts/manifests/evasion.manifest.mjs` | `tests/unit/evasion-probes.test.mjs; tests/unit/vector-library.test.mjs` | Only attested safe request shape is executed; unsupported delivery is zero-I/O and excluded from runnable coverage. |
| G05 | Fix baseline/body/method integration | locally verified | Probe runtime: `src/lib/vectorProbes/wafClassProbes.mjs; src/lib/outsideInWafScanner.mjs` | `tests/unit/waf-class-probes.test.mjs; tests/unit/pv-signature-grading-regressions.test.mjs` | Bounded signature body retained; healthy independent baseline and all planned marker legs required; HEAD has no invented body. |
| G06 | Fix DNS recursion and DNSSEC claims | locally verified | DNS: `src/lib/dnsWireQuery.mjs; src/lib/dnsTcpAxfrSession.mjs; src/lib/capabilityProbes.mjs` | `tests/unit/capability-probes.test.mjs; tests/unit/reflector-guardrails.test.mjs` | Authoritative answers do not prove recursion; DNSKEY does not prove cryptographic DNSSEC validation. |
| G07 | Fix cache and fake-size conclusions | locally verified | Detection / protocol: `src/lib/capabilityProbes.mjs; src/lib/probeEvidenceTiers.mjs` | `tests/unit/capability-probes.test.mjs; tests/unit/safe-network-probes.test.mjs` | Transferred bytes govern size claims; ordinary cache behavior, invalid encoding and oversized local refusal do not prove mitigation. |
| G08 | Complete origin identity and lockdown producer | partly implemented | Validation: `src/lib/entryPathComparison.mjs; src/lib/capabilityProbes.mjs` | `tests/unit/entry-path-comparison.test.mjs; tests/unit/entry-path-comparison-signed-scope.test.mjs` | Fresh same-scenario identity/nonce comparison only. Standalone host/SNI lacks permitted baseline; declaration producer and scanner-origin signed authority remain unsupported/inconclusive, not newly implemented. |
| G09 | Separate readiness from resilience | locally verified | Detection / data: `src/lib/readinessProjection.mjs; src/lib/protectionCoverage.mjs` | `tests/unit/readiness.test.mjs; tests/unit/inconclusive-coverage.test.mjs` | Coverage-bound target/check score, seven-day immutable age, zero governance protection credit, incomplete input score null; never DDoS capacity. |
| G10 | Do not validate a CVE with a fingerprint | locally verified | Detection / workflow: `src/contracts/cvePipeline.mjs; src/services/cvePipeline.mjs` | `tests/unit/cve-validation-executor.test.mjs` | Specific approved scenario/component/version/mitigation + exact retest lineage required. Current generic fingerprint catalog cannot validate CVE mitigation. |
| G11 | Validate marker and business-request safety | locally verified | Security / runtime: `src/lib/probeJobs.mjs; src/lib/probeExecution.mjs; workers/probe-worker.mjs` | `tests/unit/verified-execution-safety.test.mjs; tests/integration/postgres-probe-activity.test.mjs` | Inert markers, no unapproved callback or arbitrary business POST, bounded pinned local wire fixtures. |
| G12 | Prove distributed budgets and stop | external acceptance | Security / runtime: `src/lib/probeJobs.mjs; src/lib/probeExecution.mjs; workers/probe-worker.mjs` | `tests/unit/verified-execution-safety.test.mjs; tests/integration/postgres-probe-activity.test.mjs` | Local one-shot grant, expiry, partition and ACK regressions implemented. Real distributed fleet stop timing/capacity is unverified and not authorized here. |
| G13 | Post-protection observation | excluded by scope | Reporting / UX: `src/lib/protectionValidationReport.mjs; apps/web/react/src/components/evidence/execution-inspector.tsx` | `tests/unit/protection-validation-report.test.mjs; tests/e2e/journeys/portal-probe-activity.spec.mjs` | No new origin/edge/WAF/LB log integration; origin receipt stays unavailable. |
| G14 | Trustworthy leakage accounting | excluded by scope | Reporting / UX: `src/lib/protectionValidationReport.mjs; apps/web/react/src/components/evidence/execution-inspector.tsx` | `tests/unit/protection-validation-report.test.mjs; tests/e2e/journeys/portal-probe-activity.spec.mjs` | No fabricated generated-to-origin denominator or leakage percentage. |
| G15 | Legitimate-user impact and safety SLOs | assessment only | Probe runtime: `src/lib/vectorProbes/wafClassProbes.mjs; src/lib/outsideInWafScanner.mjs` | `tests/unit/waf-class-probes.test.mjs; tests/unit/pv-signature-grading-regressions.test.mjs` | Healthy permitted baseline prevents all-user denial credit. Independent journey p95/p99, goodput, cost/SLO telemetry is not implemented. |
| G16 | Mitigation onset and recovery timing | assessment only | Detection / protocol: `src/lib/capabilityProbes.mjs; src/lib/probeEvidenceTiers.mjs` | `tests/unit/capability-probes.test.mjs; tests/unit/safe-network-probes.test.mjs` | Recorded sample times may be shown; independent provider activation/recovery timing is unavailable. |
| G17 | Rate-limit calibration and key semantics | assessment only | Detection / protocol: `src/lib/capabilityProbes.mjs; src/lib/probeEvidenceTiers.mjs` | `tests/unit/capability-probes.test.mjs; tests/unit/safe-network-probes.test.mjs` | Existing bounded samples do not calibrate hidden thresholds, identity keys or every client population. |
| G18 | GCP Cloud Armor configuration connector | excluded by scope | Reporting / UX: `src/lib/protectionValidationReport.mjs; apps/web/react/src/components/evidence/execution-inspector.tsx` | `tests/unit/protection-validation-report.test.mjs; tests/e2e/journeys/portal-probe-activity.spec.mjs` | No new GCP Cloud Armor connector. |
| G19 | Azure protection configuration connector | excluded by scope | Reporting / UX: `src/lib/protectionValidationReport.mjs; apps/web/react/src/components/evidence/execution-inspector.tsx` | `tests/unit/protection-validation-report.test.mjs; tests/e2e/journeys/portal-probe-activity.spec.mjs` | No new Azure protection connector. |
| G20 | AWS resource-level coverage and 2026 L7 controls | excluded by scope | Reporting / UX: `src/lib/protectionValidationReport.mjs; apps/web/react/src/components/evidence/execution-inspector.tsx` | `tests/unit/protection-validation-report.test.mjs; tests/e2e/journeys/portal-probe-activity.spec.mjs` | No new AWS resource/account/L7 integration; prior configuration remains explanation-only. |
| G21 | Effective WAF policy analysis | excluded by scope | Reporting / UX: `src/lib/protectionValidationReport.mjs; apps/web/react/src/components/evidence/execution-inspector.tsx` | `tests/unit/protection-validation-report.test.mjs; tests/e2e/journeys/portal-probe-activity.spec.mjs` | No effective-policy connector expansion; existing explanation context cannot satisfy runtime proof. |
| G22 | Akamai full traffic-path correlation | excluded by scope | Reporting / UX: `src/lib/protectionValidationReport.mjs; apps/web/react/src/components/evidence/execution-inspector.tsx` | `tests/unit/protection-validation-report.test.mjs; tests/e2e/journeys/portal-probe-activity.spec.mjs` | No new Akamai full-path correlation integration. |
| G23 | All declared entry paths and address families | locally verified | Validation: `src/lib/entryPathComparison.mjs; src/lib/capabilityProbes.mjs` | `tests/unit/entry-path-comparison.test.mjs; tests/unit/entry-path-comparison-signed-scope.test.mjs` | Honor signed target/path/port/SNI/address family; no discovery or widening from historical group association. |
| G24 | Repair TLS, gRPC, API, CORS and DNS availability semantics | locally verified | Detection / protocol: `src/lib/capabilityProbes.mjs; src/lib/probeEvidenceTiers.mjs` | `tests/unit/capability-probes.test.mjs; tests/unit/safe-network-probes.test.mjs` | TLS/gRPC/API/CORS/DNS outcomes state actual bounded protocol observation, not exhaustive control/capacity proof. |
| G25 | Remove fictional historical coverage | locally verified | Data: `src/services/wafCoverageService.mjs; src/lib/wafPostureAssurance.mjs` | `tests/unit/waf-coverage-service.test.mjs; tests/unit/waf-risk-service.test.mjs` | No retained historical snapshot means unknown; present evidence cannot backfill a past cutoff. |
| G26 | Calibrate fingerprints and preserve unknown | locally verified | Detection / QA: `src/contracts/vectorTargetMatrix.mjs; src/lib/probeEvidenceTiers.mjs` | `tests/unit/vector-library.test.mjs; tests/unit/full-catalog-live-evidence.test.mjs` | Fingerprint conflicts/unknown preserved; corpus calibration and fleet ground truth remain external acceptance. |
| G27 | Deduplicate semantic coverage | locally verified | Detection / QA: `src/contracts/vectorTargetMatrix.mjs; src/lib/probeEvidenceTiers.mjs` | `tests/unit/vector-library.test.mjs; tests/unit/full-catalog-live-evidence.test.mjs` | Definition/vector/profile/mechanism counts separate; shared semantic mappings do not prove independent defenses. |
| G28 | Replace generic remediation | locally verified | Detection: `src/lib/remediationPlan.mjs; src/services/remediation.mjs` | `tests/unit/remediation-delivery.test.mjs` | Observed cause, confidence, bounded scope, owner/action/impact/rollback and compatible retest; no invented vendor config. |
| G29 | Real benign and application-aware scenarios | assessment only | Probe runtime: `src/lib/vectorProbes/wafClassProbes.mjs; src/lib/outsideInWafScanner.mjs` | `tests/unit/waf-class-probes.test.mjs; tests/unit/pv-signature-grading-regressions.test.mjs` | Additional benign business journeys require approved side-effect-free endpoints; no login/payment/OTP transactions. |
| G30 | Multi-vantage repeatability | assessment only | Reporting / UX: `src/lib/protectionValidationReport.mjs; apps/web/react/src/components/evidence/execution-inspector.tsx` | `tests/unit/protection-validation-report.test.mjs; tests/e2e/journeys/portal-probe-activity.spec.mjs` | Only signed available source context; no invented locations or new fleet deployment. |
| G31 | Automatic change invalidation | locally verified | Workflow: `src/lib/assuranceScope.mjs; src/lib/protectionCoverage.mjs` | `tests/unit/inconclusive-coverage.test.mjs; tests/unit/protection-validation-report.test.mjs` | Material target/policy/catalog scope changes invalidate current assurance; historical custody unchanged; reviewed retest only. |
| G32 | Certified live DDoS simulation adapter | excluded by scope | Security / runtime: `src/lib/probeJobs.mjs; src/lib/probeExecution.mjs; workers/probe-worker.mjs` | `tests/unit/verified-execution-safety.test.mjs; tests/integration/postgres-probe-activity.test.mjs` | No new certified live partner/SOC adapter; existing SOC gates retained. |
| G33 | L3/L4 bandwidth, packet and state resilience | excluded by scope | Security / runtime: `src/lib/probeJobs.mjs; src/lib/probeExecution.mjs; workers/probe-worker.mjs` | `tests/unit/verified-execution-safety.test.mjs; tests/integration/postgres-probe-activity.test.mjs` | No L3/L4 traffic/state/capacity generator. |
| G34 | Application concurrency and expensive endpoint resilience | excluded by scope | Security / runtime: `src/lib/probeJobs.mjs; src/lib/probeExecution.mjs; workers/probe-worker.mjs` | `tests/unit/verified-execution-safety.test.mjs; tests/integration/postgres-probe-activity.test.mjs` | No application concurrency/expensive-endpoint resilience execution. |
| G35 | Autoscaling, quotas and economic exposure | excluded by scope | Reporting / UX: `src/lib/protectionValidationReport.mjs; apps/web/react/src/components/evidence/execution-inspector.tsx` | `tests/unit/protection-validation-report.test.mjs; tests/e2e/journeys/portal-probe-activity.spec.mjs` | No cloud autoscaling/quota/cost collection. |
| G36 | Failover, degraded mode and recovery | excluded by scope | Security / runtime: `src/lib/probeJobs.mjs; src/lib/probeExecution.mjs; workers/probe-worker.mjs` | `tests/unit/verified-execution-safety.test.mjs; tests/integration/postgres-probe-activity.test.mjs` | No new failover/degraded-mode/SOC recovery exercise. |
| G37 | Multi-vector, pulse and per-path adaptation | excluded by scope | Security / runtime: `src/lib/probeJobs.mjs; src/lib/probeExecution.mjs; workers/probe-worker.mjs` | `tests/unit/verified-execution-safety.test.mjs; tests/integration/postgres-probe-activity.test.mjs` | No multi-vector/pulse/adaptive campaign tooling. |
| G38 | End-to-end alert and incident response | excluded by scope | Backend: `src/persistence/postgres/protectionFindingsRepository.mjs; src/persistence/postgres/notificationServiceAdapters.mjs` | `tests/integration/postgres-protection-validation-api.test.mjs; tests/integration/postgres-notification-outbox.test.mjs` | Existing outbox correctness is tested; end-to-end on-call/incident drills/new workflows are excluded. |
| G39 | Tenant isolation and concurrency acceptance | locally verified | Backend / security: `src/persistence/postgres/tenantContext.mjs; src/persistence/postgres/validationEvidenceRepository.mjs` | `tests/unit/postgres-tenantContext.test.mjs; tests/integration/postgres-safe-admission-completeness.test.mjs` | App-role RLS, same-pool tenant transaction, last-slot race and uncapped accounting tested; production acceptance separate. |
| G40 | Release truth and traceability | external acceptance | Release / QA: `PROGRESS.md; docs/implementation/current-release/review-ledger.md` | `npm test; make verify; browser and contract gates below` | Local test/build truth only; no commit/push/deployment/image attestation or production signoff generated. |
| G41 | Credential/authentication rollout | external acceptance | Release / QA: `PROGRESS.md; docs/implementation/current-release/review-ledger.md` | `npm test; make verify; browser and contract gates below` | Existing identity/revocation regressions run; real IdP rollout and human acceptance stay open. |
| G42 | Evidence retention and custody | external acceptance | Release / QA: `PROGRESS.md; docs/implementation/current-release/review-ledger.md` | `npm test; make verify; browser and contract gates below` | Existing custody/tamper regressions run; real KMS/retention/legal and backup drills stay open. |
| G43 | Outbound integration delivery | locally verified | Backend: `src/persistence/postgres/protectionFindingsRepository.mjs; src/persistence/postgres/notificationServiceAdapters.mjs` | `tests/integration/postgres-protection-validation-api.test.mjs; tests/integration/postgres-notification-outbox.test.mjs` | Opted-in PV high/critical findings atomically queued with domain write; replay/rollback/RLS/disabled rules tested. No live sends/new channels/test-send endpoint. |
| G44 | Scheduler/target-only migration closure | locally verified | Backend: `src/services/validationScans.mjs; src/persistence/postgres/validationScanServiceAdapters.mjs` | `tests/unit/validation-scan-management.test.mjs; tests/integration/postgres-validation-scans.test.mjs` | Preserve direct-target policies, recurrence scope and common admission; no customer group UI; historical implementation already committed. |
| G45 | Ground-truth regression suite | locally verified | Release / QA: `PROGRESS.md; docs/implementation/current-release/review-ledger.md` | `npm test; make verify; browser and contract gates below` | Ground-truth negative/control/local-wire and all applicable release gates; fixtures do not certify every vendor. |
| G46 | Scope-specific report language | locally verified | Reporting / UX: `src/lib/protectionValidationReport.mjs; apps/web/react/src/components/evidence/execution-inspector.tsx` | `tests/unit/protection-validation-report.test.mjs; tests/e2e/journeys/portal-probe-activity.spec.mjs` | Exact live ID, bounds/capture/Stop, outcome vs expectation, ignored-for-findings, not-tested/incomplete and attribution shown separately. |
| G47 | BGP/RPKI/IRR assurance | assessment only | Detection / QA: `src/contracts/vectorTargetMatrix.mjs; src/lib/probeEvidenceTiers.mjs` | `tests/unit/vector-library.test.mjs; tests/unit/full-catalog-live-evidence.test.mjs` | BGP/RPKI/IRR: possible separate timestamped public-routing posture, not ASN-hosting assurance. |
| G48 | Broader attack-surface discovery | assessment only | Detection / QA: `src/contracts/vectorTargetMatrix.mjs; src/lib/probeEvidenceTiers.mjs` | `tests/unit/vector-library.test.mjs; tests/unit/full-catalog-live-evidence.test.mjs` | Broader passive candidates never become mandatory inventory or authorization to probe. |
| G49 | AI selection and authoring | assessment only | Detection / QA: `src/contracts/vectorTargetMatrix.mjs; src/lib/probeEvidenceTiers.mjs` | `tests/unit/vector-library.test.mjs; tests/unit/full-catalog-live-evidence.test.mjs` | Deterministic coverage-aware reviewed suggestions before AI; no automatic/free-form traffic authoring. |
| G50 | Provider-policy and capability versioning | locally verified | Detection / QA: `src/contracts/vectorTargetMatrix.mjs; src/lib/probeEvidenceTiers.mjs` | `tests/unit/vector-library.test.mjs; tests/unit/full-catalog-live-evidence.test.mjs` | Current check/scenario/classifier/provenance versions reject stale proof; no provider/SOC policy expansion. |
| G51 | Per-protocol response identity | locally verified | DNS: `src/lib/dnsWireQuery.mjs; src/lib/dnsTcpAxfrSession.mjs; src/lib/capabilityProbes.mjs` | `tests/unit/capability-probes.test.mjs; tests/unit/reflector-guardrails.test.mjs` | Peer/protocol/message/transaction identity required; malformed/truncated/right-size wrong-protocol results remain inconclusive. |
| G52 | Layer-specific attribution | locally verified | Reporting / UX: `src/lib/protectionValidationReport.mjs; apps/web/react/src/components/evidence/execution-inspector.tsx` | `tests/unit/protection-validation-report.test.mjs; tests/e2e/journeys/portal-probe-activity.spec.mjs` | One unattributed denial cannot credit WAF and CDN independently; inner-layer telemetry excluded. |
| G53 | Client population and exclusion coverage | locally verified | Detection / protocol: `src/lib/capabilityProbes.mjs; src/lib/probeEvidenceTiers.mjs` | `tests/unit/capability-probes.test.mjs; tests/unit/safe-network-probes.test.mjs` | Use approved endpoint/exposure expectations; unsampled client populations/exclusions remain untested. |
| G54 | Data-plane proof separate from account configuration | locally verified | Reporting / UX: `src/lib/protectionValidationReport.mjs; apps/web/react/src/components/evidence/execution-inspector.tsx` | `tests/unit/protection-validation-report.test.mjs; tests/e2e/journeys/portal-probe-activity.spec.mjs` | Configured, attached, in-path and runtime-observed are distinct; permission-gated existing explanation data grants zero protection credit. |

## Live workspace and signed execution acceptance

- Exact accepted run/scan ID opens the existing Inspector; single/batch/initial detection retain returned IDs rather than select the newest list item.
- Shared passive REST reader drains ascending ingestion pages, deduplicates immutable IDs, retries with bounded backoff, fetches final events, respects historical pins and scope/access revocation even while display is paused.
- Signed bounds/plans are not observed traffic. Recorded previews are bounded/redacted. Recorded metadata is not packet-complete capture.
- `pw2` binds worker identity, method/full path, timestamp, raw body and tenant. `probe-authority-v2` retains immutable issue/deadline/one execution attempt through recovery; max 120 s additionally limited by original collection/window deadlines.
- Durable whole-budget `execution-reservation.v1` precedes destination I/O. Uncertain allowance is `reserved_unknown`, not measured sent traffic; no second grant or refund. Fresh positive results require exact worker/reservation/lease.
- Current ownership, active exact target/group/run and signed kind/value/port/protocol are rechecked at execution grant. Lost/ambiguous grant is not retried as traffic.
- Reporter control-plane failure/hung sender revokes execution after bounded grace; transports obey deadline/abort. Stop requested, authenticated worker ACK, unreachable and deadline elapsed remain separate. Database cancellation is not packet-stop proof.
- Admission uses complete tenant-scoped SQL, transaction locks and target/policy/kill/window rechecks, never capped presentation lists. Missing complete usage is audited 503, not assumed zero.
- Local fixtures cover >100 history rows, last hourly-slot race, hidden cooldown, grant mutation/revocation/expiry/kill, reporter loss and >500 audit/>200 event pagination. Real fleet stop and distributed operational timing remain external acceptance.

## Recovered local session work (2026-10-08)

Destination is restored audit session `4aca7b73-e4dd-4a78-a235-048c13029d0f`. Local metadata does **not** establish which session closed today; completed Codex turns are not session-closure evidence. Historical transcript content is evidence of prior requests, not new deployment/safety authorization.

| Recovery ID | Source / verified unfinished item | Current task disposition |
|---|---|---|
| REC-01 | Claude `1ef1472c-527d-42e4-b673-ba2e76fcfbaa`, Oct 5–6, PV-06: PG high/critical protection findings not queued | Include in G43: atomic opted-in durable outbox, dedupe and asynchronous existing recovery worker; local tests only. |
| REC-02 | Same session/PV-06: report `ignored_for_findings` absent in React | Include in G46: expose exclusion reasons and unknown/not-tested coverage without inventing findings/pass. |
| REC-03 | Same session/PV-08: portal configuration explanation missing | Existing permission-gated explanation-only matrix data may be rendered; **no new integration**; no runtime-protection credit. |
| REC-04 | Same rollout: declared denial producer and standalone host/SNI permitted baseline absent | G08 unsupported/assessment boundary; current one-request scope cannot confirm lockdown. No unsigned authority or extra unreviewed I/O. |
| REC-05 | Same final response: disappearing form-submit errors outside reports | Reproduce current target/settings forms; include confirmed persistent-alert/draft-preservation repairs only. Integration/report pages already have alerts. |
| REC-06 | Same and Codex `01a1037d-7f31-7073-ac7a-7dcfd5958264`, Oct 3–4 | Human visual/usability approval, owned appliance/custom endpoints, nonce identity, live IPv6/port/TLS reruns and hosted PG lifecycle stay external acceptance. |
| REC-07 | VibeRouter `782701be-d8f1-4621-b607-ba5b05656e77`, Oct 1, RUX-015 | Existing Edit/security/delivery regressions included. New test-send endpoint/webhook HMAC product addition and live drills are assessment, not silently authorized expansion. |

Principal provenance: local Claude project transcript `1ef1472c-527d-42e4-b673-ba2e76fcfbaa.jsonl`; `PROGRESS.md` PV-06/PV-08/RUX-015/CR-028; `docs/backend/protection-validation-rollout.md`; `docs/implementation/provider-neutral-protection-validation-review.md`; `docs/implementation/current-release/review-ledger.md`; `docs/detection/edge-port-fidelity-audit-2026-10-08.md`.

Do not reopen completed notification R01–R04 (`ec144753`), direct-domain UI, port fidelity, reviewed subdomain import, initial detection queue, independent target runs, earlier PG comparison persistence or already repaired recurrence/CSV/lock-pool issues. Preserve “just merge dont deploy” from the earlier fidelity session. GuardianBot/microphone/terminal work is unrelated. Demo safety-gate removal is never carried forward.

## Missing and optional capabilities

| Candidate | Recommendation / evidence boundary |
|---|---|
| Coverage-aware reviewed suggestions | Useful follow-on using existing catalog, applicability and current gaps; deterministic first, no automatic dispatch or increased budgets. |
| Safe benign endpoint journeys | Additional explicitly approved read-only fixtures/paths; no credentials, login/OTP/email/payment side effects or arbitrary POST. |
| Existing-vantage repeatability | Compare only same-scenario current signed source/address-family evidence; new fleet locations need operational authorization. |
| Mitigation onset/recovery | Report actually observed intervals only; provider activation/inner resource recovery stays unavailable. |
| Customer denial declarations / host-SNI baseline | Future signed versioned scope/producer + independently permitted baseline and reviewed budget required; current standalone result cannot prove origin lockdown. |
| Routing posture (G47) | Separate timestamped public BGP/RPKI/IRR evidence product; not inferred from cloud/ASN labels. |
| Passive candidates (G48) | Optional reviewed hostname suggestions only; no mandatory discovery, promotion to ownership or silent probing. |
| AI suggestions (G49) | Evidence-cited allowlisted reviewed templates after deterministic selection; never free-form traffic or SOC bypass. |
| Origin receipt/leakage/internal resource/cost/capacity | Not honestly obtainable from external responses; integrations/governed execution explicitly excluded. |

## Final local engineering acceptance (2026-10-09)

All applicable local engineering gates passed against the final frozen sources. This closes the implemented current-platform defect repairs, not deployment or missing/unsupported evidence producers. G08 remains partly implemented because the standalone permitted baseline, signed customer denial declaration and scanner-origin authority producers are not implemented; its existing false-assurance paths are hardened and tested. Four external-acceptance, fourteen excluded and eight assessment-only audit areas remain explicitly separate. Existing high-scale SOC authorization is preserved.

| Gate | Verified final result | Log |
|---|---|---|
| npm test | 4950 unit/e2e/provenance + 476 integration; zero failures/skips | /tmp/astranull-audit-final-npm8.log |
| make verify | 4922 unit + 477/478 integration + 21 first-slice e2e + 11 corpus; one intentionally disabled public-DNS test, zero failures | /tmp/astranull-audit-final-make5.log |
| Contract | 16/16; no skips | /tmp/astranull-audit-final-contract4.log |
| Full scaled browser | 418/418; no failures/skips/unrun | /tmp/astranull-audit-final-browser3.log |
| Separate accessibility | 50/50; no failures/skips | /tmp/astranull-audit-final-a11y3.log |
| Active dev/PostgreSQL scale | 14/14; no skips or increased budgets | /tmp/astranull-audit-final-scale4.log |
| Type/build/lint/catalog | passed; generated served bundle rebuilt | /tmp/astranull-audit-final-{type4,build3,portal-lint5,vector4,library4}.log |

Actual log totals were checked independently of wrapper exit codes. The preceding 417-pass/one-failure browser attempt remains recorded below; its no-verdict fixture incorrectly shared a target with newer genuinely signed passing runs. The final regression isolates a declared target, proves absent verdict/event/vault evidence, and asserts Not recorded/no Passed/no Earlier run. No product proof gate or no-false-pass assertion was weakened.

Late assurance regressions cover contradictory/missing actual positive outcomes, wrong nonce, absent immutable ingestion, changed policy/group definitions, unmatched actual scenario/expectation and unavailable actual firewall pre/post comparisons. Their current credit fails closed without modifying retained status, digests or custody. Dedicated accepted Origin/Firewall/Path starts preserve exact submitted execution identity, with explicit errors for missing/mismatched IDs and no newest-run substitution.

All 1218 final recorded source/test/config/bundle hashes matched after acceptance (/tmp/astranull-audit-final-source-snapshot3-20261009.json). Changes remain local, uncommitted and undeployed. Public/customer probes, hosted verification, live provider sends, production migrations and human sign-off were not performed. Tests demonstrate these local contracts and reduce regression risk; they do not certify every vendor, full capacity, packet completeness or mathematical flawlessness.

## Verification record

This is the chronological implementation record. Intermediate “pending” and failure notes below describe their then-current state; the final acceptance section above records the completed local gates. Original failures are retained rather than replaced by later passing summaries.

- Pre-change local baseline: 4,784 unit/e2e/provenance + 471 integration = 5,255 passed; this is **not** acceptance of current edits.
- Current focused signed lifecycle and admission cases, connected local browser fixtures and assurance/protocol suites are recorded during implementation. A partial successful run never substitutes for final release gates.
- Required final gates: `npm test`, `make verify`, contract schemas, active local scale fixture, scaled full portal browser + a11y, typecheck, build, portal lint, safety/schema/tenant-query/taxonomy/generated catalog/check-library/corpus checks.
- Opt-in public live DNS, customer/public endpoints, hosted/production verification, live provider sends and human approval remain unrun. The active local PostgreSQL scale lane is exercised below; any future disabled/skip-only invocation is not a pass.
- Current release checks passed: lint, safety, schema, tenant-query audit (zero findings), resource taxonomy, generated check library and edge corpus (`/tmp/astranull-final-{lint,safety,schema,tenant-query,taxonomy,check-library,corpus}.log`).
- Active scale: 14/14 passed, no skips (`/tmp/astranull-final-scale2.log`); dev state p95 9.21 ms/200 ms, PostgreSQL state 122.56 ms/200 ms, group 12.61 ms/180 ms, target detail 21.87 ms/250 ms. Budgets were not relaxed and internal accounting was not capped.
- Protocol/catalog slice: 562/562 unit cases and 4/4 strictly loopback protocol integration cases passed; no skips (`/tmp/astranull-owned-comprehensive-frozen.log`, `/tmp/astranull-reflector-loopback-final.log`). Catalog remains 251 definitions/721 mappings/161 safe IDs, not independent mechanisms.
- Current whole local integration lane: 475/475 passed, no skips (`/tmp/astranull-final-integration2.log`). Later exact-proof/report changes still require final whole-gate reruns; this does not close the remediation alone.
- Contract 16/16 and generator 5/5 passed; typecheck, portal lint and deterministic vector/check-library checks passed in the same explicit-failure command (`/tmp/astranull-final-contract2.log`, `/tmp/astranull-final-generator3.log` and sibling check logs).
- Whole regression before the final report/dedicated-start repair: `ASTRANULL_RUN_PUBLIC_DNS=0 npm test` passed 4,938 unit/e2e/provenance + 475 integration, zero failures/skips (`/tmp/astranull-final-npm-test5.log`). `ASTRANULL_RUN_PUBLIC_DNS=0 make verify` passed 4,910 unit + 476/477 integration (one deliberately disabled public-DNS test) + 21 first-slice e2e + 11 corpus cases and its static checks (`/tmp/astranull-final-make-verify2.log`); both commands exited 0. These passes do not close later edits or browser/a11y acceptance.
- Additional final review repairs: current report policy/group and performed-outcome binding, shared readiness/profile rejection of contradictory marker outcomes and invalid nonce/ingestion, and exact dedicated Origin/Firewall/Path Inspector handoffs are implemented. Matched score proof remains eligible; contradictory/wrong-nonce/missing-ingestion cases now return zero credit with custody unchanged. Focused assurance 199/199 and reviewed-start browser 11/11 + UI unit 180/180 passed (`/tmp/astranull-assurance-binding-final.log`, `/tmp/astranull-exact-reviewed-starts-final{,-unit}.log`).
- Independent WAF posture retained-positive/actual-`not_enforced` credit gap is repaired: every actual signed leg must match positive enforcement and have immutable ingestion availability. Historical status/custody remain unchanged; 112/112 focused tests passed including live PostgreSQL/API/coverage/risk (`/tmp/astranull-posture-outcome-binding-final.log`). The dashboard browser failure is a stale shared fixture: its alleged no-verdict target now has newer genuinely backed runs. Its regression uses an independent declared target and bare-pass completed run with explicitly absent verdict/event/vault proof; the no-false-pass requirement was strengthened, not weakened. Fresh final broad/browser verification is pending.
- Frozen-source final broad gates: `npm test` 4,945 unit/e2e/provenance + 476 integration passed, zero failures/skips (`/tmp/astranull-audit-final-npm6.log`); `make verify` 4,917 unit + 477/478 integration (one deliberately disabled public-DNS test) + 21 first-slice e2e + 11 corpus passed (`/tmp/astranull-audit-final-make3.log`); contract 16/16, types/build/lint/catalog checks passed.
- Final browser attempt: 417 passed, **one failed** (dashboard completed/no-verdict case), no acceptance despite the wrapper returning exit 0 (`/tmp/astranull-audit-final-browser2.log`). Separate accessibility 50/50 passed; active dev/PostgreSQL scale 14/14 passed without skips or relaxed budgets (`/tmp/astranull-audit-final-a11y2.log`, `/tmp/astranull-audit-final-scale3.log`). Browser failure is assigned for diagnosis and a fresh full rerun.
- All 1,218 recorded source/test/config/bundle hashes were unchanged during these final runs (`/tmp/astranull-audit-final-source-snapshot-20261009.json`). Later repairs must be reverified.
- Latest post-fix whole npm regression passed 4,950 unit/e2e/provenance + 476 integration with no failures/skips (`/tmp/astranull-audit-final-npm7.log`). The following `make verify` passed 4,922 unit cases but failed integration: 474 passed, three failed, one intentional public-DNS skip (`/tmp/astranull-audit-final-make4.log`). Privacy defaults and rate-limit tests received 404 instead of 200; these failures block local closure and are under diagnosis. Contract 16/16, typecheck, portal lint and catalog generation checks separately passed. Full scaled browser attempt 3 remains running; no outcome inferred.
- Make integration follow-up is test-only: privacy server shutdown is awaited with explicit memory/dev-header configuration; each rate-limit scenario has an independent budget/server and uses canonical `/v1/targets`. Exact privacy defaults/PATCH/reload, 200/200/429 + Retry-After and unaffected health/body-limit assertions remain enforced, with diagnostic response bodies and no retries. Focused 9/9 passed; the original intermittent 404 was not reproduced in 30 pre-change invocations (270/270 cases), so cleanup is not claimed as a proven root cause. A fresh whole make/npm run is required before closure. Only `tests/integration/misc-portal-endpoints.test.mjs` and `tests/integration/operability.test.mjs` changed after snapshot2; all other recorded source hashes remain unchanged.
- Fresh npm acceptance after the isolated privacy/operability test changes: 4,950 unit/e2e/provenance + 476 integration passed, no failures/cancellations/skips (`/tmp/astranull-audit-final-npm8.log`). Actual summaries were independently checked. This does not substitute for still-pending final make/browser/a11y/scale outcomes.
- Fresh full make acceptance after the isolated test lifecycle changes passed: 4,922 unit + 477/478 integration + 21 first-slice e2e + 11 corpus cases (`/tmp/astranull-audit-final-make5.log`), with zero failures/cancellations and only the intentionally disabled public-DNS skip. Lint/safety/schema, tenant-query audit (zero findings), taxonomy and generated catalog checks passed. Failed make4 remains recorded; focused 9/9 and 30 post-change independent invocations (270/270) also passed, but the original intermittent 404 root cause is unproven. Browser/a11y/scale chain still determines remaining local acceptance.
- Final counts/logs are recorded in Final local engineering acceptance above. Earlier failures and intermediate passes below are historical verification steps, not a remaining engineering gate. No mathematical zero-regression/flawlessness promise.

## Audit shared-engine exceptions

Each entry below preserves the audit's distinct allegation/correction and acceptance boundary. It is **historical review data**, not a claim that the changing tree still contains that defect. Current per-check execution/support is indexed in the companion catalog appendix; full final gates control local completion. No unsupported mechanism is implemented as a reusable attack recipe.

### SOC

- Supported observation: Authorization, approvals, scheduling, evidence metadata and closure workflow exist.
- Gap: A scenario, approved request or running state is not proof a certified adapter emitted traffic or observed mitigation. Live adapter/telemetry acceptance remains open.
- Correction: Integrate an approved provider adapter; bind execution receipts and telemetry to scope/version, enforce stop acknowledgment, and keep unavailable execution explicit.
- Acceptance: A controlled approved exercise yields provider attestation, time-aligned metrics, stop receipt and evidence-backed stopped report.
- Historical source snapshot: src/contracts/governedScenarios.mjs; src/services/highScale.mjs; src/contracts/wafOffensive.mjsAWSPOLICY AZPOLICY
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### alert_webhook_ping

- Supported observation: A bounded webhook POST observes delivery response and timing.
- Gap: HTTP acceptance is not incident detection, paging, on-call acknowledgment or external ticket completion.
- Correction: Keep E2, correlate delivery receipts and separately run approved incident-response drills.
- Acceptance: A webhook 2xx with no downstream page stays delivery-only.
- Historical source snapshot: src/lib/safeNetworkProbes.mjsHTTP REDBUTTON
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### api_surface_scan

- Supported observation: HEAD checks curated documentation paths.
- Gap: 2xx/3xx can be a soft-404 SPA or login redirect rather than actual API docs; public docs are not inherently insecure.
- Correction: Use bounded content/schema and negative-path confirmation where authorized; separate discovery from exposure policy and vulnerability.
- Acceptance: Identical SPA responses to all paths are not multiple exposed API documents; no content evidence remains unknown.
- Historical source snapshot: src/lib/capabilityProbes.mjs:probeApiSurfaceScanHTTP
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### bot_challenge_probe

- Supported observation: A scripted HEAD captures status and selected challenge headers.
- Gap: 401/authentication, 302/normal redirect and arbitrary 403/429 are counted as challenges. A 200 challenge header is not consistently reflected in the result. Absence of challenge is not inherently a defect.
- Correction: Interpret documented challenge signals and explicit bot-policy intent, compare healthy browser/API traffic, keep authentication separate.
- Acceptance: Login redirect is not bot mitigation; Cloudflare challenge header is recognized across statuses; intentionally public clients are not false positives.
- Historical source snapshot: src/lib/capabilityProbes.mjs:probeBotChallengeHTTP CFCHALLENGE
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### cache_abuse_probe

- Supported observation: Three HEAD requests observe cache-control and cache-status labels.
- Gap: public is not evidence of sensitive content; identical cache labels can be correct behavior. No cache-key isolation, poisoning or origin-work cost is proven.
- Correction: Require declared sensitivity and controlled representations; test only an isolated approved cache fixture with identity-bound content comparison; otherwise report headers only.
- Acceptance: Public static HIT/HIT/HIT passes no vulnerability judgment; intentionally ignored query keys are not false positives; wrong-content cross-user cases need actual evidence.
- Historical source snapshot: src/lib/capabilityProbes.mjs:probeCacheAbuseCACHE
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### cors_posture_probe

- Supported observation: OPTIONS observes Access-Control-Allow-Origin.
- Gap: Wildcard/reflection alone does not establish sensitive cross-origin data access, and CORS is not a DDoS mitigation primitive.
- Correction: Move to web posture; combine resource sensitivity, authentication/credentials, browser semantics, and declared intended origins.
- Acceptance: Public unauthenticated API wildcard is not a vulnerability; credentialed sensitive access is assessed with actual browser rules.
- Historical source snapshot: src/lib/capabilityProbes.mjs:probeCorsPostureCORS
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### dns_axfr_leak

- Supported observation: A bounded AXFR exchange checks transfer framing against a selected nameserver.
- Gap: The no_nameservers branch returns blocked; absence of a test is not a refusal. Only one selected NS is not whole-zone coverage.
- Correction: Return not_tested/unknown for failed discovery, record per-NS authorization and coverage, and require matching SOA-framed evidence for transfer exposure.
- Acceptance: No NS, unreachable NS and explicit refusal are separate; a partial transfer is not invented as a complete leak.
- Historical source snapshot: src/lib/capabilityProbes.mjs:probeAxfrLeakRECURSION
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### dns_failover_posture

- Supported observation: Counts NS names and limited address lookups.
- Gap: Two names can share infrastructure; name count is not failover health. Exact-host secondary restrictions can prevent legitimate nameserver lookup and leave coverage incomplete.
- Correction: Report NS count only; independently authorize and check authoritative responses, address-family diversity and failure-domain metadata; use an approved failover exercise for a failover claim.
- Acceptance: Two dead or same-failure-domain servers do not pass availability; external nameservers are explicitly scoped or untested.
- Historical source snapshot: src/lib/capabilityProbes.mjs:probeDnsFailoverPostureRECURSION REDBUTTON
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### dns_open_recursion

- Supported observation: The target DNS server is asked to resolve its own name.
- Gap: A correct authoritative answer can be mislabeled open recursion; it does not establish recursion for arbitrary unrelated names.
- Correction: Use a separately authorized controlled external-zone fixture, distinguish RD/RA/AA and cached/authoritative answers, and corroborate controlled authoritative receipt.
- Acceptance: Authoritative-only service never fails as open recursive; a restricted resolver and an intentionally public resolver remain distinct.
- Historical source snapshot: src/lib/capabilityProbes.mjs:probeOpenRecursionRECURSION
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### dns_wire_query

- Supported observation: Bounded DNS transaction/peer/rcode/size metadata is collected.
- Gap: NXNS, garbage flood, multi-question, TCP fallback and amplification names exceed a single ordinary query or a TCP-only transaction.
- Correction: Describe exact qtype and transport; use separate paired fallback or protocol-specific experiments for stronger claims.
- Acceptance: Returned query/response transcript metadata shows actual tested mechanism; no capacity or resolver-chain pass from one response.
- Historical source snapshot: src/lib/dnsWireQuery.mjsRECURSION DNSSEC
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### dnssec_posture

- Supported observation: An authoritative DNSKEY query observes whether keys are present.
- Gap: DNSKEY presence is mapped to protected despite no DS/RRSIG trust-chain validation and no expensive-query or DDoS test.
- Correction: Rename DNSKEY observation; separately validate delegation, signatures, times, algorithm support and rollover context. No capacity score from DNSSEC.
- Acceptance: An orphan DNSKEY with missing/wrong parent DS does not pass DNSSEC validation or DDoS readiness.
- Historical source snapshot: src/lib/capabilityProbes.mjs:probeDnssecPostureDNSSEC
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### graphql_posture_probe

- Supported observation: One HEAD at /graphql observes reachability and two optional header names.
- Gap: Missing nonstandard complexity/rate headers is treated as weak control; non-2xx including 405 or 500 can be called blocked. No depth or batch query is executed.
- Correction: Downgrade to endpoint observation; implement authorized low-cost query fixtures and configuration/telemetry evidence for actual depth/batch/cost controls.
- Acceptance: Hidden working controls are not failures, HEAD-405 and service-500 are not protection, and batch/depth coverage is recorded separately.
- Historical source snapshot: src/lib/capabilityProbes.mjs:probeGraphqlPostureGRAPHQL HTTP
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### grpc_reflection_probe

- Supported observation: A bounded TLS/HTTP2 gRPC request collects status/trailers and message metadata.
- Gap: A health request is not reflection discovery; unsupported/unavailable/internal errors are not security denials. No stream flood or capacity measurement.
- Correction: Bind to an actual approved method, distinguish gRPC error categories, and require a well-formed reflection response for reflection exposure.
- Acceptance: UNIMPLEMENTED/UNAVAILABLE never become protection; healthy non-reflection service is not exposed reflection.
- Historical source snapshot: src/lib/capabilityProbes.mjs:probeGrpcReflectionGRPC
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### header_size_probe

- Supported observation: A clean baseline plus a bounded larger header may show size-sensitive rejection.
- Gap: A generic 400/413/414/431 is not attribution to a particular parser/WAF limit; header size is not request-body inspection coverage.
- Correction: Use a healthy comparable baseline, actual transmitted byte count, repeated controlled boundaries and control-specific evidence; keep unqualified rejection as observation.
- Acceptance: Generic application 400, auth failure or URI-only error does not become exact header-limit enforcement.
- Historical source snapshot: src/lib/capabilityProbes.mjsHTTP AWSSIZE
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### host_sni_bypass

- Supported observation: Authorized direct-path response, nonce identity and same-scenario comparison can establish a scoped bypass.
- Gap: One direct request does not create its own clean permitted baseline. Required lockdown/nonce fields and fresh primary comparison must actually be produced. Shared-edge IP responses are not necessarily the origin.
- Correction: Complete evidence production and baseline binding; preserve unknown on ambiguity; validate source/address family/port/SNI/path and deny signature independently.
- Acceptance: Confirmed bypass requires healthy enforcing primary, same scenario allowed on alternate and bound application identity; vendor denial or timeout alone never proves lockdown.
- Historical source snapshot: src/lib/capabilityProbes.mjs; src/lib/entryPathComparison.mjsHTTP SITESHIELD
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### http2_frame_probe

- Supported observation: Reads SETTINGS and possibly performs a bounded ping/single reset.
- Gap: Positive maxConcurrentStreams is treated as mitigation; advertised header limits similarly imply protection. These are not Rapid Reset, MadeYouReset, CONTINUATION or HPACK resilience tests.
- Correction: Downgrade to E2 advertised facts. Add product/version mitigation evidence and authorized protocol-specific validation with resource metrics, never an unbounded reset generator.
- Acceptance: Vulnerable and patched fixtures with identical SETTINGS are not declared equivalently protected; each mechanism has a separate evidence contract.
- Historical source snapshot: src/lib/capabilityProbes.mjs:probeHttp2FrameBehaviorH2RESET MADE
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### http2_settings

- Supported observation: A bounded HTTP/2 handshake reads peer SETTINGS.
- Gap: Settings are not evidence of Rapid Reset or stream-creation-rate mitigation.
- Correction: Keep E2 and rename readiness labels to advertised limits. Use vendor patch/config evidence and separately approved tests.
- Acceptance: A vulnerable and patched endpoint with identical SETTINGS both remain unvalidated for reset resilience.
- Historical source snapshot: src/lib/safeNetworkProbes.mjsH2RESET MADE
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### http3_control_probe

- Supported observation: Delegates the Alt-Svc observation helper.
- Gap: No HTTP/3 control stream, SETTINGS, QPACK or real protocol translation is exercised.
- Correction: Rename or retain unimplemented control-stream coverage until an actual supported protocol adapter exists.
- Acceptance: Wire/protocol attestation distinguishes HTTPS advertisement from negotiated QUIC/HTTP3.
- Historical source snapshot: src/lib/capabilityProbes.mjsHTTP
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### http_head

- Supported observation: A bounded HEAD observes status/timing and allowed response metadata.
- Gap: HEAD does not execute a full business transaction or measure expensive-endpoint, password-reset or XML-RPC resource cost; canary receipt needs identity proof.
- Correction: Rename by actual operation; bind declared path and add optional business-approved synthetic transactions plus backend telemetry.
- Acceptance: HEAD-only observations cannot close application-cost, authentication or canary-identity findings.
- Historical source snapshot: workers/probe-worker.mjsHTTP
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### http_method_matrix

- Supported observation: HEAD/OPTIONS observes advertised methods.
- Gap: Allow header does not prove that a method is accepted or rejected; public methods are not inherently DDoS gaps.
- Correction: Keep advertised-method posture, evaluate declared endpoint intent, and separate approved method validation from method listing.
- Acceptance: Missing/forged Allow and ordinary OPTIONS responses do not imply enforced restrictions.
- Historical source snapshot: src/lib/capabilityProbes.mjsHTTP
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### l7_resource_posture_probe

- Supported observation: Sends small requests with encoding or size descriptors and observes response codes.
- Gap: Declared 50-MiB/64-KiB size headers are not actual sizes; an invalid encoding can produce a normal 415/400. This does not measure decompression or parser resource limits.
- Correction: Relabel descriptor/rejection observations or use strictly bounded valid fixtures with measured encoded/decoded sizes in an isolated authorized target.
- Acceptance: Actual payload size/encoding is attested; unsupported encoding is not treated as decompression protection; no resource-capacity claim.
- Historical source snapshot: src/lib/vectorProbes/l7ResourceProbes.mjs; src/lib/capabilityProbes.mjsHTTP AWSSIZE
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### metadata_marker

- Supported observation: Zero customer-network operations; explicit not_run is the correct result.
- Gap: Names include flood, capacity and readiness mechanisms that are not implemented by this engine. Mapping labels must not imply executable validation.
- Correction: Keep as declared intent/planned coverage; remove from runnable/implemented-security counts. Add an executable mechanism only with a new evidence contract.
- Acceptance: Every one of these entries remains not_run, receives no readiness credit, and cannot close a finding or CVE.
- Historical source snapshot: workers/probe-worker.mjs; src/lib/probeEvidenceTiers.mjsAWSPOLICY
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### ops_readiness

- Supported observation: Checks accepted contact/runbook or retained kill-switch evidence without target traffic.
- Gap: The names imply a live drill although no human is contacted and no worker-stop exercise is performed.
- Correction: Rename record-completeness checks. Separate measured stop latency and real acknowledgment into explicit approved drills.
- Acceptance: Missing/stale records are unknown; a stored enabled flag cannot mark a fleet-stop drill successful.
- Historical source snapshot: src/lib/opsReadinessValidation.mjsREDBUTTON
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### origin_leak_scan

- Supported observation: Finds bounded DNS divergence and corroborated origin hints among declared names.
- Gap: Different addresses are not proof of the same application or bypass; fixed prefixes are not exhaustive discovery.
- Correction: Retain candidates, explicitly authorize origins, perform identity-bound same-scenario comparisons, and report enumeration coverage.
- Acceptance: Unrelated API host, CDN addresses and IPv6-only answers do not automatically become confirmed origin bypass.
- Historical source snapshot: src/lib/capabilityProbes.mjsSITESHIELD
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### port_scan_bounded

- Supported observation: Up to 15 sequential TCP connections establish observed open ports.
- Gap: 80/443-only is not universally safe and an extra service port is not universally misconfigured; timeouts and untested ports are not denial proof.
- Correction: Apply explicit service intent and exposure authorization; report per-port completion and actual address family.
- Acceptance: Public mail/DNS/administration intent and forbidden web exposure produce context-correct findings.
- Historical source snapshot: src/lib/capabilityProbes.mjsHTTP
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### quic_reachability

- Supported observation: The selected one-operation profile reads HTTPS Alt-Svc.
- Gap: It does not actually establish a QUIC handshake, UDP/443 reachability or QUIC reflection.
- Correction: Rename Alt-Svc advertisement; add a separate explicitly budgeted and authorized QUIC handshake with observed negotiation.
- Acceptance: Alt-Svc with UDP blocked remains advertisement-only; no H3/QPACK/reflection pass.
- Historical source snapshot: src/lib/safeNetworkProbes.mjsHTTP
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### rate_limit_sequence

- Supported observation: At most five requests record responses for a declared test scenario.
- Gap: Any 403 or 503 is counted as throttling and blocked. This can turn an outage into protection; no measured threshold/window/key, recovery or legitimate-user safety. Some profiles pin / instead of the intended business path.
- Correction: Remove status-only enforcement verdicts. Add healthy baseline, actual endpoint/method/key attestation, provider action/rule evidence and distinct error/unknown; use explicitly approved canary calibration for thresholds.
- Acceptance: 503 outage, generic 403 and a preexisting challenge never pass rate control. Five allowed requests do not prove no limit; known controlled threshold tests respect provider timing.
- Historical source snapshot: src/lib/capabilityProbes.mjs:probeRateLimitSequenceHTTP RATE AWSRATE
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### reflection_service_probe

- Supported observation: One declared-endpoint request observes a peer-matched response and its byte ratio, without source spoofing.
- Gap: Broad compound protocol names overstate the single selected payload. The visible wrapper classifies payload/response size, not a demonstrated complete per-protocol exchange; payload-helper internals are not all embedded. No measured reflector capacity.
- Correction: Validate each protocol response/transaction, narrow compound names, review protocol-specific side effects, and preserve bounded no-spoof/no-third-party safeguards.
- Acceptance: For each selected service, malformed/unrelated replies do not establish protocol identity; request/response counters and limits are correct; no reply is not mitigation.
- Historical source snapshot: src/lib/safeNetworkProbes.mjsRECURSION AWSPOLICY
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### slow_header_probe

- Supported observation: A single incomplete-header connection observes whether closure occurs within the signed deadline.
- Gap: A five-second observation does not establish a longer server timeout or resistance to slow-read, slow-body or concurrent connection exhaustion.
- Correction: Report timeout bound/censoring explicitly; separate header/body/read mechanisms and never label a long-but-bounded timeout as no protection.
- Acceptance: Server close, client deadline, transport failure and unobserved full timeout remain separate; one socket never certifies capacity.
- Historical source snapshot: src/lib/capabilityProbes.mjsHTTP
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### tcp_connect

- Supported observation: A completed connection establishes transport reachability for the actual selected address and port.
- Gap: No firewall attribution, anomalous flags, flood resistance or reflection validation; refusal/silence do not establish which control acted.
- Correction: Rename to transport observation; retain per-address/protocol/source/time evidence and do not convert closed/silent to protected.
- Acceptance: Open, RST, timeout, TLS-only and wrong-address cases have distinct results; requested IPv6 is actually used.
- Historical source snapshot: workers/probe-worker.mjs; src/lib/externalObservationOutcomes.mjsHTTP
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### tls_audit

- Supported observation: One TLS handshake observes negotiated protocol, cipher and certificate authorization/expiry.
- Gap: Same profile backs full-audit and OCSP-stapling names, but no explicit OCSP response validation or complete version/cipher scan exists. Port 443 is hardcoded in the audited routine. TLS health is not WAF/DDoS protection.
- Correction: Rename basic TLS observation; honor signed port/SNI; separate negotiated facts from exhaustive support tests and stapling validation.
- Acceptance: Service on non-443 is tested only at the signed port; absent stapling is not inferred without requesting it; one modern negotiation does not rule out weak versions.
- Historical source snapshot: src/lib/capabilityProbes.mjs:probeTlsAuditTLS
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### tls_session

- Supported observation: One TLS session yields negotiated protocol/cipher/certificate metadata.
- Gap: No idle hold/timeout exercise and no renegotiation exercise in the named checks.
- Correction: Relabel ordinary TLS observations; separate actual idle/resumption/renegotiation behavior where safe and applicable.
- Acceptance: Normal handshake cannot certify timeout or renegotiation controls.
- Historical source snapshot: src/lib/safeNetworkProbes.mjsTLS
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### udp_probe

- Supported observation: A peer-matched UDP response is a reachability observation; no reply is ambiguous.
- Gap: One datagram cannot prove a deny rule, mitigation or amplification capacity; a TCP target-type label for a UDP profile needs compatibility review.
- Correction: Preserve unknown on silence, validate protocol/target schema and authorization, correlate explicit firewall evidence separately.
- Acceptance: Spoofed/unexpected-source replies rejected; loss and healthy silent services never pass denial.
- Historical source snapshot: src/lib/safeNetworkProbes.mjsRECURSION
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### waf_class_marker_probe

- Supported observation: Compares bounded inert class markers with a permitted baseline, where the transport supports them.
- Gap: Any blocked leg can produce protected while another is inconclusive. Delegated response bodies are canceled before body-only signature use; login/API HEAD variants conflict with GET/POST-only transport. Markers do not execute the named exploit classes.
- Correction: Unify evidence aggregation; preserve partial/unknown; consume bounded body before cancellation with redaction; align methods; require explicit harmless-marker contract and safe app fixture.
- Acceptance: Mixed blocked+timeout stays partial; body-only denial is recognized safely; permitted login/API variants execute or explicitly remain unsupported; no exploit/CVE claim from a token.
- Historical source snapshot: src/lib/capabilityProbes.mjs; src/lib/vectorProbes/wafClassProbes.mjsHTTP JNDI
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### waf_enforcement_probe

- Supported observation: One inert-marker GET can observe a specific denial signature.
- Gap: No healthy permitted baseline; a generic/custom-marker response proves neither a whole exploit class nor DDoS effectiveness. Single-operation cap cannot include an independent baseline.
- Correction: Add/require a fresh comparable clean baseline and customer-approved marker expectation; distinguish denial signatures from cryptographic authenticity and correlate rule telemetry when available.
- Acceptance: All-traffic block, login wall and static block-page content cannot pass marker-specific enforcement; one allowed harmless marker is not a demonstrated exploit.
- Historical source snapshot: src/lib/capabilityProbes.mjs:probeWafEnforcement; src/lib/outsideInWafScanner.mjsHTTP WAFW00F
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### waf_evasion_marker_probe

- Supported observation: Clean baseline, blocked plain marker, then a query-string transformed marker is a useful conditional normalization experiment.
- Gap: Most delivery descriptors are not sent; value is query-only, limited to 512 characters, and POST becomes GET. Gzip is a base64 marker, not a compressed body. Some transforms are identical to the plain marker.
- Correction: Separate actual text normalization from unimplemented body/header/framing/protocol delivery. Disable unsupported claims; require transformation semantic equivalence and wire-level test fixtures, without exposing dangerous free-form traffic.
- Acceptance: Every selected transformation has attested actual location/method/protocol/encoding; unsupported descriptors return not_implemented, not protected.
- Historical source snapshot: src/lib/vectorProbes/evasionProbes.mjs; src/lib/capabilityProbes.mjs:probeWafEvasionMarkerHTTP AWSSIZE
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### waf_fingerprint_observation

- Supported observation: One normal GET plus bounded DNS/CNAME evidence identifies candidate WAF/CDN/cloud layers; E2 exclusion is appropriate.
- Gap: 172 matcher trees do not mean 172 vendors detectable passively. Confidence numbers are uncalibrated; hidden WAFs and conflicting fingerprints remain possible.
- Correction: Keep provider detection distinct from enforcement. Calibrate on labeled positive/negative/stacked fixtures; record corpus revision, source age and unobserved branches.
- Acceptance: Negative DNS/headers never imply no WAF; attack-only branches remain unknown; known corpus fixtures preserve provider/family conflicts.
- Historical source snapshot: src/lib/edgeFingerprint.mjs; src/lib/edgeDetectionProjection.mjsWAFW00F CDNCHECK
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### waf_inspection_limit_probe

- Supported observation: Compares a marker baseline with bounded padded/body/form/JSON variants.
- Gap: The baseline contains the marker, not a separate clean allowed request; HEAD cannot return a body-only signature. Fixed sizes are not every provider/resource inspection boundary.
- Correction: Add clean baseline and canonical blocked marker; use actual transmitted dimensions and provider-specific configured limits/oversize action; keep ungraded variants unknown.
- Acceptance: An always-denying endpoint does not pass; transport cap refusal is not a WAF block; before/after actual configured boundary evidence is retained.
- Historical source snapshot: src/lib/capabilityProbes.mjs:probeWafInspectionLimitHTTP AWSSIZE
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.

### websocket_upgrade_posture

- Supported observation: One bounded upgrade response is observed.
- Gap: Handshake metadata is not stream/message-rate or connection-capacity evidence.
- Correction: Keep handshake-only classification and include verified protocol-upgrade outcome.
- Acceptance: 101, auth denial, proxy rejection and timeout are distinct; no capacity claim.
- Historical source snapshot: src/lib/safeNetworkProbes.mjsHTTP
- Disposition: existing bounded observation truth/evidence repairs only; unsupported protocol/body/flood/callback/business mechanisms remain explicit not-tested. SOC workflow expansion excluded. Sources/regressions: current catalog appendix and G01–G54 area anchors above.
