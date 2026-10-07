# Plan

Implement provider-neutral, outside-in validation of WAF coverage, declared application entry paths, and firewall behavior before and after a change. Reuse AstraNull's targets, target groups, origin bindings, signed bounded probes, evidence history, and findings so the same workflow works across commercial, cloud-native, appliance, reverse-proxy, and unknown/custom providers without requiring credentials.

Date: 2026-10-06. Status: proposed implementation plan; no application changes are implemented by this document. Provider names are optional evidence labels, never prerequisites for validation. "Firewall change" includes migrations between any products; FTNT and NCFW are not special execution modes.

## Scope

- **In:** evidence correctness; explicit application-to-entry-path relationships; per-path WAF enforcement and bypass comparisons; declared TCP/UDP/service expectations; pre/post firewall behavior comparison; target-centered UI; findings, retests, reports, audit, and PostgreSQL/dev-store parity.
- **In, as optional enrichment:** already-supported provider snapshots and customer-supplied sanitized configuration evidence. These can explain observations but cannot replace external validation or grant probe authorization.
- **Out:** mandatory vendor connectors, automatic IP inventory discovery, internal agents, environments, arbitrary destination/Host/SNI overrides, reusable attack tooling, automatic rule deployment, and unrestricted high-scale execution.
- **Out of the default release:** volumetric capacity certification, internal/east-west/egress validation, complete firewall rule equivalence, and proof that a packet traversed a particular appliance. These require separately governed execution or additional evidence. Preserve existing SOC controls.

Follow [AGENTS.md](../../AGENTS.md), [ADR-0008](../adr/0008-outside-in-only-targets-first.md), [ADR-0014](../adr/0014-inconclusive-readiness-coverage.md), and the [current customer release scope](../feedback/24-current-release-scope.md). Earlier agent-based detection/test documentation is superseded by the outside-in decision.

### Existing foundations to extend

| Area | Existing implementation | Implementation implication |
|---|---|---|
| WAF detection and bounded enforcement | `src/lib/outsideInWafScanner.mjs`, `src/lib/vectorProbes/wafClassProbes.mjs`, `src/lib/vectorProbes/evasionProbes.mjs` | Extend generic scenarios and evidence semantics; do not create a scanner per provider. |
| Origin checks and authorization | `src/services/originBindings.mjs`, `src/lib/capabilityProbes.mjs`, `src/lib/probeJobs.mjs` | Keep the independently verified origin target and server-derived signed scope. |
| Policy mapping | `src/contracts/protectionMapping.mjs`, `src/lib/connectorProviders/` | Keep optional configuration mapping separate from observed control effectiveness. |
| Evidence and target profiles | `src/services/targetHistory.mjs`, `src/services/protectionProfile.mjs`, `src/lib/probeEvidenceTiers.mjs` | Preserve immutable history, comparability, freshness, and observation-only exclusions. |
| Persistence | `src/persistence/postgres/targetHistoryRepository.mjs`, `src/persistence/postgres/targetHistoryServiceAdapters.mjs` | Share pure assessment rules between stores; persist through tenant-scoped repositories. |
| Customer workflow | `apps/web/react/src/pages/target-detail-view.tsx`, `apps/web/react/src/components/targets/origin-relations.tsx` | Extend the target workspace rather than introducing standalone run/scan pages. |

## Action items

- [ ] **PV-01 / P0 - Correct external evidence semantics before adding comparisons.**

  Review the scanner, `wafBoundRunCorrelation.mjs`, `wafProtectedEvidence.mjs`, `edgeDetectionProjection.mjs`, correlation, and customer projections together. In the reviewed scanner, the optional origin leg could promote a connection failure to `origin_lockdown_confirmed`; a local injected timeout reproduced a `Protected` label alongside an inconclusive firewall result. Matching `Server` headers were also used to corroborate application bypass. Reconfirm these behaviors against the implementation checkout before patching.

  Define shared outcomes for response observed, application identity confirmed, explicit denial observed, no response, transport error, and not tested. A timeout, refusal, TLS failure, generic error page, or missing fingerprint must not establish lockdown or identify the responsible control. Require a healthy permitted-path baseline and stronger application-specific evidence, preferably a nonce-bound customer canary response, before confirming an application bypass. Treat generic header/content similarity as supporting evidence only. A customer-created marker validates that marker's enforcement, not an entire attack family.

  **Acceptance:** timeouts never produce a protection claim; ordinary shared server headers never confirm application bypass; scanner, standalone origin executor, finalization, and portal labels agree. Scope all conclusions to the tested path, source, scenario, and time. Keep historical verdicts immutable; increment affected check/scenario versions and require an explicit retest for current conclusions. Add focused negative regressions before broad suite execution.

- [ ] **PV-02 / P0 - Define the generic protection contract and record the architectural decision.**

  Add a detection specification and an ADR for application entry-path validation. An existing declared target anchors an application relation; each entry path references an existing same-tenant target. Relation kinds cover primary route, alternate hostname, declared API/login URL, origin, and fallback/backend route. Record owner, purpose, expected behavior, and required control layers using explicit declarations; do not infer them from tags, logos, or vendor names.

  Model WAF, CDN/edge, network firewall, and DDoS as independent layers. Separate declared intent, vendor detection, observed enforcement, application identity, suspected bypass, confirmed scoped bypass, and evidence limitations. A successful WAF marker does not prove DDoS capacity or firewall traversal. Specify freshness, versioning, comparison compatibility, and reference-only evidence links.

  **Acceptance:** a custom/unidentified provider can complete the same validation workflow with connectors disabled. Every status has an evidence requirement and an unknown/inconclusive alternative. Add planned PV tasks to `PROGRESS.md` at implementation start; use `[~]` while acceptance or release evidence remains outstanding.

- [ ] **PV-03 / P0 - Persist declared entry paths and immutable comparison records.**

  Add an additive, tenant-scoped migration at the next available sequence and synchronize `db/schema.sql`. Proposed records: application entry-path relations, versioned behavior expectations, comparison baselines, and comparison evaluations. Store target/check/run/binding references, declared intent, bounded provenance, timestamps, and digests rather than raw traffic or credentials. Use existing origin bindings for origin relations instead of duplicating their authority.

  Implement contract validation, services, PostgreSQL repositories/adapters, and dev-store parity. Support create/list/archive for relations, capture/read for baselines, and record/read for evaluations. Reuse `target_group:read`, `target_group:write`, evidence-read, and existing run permissions with least privilege; specify permissions per endpoint. Add same-tenant foreign keys, RLS, uniqueness, bounded pagination, idempotent writes, and transactional mutation audit. Validate target lifecycle and current ownership at execution, even when the relation was previously authorized.

  **Acceptance:** cross-tenant references are rejected without disclosure; repeated identical writes are safe; conflicting scopes are rejected; archived relations cannot authorize new checks. Creating a relation or baseline never dispatches traffic. Declaration changes cannot silently reinterpret an older baseline.

- [ ] **PV-04 / P1 - Build bounded entry-path comparisons with existing signed execution.**

  Build plans from exact declared targets and existing eligible checks. Reuse signed jobs, request accounting, destination vetting/pinning, reviewed Start actions, deadlines, cooldowns, concurrency controls, safe windows, cancellation, and kill switches. Persist approved comparison scope at creation/start; capture Host/SNI/port/path through the existing origin gate. Never use a discovered endpoint, redirect, response header, or relation metadata to select a new socket destination.

  Compare a healthy primary route against independently authorized alternate routes using the same scenario and expectation where compatible. Cover declared IPv4/IPv6 variants, hostnames, URL paths, ports, and supported protocols. Results should distinguish intentional public access, a reachability exposure, weaker observed enforcement, suspected alternate application route, and a scoped application bypass. If multiple WAFs/edges are stacked, report the observed behavior without attributing a block or bypass to a specific inner layer unless evidence establishes it.

  Extend generic WAF scenarios for declared login/API paths, bounded method/content-type/encoding variations, and safe inspection-limit checks. Retain a blocked baseline prerequisite for evasion comparisons; an allowed baseline is inconclusive. Do not introduce state-changing login actions, real account abuse, desynchronization, or offensive execution through the safe path.

  **Acceptance:** primary-route success never counts as validation of untested alternate routes; partial plans retain skipped/unknown outcomes. Every executed attempt maps to an exact authorized target and immutable run scope. GET/list/inspection remains passive. Existing [origin execution rules](../backend/current-release-origin-execution.md) remain enforced.

- [ ] **PV-05 / P1 - Implement provider-neutral firewall change acceptance.**

  Define versioned customer expectations for approved destination, protocol/port or exact service endpoint, expected allow/deny behavior, approved source perspective, and change identifier. Capture a selected immutable pre-change baseline from finalized signed external evidence; compare it to explicitly selected post-change evidence. Record exact endpoints or an explicit customer-declared pre/post mapping when migration changes the destination. An inferred IP change is not comparable evidence.

  Reuse bounded TCP/UDP and semantic service checks. Keep E2 transport observations outside readiness coverage under ADR-0014. A port connection can support a statement about observed reachability; it cannot establish firewall enforcement or application inspection. UDP silence remains ambiguous. Required-allow acceptance needs a valid service response; expected-deny acceptance needs control-specific denial evidence or stays inconclusive. If a new semantic firewall check is necessary, specify its evidence model and signed limits before promoting its tier.

  Return per-expectation statuses: matched, regression, improvement, inconclusive, not tested, stale, and not comparable. Classify forbidden service newly reachable and required service newly unavailable as observed acceptance gaps; do not invent a rule ID or root cause. Include repeated samples and approved source variations within existing aggregate limits. Preserve source/worker identity in evidence, and fail comparison when required source evidence is absent or incompatible; never spoof source addresses.

  **Acceptance:** incompatible versions, expectations, sources, targets, or unfinished evidence cannot produce an equivalence/pass claim. Mixed, missing, and inconclusive results remain visible. Zero evaluated expectations never means success. Reports state sampled public-ingress behavior and explicitly leave full rule-table, routing, NAT, egress, and east-west equivalence unestablished.

- [ ] **PV-06 / P1 - Connect scoped gaps to findings, remediation, retests, and reporting.**

  Generate deduplicated findings from accepted comparison evaluations with application/target, failed expectation, scenario, required layer, observed route, evidence references, limitations, owner, and priority. Distinguish confirmed exposures from suspected bypass and unavailable evidence. Do not claim that an allowed probe proves monitor mode, a disabled rule, or a routing bypass; those are candidate explanations until corroborated.

  Extend existing retest lineage to retain comparison context and baseline versions. Recheck current execution authorization before a retest. Reuse existing audited finding lifecycle and exception workflows; a newer passing run or closed external ticket must not silently close findings or siblings.

  Add report/analytics projections over the same server predicates as the matrix. Keep separate units for unique applications/hosts, entry paths, and target/check pairs. Report detection separately from enforcement, and show denominator, freshness, unknowns, exclusions, incomplete scope, and not-tested paths. Multi-provider evidence must not double-count assets. Existing observation/declaration-only checks must not inflate readiness.

  **Acceptance:** a report can reconstruct each conclusion from captured references; missing scope or evidence is visible; inspection and export never execute checks or send notifications. Optional notification delivery retains existing opt-in, permission, outbox, and audit rules.

- [ ] **PV-07 / P1 - Add the workflow to the existing target UI and API contracts.**

  Extend the target workspace with declared entry paths, a per-path/layer evidence table, and a firewall change comparison within Changes & history. Offer inline relation/expectation creation, baseline selection, explicit reviewed check/retest start, progress/Stop, and evidence inspection using shared components and the existing design system. Selecting a baseline or loading a comparison must not run a check. Offer only existing declared targets; show authorization requirements rather than discovering addresses.

  Document proposed routes before implementation, for example target-scoped entry-path collection, application comparison reads, and firewall baseline/evaluation operations. Final route names and response shapes must be pinned by contract tests and documented in `docs/api.md`; do not expose a public observation-write endpoint. Paginate candidate targets and evidence; do not calculate estate totals from capped browser lists.

  Render loading, empty, permission-denied, unsupported-route, stale, partial, incompatible-baseline, unverified-target, and transport-error states. Use labels such as "Allowed for this scenario", "Origin response observed", and "No response; enforcement unverified". Provide no universal "all controls bypassed" or "DDoS protected" label from a bounded check.

  **Acceptance:** keyboard-accessible workflow at mobile/desktop in dark/light; long endpoints stay within the page; evidence selection does not jump on refresh. A user can declare paths, run eligible reviewed checks, capture a baseline, compare a post-change result, inspect a gap, and initiate the exact retest without vendor configuration access.

- [ ] **PV-08 / P2 - Normalize optional configuration enrichment without making it a dependency.**

  Map existing provider snapshots into generic fields for attachment scope, enforcement actions, path/method exclusions, version, and observation time. Preserve partial coverage: one blocking rule/group must not imply all groups block, and hostname attachment must not imply every path is covered. Mark unsupported fields, incomplete inventory, missing permissions, conflicts, and stale snapshots explicitly. Keep provider identity and evidence source distinct from conclusions.

  Define a sanitized customer-evidence import contract only if needed; do not accept raw rule/config dumps, credentials, packet bodies, or arbitrary URLs. Record imports as declarations/configuration evidence, never signed external results. Additional vendor collectors are separate optional work after the core workflow ships, each verified against current official API documentation.

  **Acceptance:** the core tests and UI succeed with no connectors. Configuration absence never means "no protection". Configuration evidence can explain a behavioral gap but cannot upgrade untested behavior, authorize traffic, or overwrite historical external results.

- [ ] **PV-09 / P0-P2 - Verify each slice, stage the rollout, and update completion evidence.**

  Add unit coverage for evidence semantics, identity binding, denominators, comparisons, stale/missing evidence, and source/scope mismatches. Add dev-store API contracts and real PostgreSQL/RLS tests for persistence, authorization, audit, immutable baselines, concurrent retries, and late completion. Add signed-worker tests for pinned destinations, budgets, cancel/kill paths, and tamper rejection. Add browser journeys for creation, review/start, evidence inspection, migration comparison, retest, and all material error/empty states.

  Run focused tests during each change, then required repository gates: `npm test`, `npm run web:typecheck`, `npm run lint`, `npm run lint:portal`, `npm run web:build`, `npm run safety`, applicable schema/tenant-query/contract checks, and `make verify`. Run the relevant browser suite separately from Node performance tests. Inspect rendered evidence at 375/768/1024/1440 pixels in both themes, with keyboard/focus and reduced-motion checks.

  Stage against owned controlled endpoints representing cloud-edge, appliance/reverse-proxy, and unknown/custom responses. Verify correct allow, explicit deny, alternate path, IPv6, application identity, timeout, UDP ambiguity, missing baseline, partial plans, and a pre/post change regression. Test fixtures/mock signatures demonstrate code behavior, not real-provider certification. Require authorized external staging evidence before claiming live execution readiness; do not probe the hospital references as part of implementation verification.

  Roll out additively behind a tenant feature gate with the origin-evidence correction handled as a correctness fix. Keep schema changes reversible at the application level; do not delete retained history. Document migration order, flag disablement, queued-work cancellation, retest requirements, and monitoring. Deployment is a separate explicit release action. Update detection/API/UX/operator docs and `PROGRESS.md` with actual verification evidence; keep tasks in progress when staging or release gates remain open.

  **Acceptance:** code, persistence, UI, and safety gates pass; remaining unsupported observations stay explicit. No implementation or production-completion status is inferred from this plan or from passing mock tests.

### Delivery sequence

| Slice | Dependencies | Reviewable outcome |
|---|---|---|
| A: evidence correction | PV-01 | Consistent bounded evidence semantics and regressions, without rewriting old verdicts. |
| B: generic declarations | A + PV-02 + PV-03 | Audited entry-path/expectation records, contracts, and store parity. |
| C: path validation | B + PV-04 | Signed scoped comparisons with explicit partial/unknown outcomes. |
| D: firewall change acceptance | B + C + PV-05 | Immutable baseline and per-expectation pre/post assessment. |
| E: customer delivery | C + D + PV-06 + PV-07 | Target UI, evidence-linked findings/retests, and accurate reports. |
| F: optional enrichment | E + PV-08 | Additional explanations without changing the no-access workflow. |

PV-09 verification applies to every slice. Ship core slices A-E independently of optional enrichment; preserve SOC boundaries throughout.

## Open questions

- Which owned staging targets and approved external source locations will demonstrate live path/firewall comparisons? Implementation can proceed against isolated fixtures, but live acceptance requires these inputs.
- Which applications can provide a nonce-bound harmless canary for strong application identity? Without one, weaker matches remain suspected and reachability remains an observation.
- Which migration cases require full vendor rule-table analysis? That is a separate optional configuration-analysis scope; it does not block generic external behavioral acceptance.
