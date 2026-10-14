# Evidence and Scoring

## Current outside-in assessment

Verdict confidence on customer targets is `external_only` ([ADR-0008](../adr/0008-outside-in-only-targets-first.md)). There is no agent-placement factor. Live scoring is `readiness-assessment.v3` in `src/lib/readinessProjection.mjs`, with pair eligibility from `src/lib/protectionCoverage.mjs` (`protection-profile.coverage.v2`).

Related: [ADR-0021](../adr/0021-bounded-execution-and-evidence-based-assurance.md) (bounded execution and pair-based assurance), [ADR-0027](../adr/0027-finding-system-summary-and-risk-acceptance.md) (risk acceptance), [ADR-0029](../adr/0029-violation-only-network-verdicts-and-truthful-waf-grading.md) (WAF grading and NFW violation-only), [rule-coverage.md](rule-coverage.md) (per-category assurance).

## Evidence model

Every customer-target verdict is backed by a signed external bundle. Internal agent observation is not an evidence type.

| Evidence item | Required for |
|---|---|
| Test run ID | All verdicts. |
| Check ID, `check_version`, definition digest | All scored pairs. |
| `grading_version`, `signature_corpus_version` | WAF marker/evasion results; stamped on runs via `deriveRunEvidenceStamp`. |
| Target, expected-behavior snapshot, `assurance-scope.v3` | All verdicts. |
| Signed `probe_result` event (`producer_kind: signed_probe`) with matching `nonce_hash` | Readiness credit. |
| Probe metadata (placements, trailing control, enforcement, TCP/UDP outcomes, `source_perspective`) | Kind-specific correlation. |
| Typed `control_declarations` | NFW deny, origin lockdown, rate-limit canary, declared block signature, perspectives, canary sink. |
| Approval documents / SOC notes | High-scale and `.soc` checks. |

Simulation (`SAFE_PROBE_SIMULATION`, `producer_kind: internal_simulation`) and manual declarations are recorded history. They do not earn current coverage credit (`provenance` must be `external`).

## What this evidence can prove

- A control-specific signature or declared header matched on a comparable healthy baseline.
- A declared network deny was violated by a handshake or protocol-validated reply.
- A finding was opened from that violation, later risk-accepted, or moved to `fix_verified` after a complete passing retest.

## What this evidence cannot prove

- Origin receipt of a packet that timed out or was RST at the edge.
- Enforcement from fingerprints, HTTP/2 SETTINGS, DNSKEY presence, or an unattributed 4xx.
- Estate coverage from a capped feed (`score: null`, `input_complete: false`).
- That an accepted-risk finding is remediated (it is a dated decision; see below).

Timeout, error, and not-run remain `inconclusive`. They create no finding and no readiness credit.

## Pair state and freshness

`pairState` keys coverage by applicable **target/check pair** (customer-runnable, kind-compatible, not declaration-only, not observation-only, not missing required setup).

`COVERAGE_FRESHNESS_POLICY`: id `protection-profile.coverage.v2`, **7 days**, unit `target_check_pair`. Age is the earlier of run `completed_at` and immutable observation time. A later completion does not renew an older observation.

| Pair state | Meaning |
|---|---|
| `conclusive` / `pass` | Fresh signed compatible proof; passing verdict (`protected`, `pass`, …, or scoped `edge_protected` after a complete marker comparison). |
| `conclusive` / `gap` | Fresh `exposed` / `edge_exposed` / `bypassable` / `penetrated`. |
| `inconclusive` | Fresh result that is neither pass nor gap. |
| `stale` | Older than 7 days; `current_assurance: expired`, `retest_required`. |
| `partial` | Version, scope, completeness, or positive-outcome gap; `retest_required`. |
| `unknown` | Unfinalized, no evidence, simulation, missing observation time. |
| `excluded` | Declaration-only (E1 / `metadata_marker` / `ops_readiness`) or observation-only (E2 / `OBSERVATION_ONLY_PROBE_KINDS`). |

NFW kinds that can emit `exposed` still sit on `OBSERVATION_ONLY_PROBE_KINDS`, so they stay **excluded from the readiness denominator** (ADR-0014). Rule-coverage reports them separately as `violation_only` ([rule-coverage.md](rule-coverage.md)).

Custom-canary checks (`waf.*_marker.safe` except the three managed markers) **roll up to one pair per target** (`rollupCustomCanaryPairs`). Efficacy is by distinct canary rule, not by check count.

## Version gaps

`versionGapFor` withdraws current credit when:

- `check_version` is missing or differs from `deriveCheckDefinitionVersion`.
- Recorded provenance digest differs (`check_definition_changed`).
- `scenario_version` is required and missing or mismatched.
- The run or verdict records a `grading_version` or `signature_corpus_version` that `gradingSignatureVersionGap` rejects.

`gradingSignatureVersionGap` (`src/lib/checkDefinitionVersion.mjs`) compares recorded `grading_version` / `signature_corpus_version` to `waf-grading.v2` and `waf-signatures.2026-10-13.2` (bumped when generic proxy headers stopped grading `blocked`; runs graded under `waf-signatures.2026-10-13` are a `signature_corpus_version_mismatch` gap until re-run). Runs stamp those fields. `versionGapFor` calls it whenever either field is recorded, so a grading or corpus change marks the pair `partial` (`retest_required`); runs that record neither field (non-WAF kinds) are unaffected. Finding `fix_verified` also compares `grading_version` between the open finding and the retest run.

Material `assurance-scope.v3` change, incomplete marker comparison (`marker-comparison-v4` with healthy baseline and all planned legs), and `observation_only` / `readiness_conclusion: false` also force `partial`.

## Positive-outcome (enforcement) credit

A retained `protected` / `pass` / `edge_protected` label earns current credit only when signed result metadata records `enforcement: enforced` (`positiveOutcomeGap` → `actual_positive_outcome_mismatch` otherwise). `allowed_as_expected` additionally requires nonce-canary application identity and `must_reach_canary`.

Class-marker, evasion, method-policy, and AXFR producers emit `enforcement`. AXFR is `enforced` only when every nameserver of the zone was queried and refused; budget-limited coverage is `partial` and earns no credit. Observation-only kinds never qualify.

## Readiness score

`projectReadiness` (`readiness-assessment.v3`):

```
score = floor(100 × current passing pairs / applicable pairs) − bounded unresolved severity penalty
```

when `input_complete` is true; otherwise `score: null`.

Severity penalties (open / `in_progress` only): critical 20, high 10, medium 5, low 1, info 0, unknown 5. Cap is the coverage maximum.

| Factor | Weight | Meaning |
|---|---:|---|
| Tested scenario assurance | 100 | Passing applicable pairs. |
| Unresolved findings | 0 | Penalty subtracted from the coverage maximum. |
| Evidence freshness | 0 | 7-day expiry; stale pairs are not current. |
| SOC governance | 0 | Reported separately; **zero protection credit**. |

### Accepted risk

`accepted_risk` findings **do not subtract** while their `risk_acceptance.review_at` is in the future. They are counted on `findings.accepted_risk_count`. After the review date they re-enter the penalty set. `fix_verified`, `resolved`, `closed`, and `false_positive` do not penalize.

### Score bands (presentation)

| Score | Label |
|---:|---|
| 90–100 | Strong |
| 75–89 | Good |
| 50–74 | Needs attention |
| 25–49 | Weak |
| 0–24 | Unknown / critical |
| `null` | Incomplete inputs |

Unknown is neither protected nor automatically vulnerable.

## Finding lifecycle

Create a finding when correlation sets `createsFinding: true` (`exposed`, `edge_exposed`, and equivalent gap verdicts).

Do not create findings for observation-only results, timeouts, source-penalized runs, or expected canary allows.

`planFixVerifiedFromRetest` (`src/lib/findingLifecycle.mjs`) moves an **open** / **in_progress** finding to `fix_verified` when a complete passing retest matches check, target, scope, `check_version`, and `grading_version`. Partial or inconclusive retests never close. `verifying_run_id` is stored. `fix_verified` is a recorded retest, not packet-cessation proof.

Risk acceptance remains a dated owner/admin decision (`finding:accept_risk`, reason + `review_at`). It is not proof of a fix ([ADR-0027](../adr/0027-finding-system-summary-and-risk-acceptance.md)).

## Vendor signatures and live verification

`VENDOR_DENIAL_SIGNATURES` carry `live_verified`. Signatures with `live_verified: false` (AWS ALB / API Gateway, Cloud Armor, Azure Front Door, Fastly NGWAF, ModSecurity/Coraza, generic CAPTCHA interstitial) have not been verified on AstraNull-owned staging endpoints. Their `match` grades `blocked` only on a WAF-specific anchor: a block-page phrase or token that only that WAF emits ("Request blocked by AWS WAF", "Cloud Armor", an Azure Front Door/Application Gateway WAF block phrase, a Fastly Next-Gen WAF/Signal Sciences token, the ModSecurity/Coraza block text). Their `suspect` predicate covers generic proxy/CDN headers (`x-azure-ref`, `via: 1.1 google`, `x-served-by`, `x-timer`, `x-amzn-errortype`, `x-amzn-requestid`, a `server` banner) with a 403/406: `matchSuspectedVendorSignature` returns the vendor, and the leg grades `inconclusive` with `inconclusive_reason: 'block_suspected_unverified_signature'` and `matched_vendor`. It never earns protection credit. Cloudflare challenge/block, Akamai reference #18, Imperva incident id, AWS CloudFront, and F5 ASM patterns are marked `live_verified: true`.

A customer-declared block signature (`waf.block_signature` header + optional status codes) is matched first and is the supported path for products without a live-verified vendor pattern.

## Completion criteria

Scoring is complete when executives can read a pair-based score with freshness, version, and enforcement gates, and engineers can drill from that score to the signed probe evidence and the finding lifecycle.
