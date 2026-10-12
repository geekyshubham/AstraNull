# Evidence and Scoring

## Current outside-in assessment (2026-10-09)

The model below contains historical agent-era examples and legacy weights; it is not the active scoring contract. ADR-0008 forbids customer agents/environments. Current verdict confidence is `external_only`; current scoring is defined by [ADR-0021](../adr/0021-bounded-execution-and-evidence-based-assurance.md) and `src/lib/readinessProjection.mjs` / `src/lib/protectionCoverage.mjs`.

`readiness-assessment.v2` keys coverage by applicable active target/check pair, including untested pairs in the denominator. Current complete signed compatible proof is eligible for seven days (`protection-profile.coverage.v2`); immutable observation/availability time, scenario/check/classifier version and current scope govern eligibility. Floor(100 × current passing pairs / applicable pairs) is reduced by bounded unresolved severity penalties: critical20/high10/medium5/low1/info0/unknown5. Governance contributes zero protection credit. Incomplete source accounting returns `score: null`, `input_complete: false`; a capped feed does not establish estate coverage. Raw and exact grouped/weighted projections must agree.

Raw responses, customer expectations, attribution, comparison completeness and final assurance remain separate. Unknown is neither protected nor automatically vulnerable. A fingerprint/status/auth wall/timeout, DNSKEY presence or HTTP/2 SETTINGS is not mitigation proof. Complete marker proof requires an independent healthy comparable permitted baseline and all scoped legs. An allowed harmless marker is not exploitability proof. Material scope/version change invalidates current credit without rewriting historical custody. A missing historical snapshot is unknown, not today's posture. Comparison-report 30-day freshness is separately labelled and never extends seven-day readiness. Specific CVE validation has no generic fingerprint fallback.


**Timeout guard regression (2026-10-11).** Shared ordinary correlation now makes every `external_result: "timeout"` inconclusive regardless of absent/malformed kind metadata, expected behavior or attested I/O. It never aliases a timeout to blocked and creates no finding or readiness credit. Regression cases cover the declared defaults of all 251 catalog definitions for error/timeout/not-run, malformed/absent kinds, and durable repository-backed verdict publication with one audit and no finding. These are contract/publication fixtures, not 251 independently executed network mechanisms. Historical verdict/custody records stay unchanged.

Current scope uses `assurance-scope.v3`, including separately declared port/protocol and losslessly hashed material target/policy/group declarations. Credential-like text and literal JSON keys cannot be redacted or dropped from authority hashes. Catalog credential-version redaction is separate and unchanged. Stored v1/v2 scopes require retest without changing custody. A complete signed marker comparison may earn scoped `edge_protected` scenario credit only after actual event/vault resolution, matching run correlation nonce, recorded immutable ingestion availability and existing baseline, version, scope and freshness gates. Retained positive verdicts cannot override contradictory actual enforcement; missing outcome proof withholds current credit. Current report classification also binds the actual scenario/expectation and all recorded policy/group definitions, rather than accepting completeness labels alone. An unattributed edge block does not independently validate WAF and CDN. Independent WAF posture projections apply the same conservative positive-outcome rule to every referenced signed event and require a recorded ingestion timestamp. Contradictory or missing actual enforcement yields current `unknown`/`not_established` while preserving the stored historical posture and custody; creation or observation time cannot substitute for ingestion availability.


## Evidence model

Every verdict should have an evidence bundle.

| Evidence item | Required for |
|---|---|
| Test run ID | All verdicts. |
| Check ID/version | All verdicts. |
| Target and expected behavior | All verdicts. |
| Probe event | Most checks. |
| Probe result | Most checks. |
| Agent observation/no-observation | Inside/outside proof checks. |
| Agent health | Agent-based checks. |
| Correlation decision | All verdicts. |
| Approval documents | High-scale checks. |
| SOC notes | High-scale checks. |
| Health metrics | High-scale and availability checks. |

## Readiness score dimensions

The live readiness service (`src/services/readiness.mjs`) computes an **evidence-backed** score from in-memory tenant records. Points are not awarded from absence of data (for example, an empty high-scale queue does not imply SOC readiness).

| Dimension | Weight | Meaning |
|---|---:|---|
| Validation coverage | 40 | Distinct declared target groups with a **recent** (≤30 days) completed/verdicted run that has a linked verdict, event, or evidence vault record. |
| Agent placement & health | 25 | Active non-revoked agents and online health; detail distinguishes registration vs observation evidence. |
| Open findings impact | 25 | Penalty for open findings; verdict counts separate recent vs stale evidence. |
| Evidence freshness | 15 | Awarded only when recent evidence-backed validations exist; **stale evidence (>30 days) earns no freshness credit**. |
| SOC governance posture | 10 | Explicit artifacts: dual SOC approval with accepted authorization pack, governed high-scale lifecycle audit trail, or tenant kill-switch evidence—not pending requests alone. |

Longer-term product dimensions (origin bypass, L3/L4, DNS, L7/API) remain roadmap items; they must also be evidence-backed when implemented.

## Score bands

| Score | Label | Meaning |
|---:|---|---|
| 90-100 | Strong | Readiness is well-evidenced. |
| 75-89 | Good | Minor gaps or stale evidence. |
| 50-74 | Needs attention | Important gaps exist. |
| 25-49 | Weak | Multiple critical gaps. |
| 0-24 | Unknown/critical | Missing evidence or confirmed high-risk exposure. |

## Finding creation logic

Create finding when:

- verdict is bypassable/penetrated,
- required control is missing,
- high-scale test failed or caused unacceptable degradation,
- agent placement invalidates readiness evidence,
- evidence is stale for critical target group.

Do not create noisy findings for expected/accepted behaviors unless policy requires it.

## Completion criteria

Scoring is complete when executives can trust the score and engineers can drill from score to evidence to remediation.
