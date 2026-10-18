# ADR-0032: Optional origin associations and paired identity

Date: 2026-10-16
Status: Accepted for local implementation; live acceptance and deployment outstanding

## Context

External origin-discovery tools combine historical DNS, related DNS names, certificate-to-IP indexes and response comparison. These can expose public associations but cannot confer ownership or establish a current production origin. AstraNull already requires declared targets, independent ownership, explicit origin bindings and signed bounded execution. Its limited leak observation, standalone one-HEAD origin request and target-side evidence projection leave source coverage and comparability gaps.

## Decision

1. Add optional target-scoped origin associations behind explicit tenant opt-in, disabled by default. Keep them in a separate append-only tenant-scoped store with PostgreSQL/dev parity, RLS, same-tenant foreign keys, bounded paging, idempotent mutations and audit. They are unverified source records, not inventory or signed external probe evidence.
2. Collect only bounded DNS for declared hostnames and accept bounded supplied historical-DNS/certificate-index records. No source-URL fetching, full cloud-dataset download, network/port sweep, wordlist brute force, recursive mail/SPF resolution or CIDR expansion. CT supplies names, not a current origin-IP map. Unknown observation times stay unknown.
3. Do not auto-create targets, inherit IP ownership, create bindings or dispatch application probes from clues. Existing declare → independent verification → reviewed binding → reviewed execution remains authoritative. GET/list/detail/inspection never starts collection or probes.
4. Revalidate current binding, both targets/proofs and exact immutable signed scope at durable grant. Archival or revocation prevents later grants. Preserve valid historical evidence separately from current execution authorization.
5. Introduce a separately reviewed versioned paired origin-identity scenario through existing entry-path comparison lifecycle and signed jobs. Two HEAD requests support nonce canaries; two bounded GET requests can additionally supply supporting content observations. Preserve the existing one-HEAD checks and exact fresh nonce/worker/source/method/path/port/scenario proof bar. Content/certificates/static markers alone do not acquire the stronger confirmed flag.
6. Ordinary origin observations remain E2 with no positive readiness credit. The existing declared-lockdown check remains violation-only. A declared-policy violation, a confirmed direct application path and a bypass of a specific WAF rule are distinct. No DDoS capacity assurance or generic protected result follows.
7. Put source associations and their coverage/limits on the target Overview, alongside existing declared origin relations. Both sides show exact binding-scoped historical evidence and current authorization separately. Multi-binding ambiguity stays explicit; no first-match execution or automatic fan-out.

## Consequences

- This is optional defensive enrichment consistent with ADR-0001/0008/0019, not a mandatory IP-discovery workflow or customer agent architecture.
- New storage is additive; migration/schema and compatible server/worker rollout are required before enablement. No deployment is authorized by this ADR.
- Third-party passive reconnaissance cannot reliably be detected from outside-in observations. Customer-side logging and hardening guidance remain recommendations, not new collectors.
- Live provider feeds, source license/coverage checks, owned staging endpoints, positive-denial producers and nonce-canary acceptance remain separately gated. Imports do not claim those integrations exist.
- Historical evidence is not rewritten or silently retested. Source errors and empty/partial feeds never imply origin protection.

## Verification

See [the detection specification](../detection/24-origin-exposure.md) and PROGRESS. Required tests cover source normalization/bounds, zero automatic promotion, tenant/RBAC/RLS/idempotency, revocation/concurrent grants, paired signed scope/budgets/Stop, strict identity outcomes and passive accessible target UI. Local fixture success is not live or production acceptance.
