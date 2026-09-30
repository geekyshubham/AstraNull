# ADR-0008: Outside-in only, targets-first scope

## Status

Accepted (2026-09-30). Supersedes ADR-0002 (outbound agent control) and narrows ADR-0004 (target groups as core scope).

## Context

The declared-scope model had three layers (environments → target groups → targets) plus an optional internal agent fleet. Customers found it hard to follow, and the agent path added install, update, placement, and auth surface that the product no longer wants to carry. AstraNull validates from the outside in.

## Decision

1. **No agents.** The agent binary, packaging, Helm chart, agent control plane (registration, heartbeat, jobs, observations, updates, trust keys), bootstrap tokens, placement diagnostics, agent auth, and agent RBAC permissions are removed. Verdicts are produced from external probe evidence only (`external_only` confidence). Readiness no longer has an "agent placement & health" factor; its weight is redistributed across the remaining factors so the score still totals 100.
2. **No environments.** The environments API, pages, and pickers are removed. Environment membership becomes a target tag (`env:<name>`), backfilled by migration `0058`.
3. **Targets first, with tags.** A target is a domain, hostname/FQDN, IP, or CIDR the customer declares. Targets carry free-form tags. Customers can create a target directly without choosing a group; it lands in the tenant's default group, created on demand.
4. **Target groups stay, as a secondary grouping.** Groups still carry the policy that runs need (safe test windows, expected behavior default, LOA, high-scale eligibility, DNS ownership rollup). Every group is `external_only`.
5. **No destructive schema change in this release.** Tables `agents`, `agent_jobs`, `bootstrap_tokens`, `environments`, and related agent-update tables stay in the database, dormant and unread. Dropping them is a separate, approved migration.

## API contract

| Change | Detail |
|---|---|
| Removed (404) | `/v1/agents*`, `/v1/agent-updates*`, `/v1/agent-update-trust-keys*`, `/v1/bootstrap-tokens*`, `/v1/placement/*`, `/v1/environments*` |
| `POST /v1/targets` | Body `{ kind, value, expected_behavior?, tags?, target_group_id? }`. Omitted `target_group_id` uses the tenant default group. `201` returns the target. Permission `target_group:write`. Audited `target.added`. |
| `PATCH /v1/targets/:id` | Body `{ tags?, expected_behavior? }`. Kind/value stay immutable. Audited `target.updated`. |
| Target responses | Every target payload exposes top-level `tags: string[]` (stored in target metadata). |
| Tag rules | Trimmed and lowercased, `^[a-z0-9][a-z0-9:_.-]{0,47}$`, deduplicated, at most 16 per target. Invalid input returns `400 invalid_target_tags`. |
| Target groups | `environment_id` is ignored on write and omitted from responses. `validation_mode` is always `external_only`. |
| `/v1/state` | No `agents_online` / `agents_total` fields. |

## Consequences

| Positive | Negative |
|---|---|
| One mental model: declare a target, prove ownership, run bounded checks, read the verdict. | Internal origin corroboration is no longer available; verdicts that needed an agent now report external-only confidence. |
| Smaller attack and ops surface: no agent auth, supply chain, or fleet rollout. | Dormant tables remain until a follow-up cleanup migration. |
| Tags replace a whole navigation tier. | Existing integrations that called removed endpoints receive `404`. |

## WAF posture without agents

The optional WAF posture add-on previously distinguished a fully validated **`protected`** state
(edge block plus an internal agent confirming the origin was not reached) from an
edge-only **`edge_protected`** state (blocked at the edge, origin unverified). With agents removed,
`protected` is now derived from the strongest **external** evidence the outside-in scanner already
collects: an edge-block result **and** a passing direct-origin / origin-bypass check showing the
origin is **not reachable** (origin lockdown) for the same asset within the same freshness window.
When no origin-lockdown evidence exists, a passing edge scan stays `edge_protected`. The summary
field names (`protected`, `edge_protected`, `underprotected`, `coverage_pct`) are unchanged so the
portal is unaffected; only the derivation and explanation strings change (for example,
"Observed validation · edge block and origin lockdown" instead of "agent-confirmed"). No
`agentCorroborated`, `requireAgentForProtected`, agent-observation events, or `agent_verified`
ownership rung participate in WAF or ownership evidence any longer; a legacy `agent_verified`
verification row ranks as unverified (rank 0) and must re-prove ownership via DNS/HTTP.
