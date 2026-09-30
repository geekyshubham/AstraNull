# AstraNull AI Agent Build Guide

This file tells implementation agents how to build AstraNull without losing context.

## Mission

Build **AstraNull**, a no-access-first, **outside-in** DDoS readiness validation platform. The system validates customer-declared targets (with tags) and target groups using external probes, SOC-gated high-scale workflows, evidence correlation, and readiness scoring. Per [ADR-0008](docs/adr/0008-outside-in-only-targets-first.md), there are **no agents and no environments** — verdicts come from external probe evidence only (`external_only` confidence).

## Non-negotiable product rules

| Rule | Meaning |
|---|---|
| No default cloud access | Do not design core functionality around AWS/GCP/Azure/CDN credentials. Optional integrations can be added later. |
| No IP inventory discovery | Customer declares targets/target groups manually or via CSV/API import. Do not reintroduce automatic discovery as a required feature. |
| Outside-in only, no agents | Per [ADR-0008](docs/adr/0008-outside-in-only-targets-first.md), do not reintroduce an internal agent, agent control plane, bootstrap tokens, placement diagnostics, or environments. Membership is expressed as target tags. |
| SOC gates high-scale tests | Customers can request high-scale tests. Only SOC can approve, schedule, execute, coordinate, stop, and close them. |
| Evidence over assumptions | Every verdict must be tied to observed external probe data, health signal, approval artifact, or explicit customer-provided declaration. |
| Do not ship attack tooling casually | Do not add raw, reusable DDoS attack scripts, amplification logic, or unmanaged traffic generators. High-scale execution must be governed and authorized. |

## Implementation agent roles

| Agent | Primary docs | Goal |
|---|---|---|
| Product Agent | `docs/product/*`, `docs/flows/*` | Maintain product scope, personas, flows, roadmap, and acceptance criteria. |
| UX Agent | `docs/ux/*` | Build the app pages, tabs, visualizations, empty states, forms, and friendly workflows. |
| Backend Agent | `docs/backend/*` | Build APIs, database models, orchestration, queue workers, scoring, reporting, and audit logs. |
| Detection Agent | `docs/detection/*` | Build check library, vector taxonomy, correlation engine, verdict logic, and evidence model. |
| SOC Agent | `docs/soc/*` | Build SOC console, approval state machine, authorization pack, execution runbooks, and kill switch. |
| Security Agent | `docs/security/*` | Review secrets, tenant isolation, safe testing limits, privacy, retention, audit, and compliance posture. |
| QA Agent | `docs/product/06-release-plan.md`, `docs/backend/05-test-strategy.md` | Create tests for every feature and update completion status. |

## How agents should work

1. Pick a task from `PROGRESS.md`.
2. Read the linked implementation doc before coding.
3. Implement the smallest complete slice.
4. Add or update tests.
5. Update `PROGRESS.md` status from `[ ]` to `[~]` or `[x]`.
6. Add any architectural change to `docs/adr/`.
7. Do not mark a task complete unless the acceptance criteria in the linked doc are satisfied.

## Status convention

| Symbol | Meaning |
|---|---|
| `[ ]` | Not started |
| `[~]` | In progress |
| `[x]` | Complete |
| `[!]` | Blocked |
| `[?]` | Needs product decision |

## Definition of done

A feature is complete only when:

- user-facing behavior works,
- API behavior is documented,
- database/event impact is handled,
- audit logging exists for security-relevant actions,
- error and empty states exist,
- tests exist,
- docs are updated,
- `PROGRESS.md` is updated,
- no unsafe DDoS execution path bypasses SOC controls.

## Safety reminder

AstraNull is a defensive validation platform. Implementation must avoid adding unmanaged traffic generation or reusable public attack recipes. For high-scale validation, build governance, authorization, scheduling, monitoring, and integration adapters rather than free-form attack execution.
