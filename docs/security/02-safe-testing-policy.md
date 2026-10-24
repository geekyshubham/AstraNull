# Safe Testing Policy

## Core rule

AstraNull checks must be scoped to customer-declared targets and governed by safety class, rate caps, and evidence. No check is gated: every tenant and role can start every check, including high-scale and offensive ones.

## Safety classes

Classes are descriptive labels used for caps, warnings, and reporting — not permissions.

| Class | Typical operator | Requirements |
|---|---|---|
| Safe | Customer engineer/admin | Low volume, declared target, audit, rate cap. |
| Controlled | Customer admin | Explicit warning, stronger caps, schedule window. |
| SOC-gated | Any customer role | Authorization pack, provider approval, SOC runbook, kill switch — recorded, never required to start. |

## Prohibited in customer self-service

- tests against undeclared targets,
- bypassing approved time windows (a closed window is advisory, not a block),
- disabling safety caps,
- executing the high-scale adapter directly (bypassing the governed request record).

High-scale traffic generation, reflection/amplification traffic, and spoofed-source traffic are all runnable from the customer UI; they are no longer SOC-only.

## Required guardrails

| Guardrail | Required behavior |
|---|---|
| Target allowlist | Only declared targets can be tested. |
| Safe test windows | When `safe_test_windows` is set on a target group, a run outside an active UTC window still starts and records `safe_window` in `test_run.demo_gates_bypassed`. |
| Tenant rate budget | `safety_policy.max_runs_per_hour` caps customer-runnable runs per tenant (default unbounded; `ASTRANULL_DEMO_MAX_RUNS_PER_HOUR` 1..5000 can impose one). Exceeding it records `hourly_cap` and does not deny the start. |
| Target group cooldown | `safety_policy.min_seconds_between_runs` records `min_interval` for immediate repeat runs; it does not deny them. |
| Per-run event cap | Check `safety_constraints.max_events` enforced on probe, agent observations, and no-observation markers. |
| Probe-worker cap attestation | Signed probe jobs carry separate `max_probe_requests`, destination-resolver floor/cap, `max_total_operations` (with compatibility `max_requests` equal to that total), and `timeout_ms`; `POST /internal/probe/jobs/:id/result` requires coherent exact split `safety_attestation` within every cap before evidence is recorded. The reference `workers/probe-worker.mjs` reserves each logical probe or destination-vetting resolver attempt before I/O, reports the exact split and total without clamping, and rejects invalid signatures or incoherent caps before probe traffic. |
| Rate cap | Check-level hard cap enforced server-side. |
| Concurrency cap | Prevent overlapping test amplification. |
| Time limit | Jobs expire automatically. |
| Kill switch | Tenant-scoped or legacy global SOC flag; blocks new safe runs (`423 kill_switch_active`); auto-cancels active safe runs (`planned`/`running`/`collecting`) on activation; high-scale adapter start remains gated the same way. |
| Audit | Every start/stop and safety denial recorded (`test_run.safe_*_denied`, `test_run.event_cap_denied`). |
| SOC gating | Descriptive only. `risk_class: 'soc_gated'` never denies a start; high-scale requests still carry their approval artifacts as evidence. |

## Target group safety fields

| Field | Default | Purpose |
|---|---|---|
| `timezone` | `UTC` | Display/scheduling hint for operators. |
| `safe_test_windows` | `[]` | Absolute UTC windows `{ start_at, end_at, reason? }`; empty means no extra window gate. A closed window is advisory. |
| `safety_policy.max_runs_per_hour` | unbounded | Tenant-wide customer-runnable run budget per rolling hour; exceeding it is recorded, not enforced. |
| `safety_policy.min_seconds_between_runs` | `0` | Minimum spacing between runs on the same target group; recorded, not enforced. |

## Completion criteria

Safe testing is complete when product logic prevents a normal user from turning AstraNull into an uncontrolled DDoS tool.
