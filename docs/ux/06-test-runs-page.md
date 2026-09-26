# Test Runs Page

## Purpose

The Test Runs page is the proof center. It should answer:

- What did AstraNull send?
- What did the outside probe observe?
- What did the inside agent observe?
- How did AstraNull decide the verdict?
- What evidence can we export?

## Summary layout

```text
Test Run: run_01J...
Target Group: Retail Checkout - Prod
Status: Completed
Verdict: Bypassable
Score Impact: -18

Top Evidence:
- Probe from us-east reached 203.0.113.10:443
- Agent prod-origin-01 observed nonce abc123 on eth0
- Expected behavior was "must be blocked before origin"
```

## Timeline event types

| Event | Description |
|---|---|
| Test planned | Planner selected checks and constraints. |
| Agent prepared | Agent acknowledged job over outbound channel. |
| Probe sent | External worker sent safe validation traffic. |
| Probe observed response | External worker recorded response/timeout/reset. |
| Agent observed nonce | Agent saw matching test ID/nonce. |
| Correlation completed | Engine matched events. |
| Verdict emitted | Pass/fail/inconclusive created. |
| Finding created/updated | Failed verdict mapped to finding. |
| Notification sent | Alert/report/ticket emitted. |

## Verdict truth table display

| External result | Agent observation | Verdict |
|---|---|---|
| Blocked/timeout | Not seen | Protected |
| Allowed/connected | Seen | Bypassable / Penetrated |
| Blocked/timeout | Seen | Edge response blocked, traffic still penetrated |
| Allowed/connected | Not seen | Inconclusive / wrong placement / downstream block |
| Probe failed | Agent silent | Inconclusive |

## Evidence detail panel

Show:

- test ID,
- nonce hash/fingerprint,
- target,
- check version,
- probe region/source ID,
- external result,
- agent ID,
- observation mode,
- timestamp delta,
- confidence,
- raw event IDs,
- retention period,
- export button.

## Validation scans (on-demand and scheduled)

A validation scan runs several bounded safe checks against one exact target or a whole target group, one check at a time, through the same safe-run path as a single run.

### Launcher

Available from the Test Runs head action "Start validation scan" and from the target group detail head action. Only roles with `test_run:start` see it; other roles see a read-only note.

1. Target group (fixed on target group detail, selectable on Test Runs).
2. Scope: whole group (shows eligible target count) or one exact target.
3. Check picker: checks grouped by taxonomy section (`section_label` from `GET /v1/checks`), section select-all, search, selected count, evidence tier and bounded probe metadata per check. SOC-gated and monitor-only (E5) checks are not listed and a note says so; the API refuses them as well. Checks incompatible with the chosen target are disabled with the reason.
4. Optional name.
5. Run now, or schedule: date and time (at least one minute ahead), recurrence none, daily, weekly, or monthly, and timezone.
6. Review: a confirmation restates group, scope, number of checks, planned steps, request upper bound, and schedule before anything starts.

### Live scan view (`#scan-detail?id=`)

- Header: name or id, status badge, links to the target group and Test Runs, and a Stop button (roles with `test_run:start`, while the scan is scheduled, pending, or running). Stop asks for confirmation, accepts an optional reason, and for recurring scans offers to cancel future occurrences.
- Progress: bar and "k of n steps complete, r running, d deferred" from the scan summary; scheduled, deferred, denied, and cancelled banners show `scheduled_for`, `next_eligible_at`, `abort_reason`, or `cancel_reason`.
- Steps table: position, check with section and evidence tier, target, status (pending, deferred, running, collecting, verdicted, denied, skipped, cancelled with humanized reason), bounded request (probe kind, method, path, protocol, max requests, timeout), response (external result, status code), requests sent (a number from the worker attestation, "0 (simulated, no live traffic)" in simulation mode, or "inline, no network" for control-plane checks), verdict with confidence, and a link to the child run.
- Activity log: chronological feed of scan lifecycle audit entries, child run audit entries, and child run events (probe result received, observation received, observation window elapsed). Metadata only; no request or response bodies exist to show.
- Live refresh: the view polls the scan and its activity every few seconds while active, slower while scheduled, and stops on a terminal status. A live region announces the refresh cadence and the final status once.

### Scheduled scans list

Shown as a "Validation scans" card on Test Runs (all groups, status filter) and on target group detail (that group, scheduled first). Columns: name or id, scope, checks, scheduled for, recurrence, next occurrence, status with progress text while active. Actions: Open, Edit (only while scheduled), Cancel (with the cancel-series option for recurring scans), and Schedule again for finished one-time scans.

### Runs integration

Child runs show a "Scan" link when they belong to a scan; run detail offers "Open parent scan". The in-progress banner counts active scans as well as runs.

## Completion criteria

Test Runs page is complete when a skeptical engineer can understand and verify the verdict without needing backend logs, and when a user can select checks by section, start or schedule a scan, watch each step's request, response, request count, and verdict update live, read the live log, and stop the scan.
