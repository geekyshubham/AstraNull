# Follow-up review of uncommitted changes

Date: 2026-10-02  
Scope: Recheck the original F01–F12 / G01–G05 findings, examine their fixes, and review the new notification lifecycle and outbox paths.  
Outcome: **The frontend fixes check out. Notification recovery still requires corrections.**

## Current assessment

**11 original defects are resolved as reported. F02 is partially resolved:** failed attempts are no longer incorrectly remembered as successful, and explicit replay works, but a failed initial enqueue can still lose the notification permanently without replay.

This review found **four actionable backend findings: three P1 and one P2**. They concern paused-channel delivery, recovery starvation, the remaining initial-enqueue loss window, and duplicate sends between the background worker and recovery. All four were reproduced using the actual Postgres notification services/repositories in temporary migrated databases, with mocked senders. No live provider traffic was generated.

The existing checks all pass, including the new regression tests. Those tests do not cover the four cases below. Application source, migrations, tests, and progress status were not edited during this review; only review Markdown was updated/added.

Severity: P1 = major reliability/control failure to correct before releasing the affected path; P2 = material incorrect behavior with a workaround.

## Verification performed

| Check | Current result |
|---|---|
| `npm run web:typecheck` | Passed |
| `npm run lint` | Passed |
| `npm run lint:portal` | Passed; zero hardcoded portal values |
| `npm run safety` | Passed |
| `npm test` | **4,003 tests passed** in the first lane; **371 integration tests passed**; zero failures/skips in both lanes |
| `npm run test:contract` | **7 passed**; the previous target-tags failure is fixed |
| Four new Playwright journey files | **26 passed** |
| Fresh production Vite build into `/tmp` | Passed; normalized generated JS and CSS match working-tree artifacts |
| `git diff --check` | Passed |
| Independent migrated-Postgres reproductions | Four failures described below reproduced |

Browser files exercised: `portal-notification-channels.spec.mjs`, `portal-refined-findings-groups.spec.mjs`, `portal-refined-policies-runs.spec.mjs`, and `portal-trend-chart-refresh.spec.mjs`. These cover notification UI state/races and permissions, populated grouped details, exact policy bindings and partial failure, run controls, cold detail hydration, and focused chart refresh across mobile/desktop and light/dark combinations.

The full test script excludes live DNS by design. No live-provider drill, production deployment, or comprehensive screen-reader verification was performed.

## Original finding status

| ID | Status | Verification |
|---|---|---|
| F01 — Chart crash on shrinking history | Resolved | Selection is keyed by run ID and bounded synchronously; browser tests cover focused 5→2→1→0 transitions and surviving selection |
| F02 — Failed emit claimed as successful | **Partially resolved** | Removed the process-local success claim; atomic event/attempt insertion and unique dedupe keys work on explicit replay and across instances. Initial enqueue failure still has no automatic recovery: R03 |
| F03 — Sends block run/report completion | Resolved | Lifecycle emitters await enqueueing rather than provider delivery; stalled-provider tests pass. Background/recovery coordination has a separate issue: R04 |
| F04 — Stale channel fetch overwrites newer state | Resolved | Request-generation/session guards and refreshing state are present; both stale-empty and stale-error browser cases pass |
| F05 — Quadratic Refined grouping | Resolved | Indexed context and cached facts remove the previous repeated scans. Same generated-title workload: 1,000 records ≈6ms, 4,000 ≈9ms, 10,000 ≈26ms in this run, versus ≈4,818ms at 10,000 previously |
| F06 — Asset collapse hides member findings | Resolved | Per-member records, lifecycle counts, group membership, and links are preserved; populated detail/member-navigation tests pass |
| F07 — Distinct group scopes counted as one asset | Resolved | Shared asset identity includes group ID or finding ID when no target/label exists; helper tests pass |
| F08 — Accepted risk presented as closed | Resolved | Lifecycle-specific SLA wording and recorded-only closure timestamps; accepted-risk browser regression passes |
| F09 — Undated findings called within SLA | Resolved | Group assessment carries dated/undated counts and unknown/partial states; browser tests pass |
| F10 — Recently opened uses oldest member | Resolved | Recent sort uses `latestOpenedAt`; oldest retains first-opening semantics |
| F11 — Bounded history called no events ever | Resolved | Authoritative per-rule latest attempts are independent of the feed; old-server fallback discloses limited history |
| F12 — Missing group-name route hydration | Resolved | Finding detail now requests target groups and exposes load failures; cold-link/failure browser tests pass |

The timing comparison is a local Node helper measurement, not a browser performance SLA. The existing scale regression also covers custom titles and operation counts.

## Remaining findings

### R01 — P1: Turning a channel off does not stop its queued retries

**Locations:** [notificationServiceAdapters.mjs:538](src/persistence/postgres/notificationServiceAdapters.mjs#L538), [notificationRetry.mjs:418](src/lib/notificationRetry.mjs#L418). The new lifecycle update path is in the former file; the existing retry helper becomes relevant to that new behavior.

`listNotificationRules()` includes live disabled rules. `processDueNotificationRetries()` passes that list unchanged to the batch helper, which builds a rule map without checking `enabled`. The delivery builder looks up the destination and sends. In contrast, the new in-process outbox worker explicitly filters disabled rules before delivery.

**Reproduction against Postgres:**

1. Create an enabled webhook rule and durably enqueue a due attempt.
2. Use `updateNotificationRule()` to set `enabled: false`.
3. Run `processDueNotificationRetries()` in webhook mode with a counting sender.

Observed:

```json
{"scenario":"paused_rule_retry","sends":1,"outcomes":["delivered_provider"]}
```

The rule was disabled before processing began; this is not merely a send already in progress when the operator paused it.

**Impact:** The UI can say Off while queued notifications still leave the system. This also makes background delivery and scheduled recovery disagree on the same rule state. The DLQ batch likewise lacks an enabled-rule gate; that path was source-traced, not independently exercised here.

**Correction:** Enforce a consistent lifecycle gate in every delivery entry point, including retry and DLQ redrive. Define whether disabled rules hold or cancel pending work, and represent that decision without sending. Check eligibility close to the actual send rather than relying solely on an earlier subscription snapshot.

**Required regression:** Enqueue → turn off → process retry, and enqueue/fail → turn off → redrive. Both should perform zero sends. Cover re-enabling according to the chosen hold/cancel semantics.

### R02 — P1: Recovery silently ignores pending outbox work older than the latest 500 events

**Locations:** [notificationServiceAdapters.mjs:540](src/persistence/postgres/notificationServiceAdapters.mjs#L540), event-list query in [notificationRepository.mjs:117](src/persistence/postgres/notificationRepository.mjs#L117).

The new outbox relies on the existing retry processor for dropped jobs and crash-orphaned attempts. That processor reads only the newest 500 events, then finds due attempts inside that recent-event slice. It never queries the durable due backlog directly or advances a cursor through older events.

**Reproduction against Postgres:** Enqueue one due pending event, insert 500 newer events, then invoke recovery after the pending attempt is due.

Observed:

```json
{"scenario":"old_pending_beyond_feed","due_count":0,"sends":0,"pending_status":"provider_retry_scheduled"}
```

Repeated processing continues to select the same newer events. Passing an explicit tenant ID to the scheduler does not fix the omission.

**Impact:** An existing durable event can remain undelivered indefinitely after a crash or queue overflow. The in-process queue can hold 1,000 jobs, so the 500-event recovery limit is smaller than the backlog the feature explicitly allows. The new documentation's assurance that unfinished work is picked up after five minutes is therefore incomplete.

**Correction:** Query due work independently of event chronology, using the latest attempt per event/rule, tenant-scoped limits, and a stable drain/pagination policy. Continue until the due backlog is drained or a bounded work budget is reached; the next tick must advance rather than revisit only recent events.

**Required regression:** Place a due pending attempt behind at least 500 newer completed/non-due events and confirm it is recovered. Add a multi-page backlog and queue-overflow case.

### R03 — P1: Initial enqueue failures still lose run/report notifications without an explicit replay

**Locations:** [reportServiceAdapters.mjs:273](src/persistence/postgres/reportServiceAdapters.mjs#L273), its catch at line 290, and [notificationServiceAdapters.mjs:723](src/persistence/postgres/notificationServiceAdapters.mjs#L723).

The outbox transaction atomically persists a notification event and its attempts, but it is a separate transaction from report creation or verdict/finding publication. If that initial transaction fails, the caller catches the error, records a metric, and allows the domain operation to succeed. No durable retry task or reconciliation marker survives. The delivery retry worker can recover committed pending attempts, but cannot recover an event that never existed.

This fixes the original erroneous in-memory dedupe behavior, yet leaves the broader notification-loss window. New tests demonstrate successful **manual replay** after failure; they do not establish automatic recovery. The new report emitter test also explicitly accepts a successful report with zero notification events after enqueue failure.

**Reproduction against Postgres:** Create an in-app `report.ready` subscription. Make `enqueueNotificationEvent()` throw once. Create a report through the actual report service, restore enqueueing, and run retries ten minutes into the future.

Observed:

```json
{"scenario":"report_commit_enqueue_failure","report_returned":true,"reports":1,"notifications":0,"retry_due_count":0}
```

**Impact:** A transient database problem during enqueueing can permanently lose report-ready or run/finding alerts. Repeating report creation creates another report rather than replaying the original report's identity. A process crash between domain commit and enqueue produces the same durable-state gap.

**Correction:** Persist outbox intent with the domain operation in the same tenant transaction, or introduce a durable domain-event/reconciliation mechanism that can discover missing notification identities and retry them independently of client replay. Keep external provider sends asynchronous. A metric and an exception-swallowing catch are not a recovery mechanism.

**Required regression:** Fail/crash after domain persistence but before notification enqueue; restart/run reconciliation without reissuing the user operation; verify exactly one event for the original report/run identity.

### R04 — P2: The background sender and recovery worker can deliver the same pending attempt concurrently

**Locations:** [notificationServiceAdapters.mjs:94](src/persistence/postgres/notificationServiceAdapters.mjs#L94), [notificationServiceAdapters.mjs:205](src/persistence/postgres/notificationServiceAdapters.mjs#L205), and the retry path at line 534.

The five-minute grace is treated as proof that a pending job is abandoned. Neither sender claims the attempt in Postgres before external I/O. While the in-process worker is still sending, its initial attempt remains `provider_retry_scheduled`; a due recovery tick sends it again.

The grace is not a valid upper bound for a healthy worker. Jobs can wait behind up to 1,000 queued jobs with concurrency two. An event can also have many subscribed destinations, sent sequentially with 10-second adapter timeouts; the total can exceed five minutes even though each individual adapter remains bounded.

**Reproduction against Postgres:** Enqueue an event, block the first mocked send, advance the injected clock beyond the configured grace, and run recovery while the first sender remains active.

Observed:

```json
{"scenario":"healthy_outbox_worker_overlaps_recovery","sends_before_first_worker_finishes":2}
```

The reproduction uses a controlled clock and sender rather than waiting five real minutes. It verifies the race; the backlog and sequential-send paths explain how it can occur in normal operation.

**Impact:** Duplicate alerts and automation calls during slow delivery/backlog. The unique event dedupe key prevents duplicate event rows; it does not coordinate delivery ownership. This is separate from the unavoidable possibility of an external send succeeding immediately before its acknowledgement is lost.

**Correction:** Have both paths atomically claim due attempts using a lease or equivalent shared ownership mechanism, with lease expiry and eligibility recheck before sending. Separate “queued” from “actively delivering”; an age threshold alone cannot decide whether a job is abandoned. Retain downstream idempotency for unavoidable delivery-acknowledgement failures.

**Required regression:** Concurrent background/recovery workers, two scheduler instances, queued jobs older than the grace, and lease expiry after process death. Assert one active sender per claimed attempt.

## Original gap status

| Gap | Current status |
|---|---|
| G01 — No rule lifecycle controls | Implemented and UI/permission tests pass; delivery semantics still need R01 |
| G02 — Different grouping entities under variants | Addressed by ADR-0009 and grouping contract tests; documented product/UX decision remains before a default change |
| G03 — No durable browser coverage | Addressed: new browser journeys are checked in and all 26 passed |
| G04 — No real-Postgres emitter coverage/dev parity | Original coverage gap addressed: publication/notification integration tests passed, and the dev finding emitter checks subscription. Recovery edge cases R02–R04 remain uncovered |
| G05 — Tracker/schema mismatch | Contract gate is green; most tracker issues reconciled. RUX-015 still says there is no checked-in notification browser journey, contradicting the new file and RUX-017 |

## Recommended next pass

1. Correct R01 across retry and DLQ paths.
2. Design the recovery query and shared attempt claims together for R02/R04.
3. Close the domain-commit/enqueue gap in R03 with transactional intent or durable reconciliation.
4. Add the four adversarial integration cases above and reconcile the stale tracker sentence.

The review verifies the original frontend corrections and their new regression coverage. It does not yet support treating notification delivery/recovery as complete.
