# In-depth review of uncommitted changes

> **Historical review.** Fixes have been re-reviewed. See [the follow-up review](UNCOMMITTED_CHANGES_REVIEW_FOLLOWUP.md) for current findings, verified resolutions, and test results. The findings below describe the original working-tree snapshot.

Date: 2026-10-02  
Repository: AstraNull  
Comparison: working tree, including untracked source and assets, against `HEAD`  
Review outcome: **Changes need corrections before release.**

## Summary

Found **12 actionable defects: 4 P1 and 8 P2**, plus five implementation or verification gaps. No P0 issue was identified. Passing automated checks do not cover the reproduced failures below.

The most consequential problems are a React chart crash during data refresh, lost notification events after transient failures, outbound notification delivery blocking Postgres run completion, and quadratic finding aggregation that stalls large inventories. Other findings concern stale responses, omitted finding records, incorrect lifecycle/SLA claims, sorting, and incomplete route hydration.

Severity definitions used here:

- **P1:** Major reliability or performance failure; correct before releasing the affected feature.
- **P2:** Incorrect behavior or material workflow/data gap with a workaround.
- **P3:** Minor polish; omitted from the defect list to keep it actionable.

This was a review, not a repair pass. Application source, existing tests, and progress status were not edited.

## Scope and approach

Reviewed the backend diff, frontend TypeScript/React changes, new Refined pages and grouping helpers, notification client and panel, shared primitives, chart changes, provider setup guidance, style changes, generated artifacts, notices, documentation, and changed tests. The baseline had 63 modified tracked files plus untracked implementation files/assets. There were no staged changes.

Traced notification creation, delivery, retry metadata, repository reads, report emission, run-terminal hooks, finding publication, route dataset policies, aggregation, navigation, and error states. Checked the changes against the outside-in product rules, `AGENTS.md`, `PRODUCT.md`, `DESIGN.md`, and the new integration documentation. Used small executable reproductions and actual React components in a browser to distinguish defects from speculation.

Browser reproductions used an isolated component harness in Ego Browser, served by Vite, with controlled records or mocked fetch responses. They exercise shipped components but do not constitute complete authenticated end-to-end journeys. The existing dashboard/target Playwright journeys were also run separately.

## Verification results

| Check | Result | Practical coverage/limit |
|---|---|---|
| `npm run web:typecheck` | Pass | Type correctness; does not catch stale array-index state |
| `npm run lint:portal` | Pass, zero hardcoded portal values | Existing source rules |
| `npm run lint` | Pass | Repository lint |
| Focused changed/new unit tests | 126 passed | Metrics, grouping, notifications, portal contracts and accessibility source guards |
| `npm test` | 3,887 tests passed in first lane; 369 integration tests passed | Includes Postgres-backed integration checks; live-DNS lane excluded by the script |
| Existing `portal-executive-clarity.spec.mjs` | 5 passed | Dashboard and target detail; viewports 375, 768, 1024 and 1440 |
| Fresh production Vite build into `/tmp` | Pass | Both JS and CSS match the working-tree generated artifacts after the repository's tab normalization |
| `npm run safety` | Pass | Existing defensive execution checks |
| `git diff --check` | Pass | Tracked diff formatting |
| Refined findings component: axe WCAG A/AA checks | No violations in tested settled states | 390px dark/light and 1440px light; zero harness overflow at 390px. No screen-reader validation or full route matrix |
| `npm run test:contract` | **5 passed, 1 failed** | `FT-SHAPE-01`: `$.target.tags: undocumented field` |

The target-schema contract failure is already identified as pre-existing in `PROGRESS.md` RUX-016; its producer/schema were not changed in this diff. It is recorded as an existing verification gap, not counted as a new regression. A separate baseline checkout was not executed.

## Findings

### F01 — P1: Readiness chart crashes when scored history shrinks

**Location:** [score-trend.tsx:262](apps/web/react/src/components/charts/score-trend.tsx#L262), active-point state at lines 298–299 and the live-region rendering.

`TrendLineChart` retains the numeric `active` index across `points` changes. If the user focuses or hovers a later point and a refresh returns fewer scored runs, the index becomes invalid. The tooltip checks tolerate missing coordinates, but `pointDescription(active)` dereferences `points[index].runId` without a guard.

**Browser reproduction:** Render five scored runs, focus the chart, press End, then update the same component to two scored runs. React reported:

```text
Cannot read properties of undefined (reading 'runId')
```

The chart disappeared from the harness. In the portal, the nearest error boundary determines how much of the page becomes unavailable. History changes, refreshed score availability, or removal of records can trigger this.

**Correction:** Track selection by stable run ID, or synchronously derive a bounded index before every render. Guard the description lookup as well; an effect that resets the index after render alone cannot prevent this crash.

**Regression coverage:** Keep the chart focused while shrinking five points to two, replacing the selected run, and transitioning to one/no scored runs.

### F02 — P1: Failed notification emission is remembered as successful and cannot recover

**Location:** [notificationServiceAdapters.mjs:378](src/persistence/postgres/notificationServiceAdapters.mjs#L378), calls to `remember()` at lines 394 and 407.

The run/finding deduplication key is inserted **before** `emitNotification()` succeeds. A temporary database or persistence failure leaves the key in the set. Replaying the terminal hook suppresses that event, even though it was never durably recorded. The catch records a metric without enqueueing recoverable work. A failure in the completion event also skips high-severity emission for that invocation because both triggers share one try block.

**Executable reproduction:** A run subscribes to completion and high-severity alerts. Make the first emit throw, then call the same terminal hook again. Observed:

```text
calls: 2
persisted/successful triggers: [finding.high_severity]
safe_test.completed: missing
```

**Impact:** Completion and security alerts can be lost following a transient persistence failure. The existing retry worker cannot retry an event/attempt that was never created.

**Correction:** Persist an idempotent notification outbox entry with a tenant/run-or-finding/trigger identity, and process delivery from it. For an interim fix, distinguish in-flight from successfully recorded keys, remove failed claims, and isolate trigger failures. The process-local set also cannot provide deduplication across worker instances, restarts, or its full-set eviction.

**Regression coverage:** Fail event persistence once and replay; fail completion while retaining the high-severity alert; exercise concurrent invocations and separate hook instances.

### F03 — P1: New Postgres emitters put external sends on run/report critical paths

**Location:** [notificationServiceAdapters.mjs:394](src/persistence/postgres/notificationServiceAdapters.mjs#L394), [reportServiceAdapters.mjs:270](src/persistence/postgres/reportServiceAdapters.mjs#L270).

Both new paths await `emitNotification()`. That service awaits `finalizeNotificationDeliveryAttempts()`, which sends to subscribed destinations sequentially before persisting its event. The Postgres validation service awaits terminal hooks during finalization, probe-ingest completion, and the collection-window sweep. Report creation now awaits the same delivery chain before returning.

**Executable reproduction:** Register the new run hook with the actual delivery finalizer and three mocked webhook destinations, each taking 100ms. The hook took **307ms**, demonstrating that all three send delays are on the awaited path. Actual configured destinations can each consume the adapter's 10-second timeout. Three timed-out destinations can therefore add approximately 30 seconds to a terminal operation; this is an extrapolation from the adapter limits, not a live-provider timing measurement.

**Impact:** Notification-provider availability delays API responses and sequential sweeper progress. A slow completion notification also delays the subsequent high-severity finding lookup, allowing another run to advance that finding before the hook reads it. The dev-store path is fire-and-forget, so its tests do not expose this behavior.

**Correction:** Await durable enqueueing, then deliver asynchronously in a bounded worker. Bind the finding-publication identity into the queued event at publication time. Keep report and validation completion latency independent of provider timeouts.

**Regression coverage:** With a deliberately stalled sender, confirm finalization/report creation returns after enqueueing and that the delivery worker later records the outcome.

### F04 — P2: Older notification fetches overwrite newer channel state

**Location:** [notification-channels.tsx:322](apps/web/react/src/components/integrations/notification-channels.tsx#L322).

`load()` has no request-generation guard, cancellation, or session identity check before applying results. Once ready, it deliberately leaves `loadState` as ready, so Refresh remains enabled during another fetch. Manual refresh, connect completion, and prop-triggered loading can overlap.

**Browser reproduction:** Mount the panel, finish its initial fetch, click Refresh twice, resolve the newer request with a Slack rule, then resolve the older request with an empty list. The panel first offered “Add another Slack channel,” then reverted to “No channels connected yet.”

**Impact:** A saved channel can appear to vanish; stale failures can replace a successful refresh. Tenant/session safety should also be included in the guard, although cross-tenant leakage was not reproduced in the actual App lifecycle.

**Correction:** Apply results only for the latest request and current session identity; abort obsolete requests on cleanup. Expose a refresh-in-progress state separately from the initial loading state.

**Regression coverage:** Resolve overlapping requests in both orders, including an older failure after a newer success and a session change.

### F05 — P1: Refined grouping stalls large inventories with quadratic work

**Location:** [finding-groups.mjs:161](apps/web/react/src/lib/finding-groups.mjs#L161), [finding-groups.mjs:281](apps/web/react/src/lib/finding-groups.mjs#L281), target resolution at line 335.

For each finding, `findingIssueIdentity()` maps the full targets and checks arrays again. Aggregation also resolves each member with a linear target search. The result is approximately O(findings × targets), including repeated allocations. `FindingsRefined` computes both all-inventory and filtered grouping synchronously on the main thread; pagination happens afterward.

**Measured reproduction:** A single call to the shipped helper, with one finding per target, generated titles and one check:

| Findings and targets | Elapsed |
|---:|---:|
| 1,000 | 86ms |
| 4,000 | 961ms |
| 10,000 | 4,818ms |

These are local Node timings, not browser benchmark claims. They demonstrate the scaling defect. The repository already tests dashboard semantics with inventories of 10,000 groups and 33,334 findings; large inventories are relevant to this product.

**Impact:** Opening or filtering the Refined queue can block the browser for seconds. Memoization does not help the initial calculation or a changed filter/dataset.

**Correction:** Normalize context once, build target/check/group indexes once, and share them across identity and member aggregation. Avoid full-array mapping inside a per-finding helper. Consider worker/server aggregation for substantially larger inventories.

**Regression coverage:** Add a scale benchmark or operation-count assertion using production-sized records, covering both summary and filtered grouping.

### F06 — P2: Refined asset collapse hides member lifecycles and finding navigation

**Location:** [finding-groups.mjs:338](apps/web/react/src/lib/finding-groups.mjs#L338), [finding-group-detail.tsx:82](apps/web/react/src/pages/refined/finding-group-detail.tsx#L82), asset Actions column.

Multiple findings on the same asset are collapsed into one asset object. Only the representative's status, severity, owner and `findingId` survive; other IDs are retained as an array but not rendered as navigation choices. Status filters examine only the representative status.

**Executable reproduction:** Same check, outcome and target; one older critical closed finding and one newer high accepted-risk finding. The group correctly reported one closed and one accepted member, but its sole asset was classified closed and linked only to the closed finding.

**Impact:** The Accepted asset filter reports zero despite an accepted-risk finding on that asset. Users cannot directly open the omitted member from the grouped detail page. Shared targets across groups can also lose additional group membership because group IDs are derived from the collapsed asset representatives.

**Correction:** Preserve member records/lifecycle counts per asset. Define asset filtering as “has a member in this lifecycle,” and expose links to every member or an asset-member drilldown. Aggregate group membership from all findings.

**Regression coverage:** An asset with open, accepted and closed members, differing owners/groups, and explicit navigation to each finding.

### F07 — P2: Classic grouping counts unrelated group-scoped findings as one asset

**Location:** [findings-helpers.ts:365](apps/web/react/src/lib/findings-helpers.ts#L365), `countFindingAssets()` uses the same label fallback.

When there is no `target_id`, host or other asset label, the helper falls back to “Target-group scope” and uses that label as the asset identity. It does not include `target_group_id`.

**Executable reproduction:** Two same-title findings with no target, one scoped to `g1` and one to `g2`, produced:

```text
assets: [{ key: 'label:Target-group scope', label: 'Target-group scope' }]
```

**Impact:** Rule cards and detail summaries show one affected asset for two independent declared scopes. Group-scoped records are explicitly supported by the finding UI, so this is not just malformed input handling.

**Correction:** Use the recorded target group as scope identity, and fall back to finding ID when no recorded scope exists. Centralize this identity so card and detail counts agree.

**Regression coverage:** Two groups with otherwise identical findings, plus unscoped records and resolved target records.

### F08 — P2: Accepted-risk findings are labeled closed, with an invented closure time

**Location:** [findings-list.tsx:99](apps/web/react/src/components/findings/findings-list.tsx#L99).

`groupSlaMeta()` treats every group without open members as closed. It derives the supposed closure timestamp from `lastObservedAt`, which can be an update or observation timestamp rather than a closure event.

**Browser reproduction:** Render one `accepted_risk` finding, then choose Accepted. The same row showed **“CLOSED OCT 1, 05:30 AM”** in SLA and **“ACCEPTED RISK”** in Status. No closure was supplied.

**Impact:** Risk acceptance is presented as remediation closure, and the UI asserts an event time that was not recorded. This conflicts with the evidence-over-assumptions rule.

**Correction:** Show “No active SLA” or lifecycle-specific text for accepted risk. Show a closure date only for a closed/resolved lifecycle with an actual closure timestamp; keep observation time separate.

**Regression coverage:** Accepted-risk-only groups, mixed accepted/closed groups, and closed records without closure dates.

### F09 — P2: Group detail claims undated open findings are within SLA

**Location:** [finding-group-detail.tsx:242](apps/web/react/src/pages/refined/finding-group-detail.tsx#L242).

The summary says “Within SLA” whenever there are open members and no known breach. Missing opening dates produce no SLA deadline, but are treated as a successful SLA assessment.

**Browser reproduction:** An open high-severity finding without a date showed:

```text
Summary: Within SLA / No open SLA due date
Asset row: NOT DATED
```

**Impact:** Unknown SLA state becomes an affirmative compliance claim. The helper already exposes `undated`; the summary loses that distinction. Normal database rows are dated, but this remains a reproduced edge-case gap in the component's supported input.

**Correction:** Aggregate dated/undated open members separately. Say “SLA unknown” or “Partially assessed” when any required deadline cannot be computed.

**Regression coverage:** All-undated and mixed dated/undated groups, including a mixture with a known breach.

### F10 — P2: “Recently opened” sorts groups by their oldest finding

**Location:** [finding-groups.mjs:408](apps/web/react/src/lib/finding-groups.mjs#L408).

The recent comparator sorts descending by `earliestOpenedAt`. An alert first seen long ago but newly affecting another target ranks behind alerts with no recent activity.

**Executable reproduction:** Group A had January 1 and October 1 members; Group B had a September 1 member. “Recently opened” placed B before A. The Classic grouping helper correctly maintains and uses `lastOpenedAt` for the same sort label.

**Impact:** New affected assets are buried in the Refined triage queue.

**Correction:** Track the maximum member opening timestamp and use it for recent sorting. Keep the minimum for oldest/first-opened semantics. If the intended feature is recent observation, label it accordingly and use an observation timestamp.

**Regression coverage:** A long-lived group with a new member versus a newer group without subsequent members.

### F11 — P2: Bounded notification history is mistaken for “no events ever”

**Location:** [notification-channels.mjs:210](apps/web/react/src/lib/notification-channels.mjs#L210), [notification-channels.tsx:343](apps/web/react/src/components/integrations/notification-channels.tsx#L343).

Last delivery is inferred from the returned event feed. Postgres `listNotifications()` requests only the latest 100 events across all rules. If a channel's last event falls outside that feed, the new UI reports “No events yet” and says no matching event has fired since connection.

**Reproduction:** An existing rule has a delivery, followed by 100 newer events for other rules. Its attempt is absent from the payload, so `latestAttemptByRule()` returns no entry and the presentation helper produces that lifetime claim. The helper output and the repository's 100-event limit were verified; a 101-event database fixture was not inserted.

**Impact:** Older deliveries and failures disappear from the channel's status, giving operators incorrect delivery history.

**Correction:** Return authoritative latest delivery per rule, independently of the bounded feed. Until that API exists, say “No delivery in recent history” and disclose the loaded window.

**Regression coverage:** A rule whose most recent attempt is older than 100 events from other subscriptions.

### F12 — P2: Finding detail's new group-name cells depend on an unhydrated dataset

**Location:** [finding-detail-view.tsx:258](apps/web/react/src/pages/finding-detail-view.tsx#L258), route policy in [types.ts:102](apps/web/react/src/lib/types.ts#L102).

The new rule-wide asset table builds names from `data.targetGroups`, but `finding-detail` hydrates only targets, checks, findings and WAF action items. Target groups are not a core dataset either.

**Reproduction path:** Open a finding-detail deep link in a fresh session. Its route dataset selection omits target groups. Visit Findings first and then the same detail, and cached group names can be available. The policy/helper dependency was traced; this cold-versus-warm sequence was not separately browser-tested.

**Impact:** Group cells vary by navigation history and fall back to opaque IDs despite recorded names being available from the API.

**Correction:** Add `targetGroups` to the finding-detail route policy or return recorded group labels in the detail response. Handle a group-load failure explicitly.

**Regression coverage:** Cold deep link with an empty cache, warm navigation, and a failed target-group load.

## Implementation and verification gaps

These are separate from the 12 defects above. Some are explicitly acknowledged in the current progress tracker.

### G01 — Notification connections have no lifecycle controls

The panel creates enabled or disabled rules, but cannot enable, disable, update or remove an existing rule. Saving with “Turn this channel on now” unchecked leaves no UI/API path to turn it on. A mistaken destination, rotated secret, departed recipient, or duplicate rule requires an out-of-band intervention. This is acknowledged in RUX-015 and the new notification docs; it should remain an explicit release boundary. Add audited, tenant-scoped rule update/deactivation controls before presenting this as complete channel management.

### G02 — Two different grouping contracts ship under presentation variants

Classic uses `findingRuleKey()` based on the displayed outcome/title and intentionally merges checks. Refined uses `findingGroupKey()` containing check ID plus issue identity. The same two findings can therefore be one Classic rule and two Refined alerts. This is an implemented design difference, not classified here as an accidental regression. Document whether “rule” and “alert” intentionally represent different entities, or share one identity contract. Otherwise the “presentation only” comments obscure changes in counts and drilldown membership.

### G03 — New workflows lack durable browser regression coverage

No checked-in browser specs were found exercising the notification connect dialog, its loading/mutation races, the Refined variants, or a populated grouped-alert detail. The updated sweep visits a **keyless** grouped-detail route, which only validates the empty state. Existing unit tests cover useful helper behavior, but do not exercise the actual chart refresh state, group member navigation, inline schedule submission, or notification component lifecycle.

Add focused journeys for notification create/read/error/permission states, Refined policy creation with partial failures and exact target bindings, Refined runs with cancel/finalize gates, grouped alert navigation with multiple historical findings per target, and the chart refresh crash. Test both themes, mobile, keyboard interaction, and reduced motion where those affect behavior.

### G04 — Production emitter recovery/parity remains unverified

The new Postgres run-hook tests use stub repositories and a stub emitter. They do not validate the newly wired runtime from real finding publication through persisted notification events/attempts. The report-ready Postgres path likewise needs a targeted subscription/persistence test. The full integration suite passing should not be read as coverage of these newly wired scenarios.

Also reconcile the new documentation's claim that events are recorded only for subscribed tenants with the unchanged dev finding-creation emitter, which calls `emitNotification()` for high/critical findings without checking subscription. That inconsistency predates this implementation but is now described as if it had been resolved.

### G05 — Progress/docs and an existing contract gate need reconciliation

RUX-014 still lists old Cloudflare scope metadata as pending, although this diff changes it. RUX-015 lists the Teams notice as pending, while the new notice includes it. RUX-016 accurately discloses the target-tags contract failure, but that failure still means a documented API shape gate is red. Update the tracker to distinguish completed implementation, missing checked-in tests, live-provider drills, and remaining release decisions.

## Positive observations and product-boundary checks

- Generated JS/CSS are synchronized with the reviewed source; no stale build mismatch was found.
- Notification rule reads render destination previews, not raw Slack/Teams secret URLs. New validation rejects URL credentials and malformed email destinations; SMTP envelope checks reject CR/LF before opening a socket.
- Delivery remains opt-in. Teams payload-size rejection and removal of the unconditional placeholder portal action improve failure behavior.
- Exact target binding and backend permission checks remain in the shared policy/run mutation handlers. No new unmanaged traffic-generation path or bypass of SOC approval was identified in the reviewed changes.
- The chart preserves verdict-only history rather than inventing numeric readiness scores. Its keyboard reading and hidden table are useful, subject to F01.
- Shared table semantics, drawer background inertness, reduced-motion handling, source-load error states, and token-based styles have meaningful improvements. Sampled settled-state accessibility scans were clean; this does not establish full WCAG compliance.
- AWS scope selection reaches the existing `config.scope` normalization/poller, and CloudFront requests use `us-east-1`, consistent with the [AWS ListWebACLs documentation](https://docs.aws.amazon.com/waf/latest/APIReference/API_ListWebACLs.html). Provider setup verification here was sampled; credentials and live vendor deliveries were not exercised.

## Recommended correction order

1. Fix F01 and add the focused-state refresh regression.
2. Address F02/F03 together with durable enqueueing and bounded asynchronous delivery, then verify real Postgres emitter recovery.
3. Fix F05 with indexed aggregation before claiming large-inventory readiness for Refined findings.
4. Fix F04 and F11 so channel state and delivery history remain trustworthy.
5. Fix F06–F10 and F12; add mixed-lifecycle, group-scope, date, sorting and cold-navigation fixtures.
6. Resolve or explicitly retain G01–G05 as release boundaries, including the failing target-schema contract.

The report does not claim a live-provider security review, complete browser matrix, screen-reader certification, or production deployment validation. Findings labeled as source traces or controlled harness reproductions state their practical limits above.
