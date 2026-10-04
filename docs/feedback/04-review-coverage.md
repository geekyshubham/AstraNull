# Current-release review coverage and evidence

Scope follows [current-release handoff](24-current-release-scope.md): 28 customer/public page reviews plus embedded target/direct-check flows. Deferred operational/admin pages and standalone execution pages are not assigned.

## Provenance and limits

The original review used the local synthetic demo with UI at 127.0.0.1:5173 and isolated API/store at 127.0.0.1:3102 under /tmp/astranull-ux-review. Current source was later consulted for data/task continuity. This is not a fresh live click-through or representative-user study. Retained observations are filtered to the current page scope; internal direct-check execution IDs may remain as historical evidence metadata.

Setup incident: an initial seed used the wrong environment variable and replaced the ignored repository .data/astranull-dev.json with demo data. This was disclosed. Subsequent review used ASTRANULL_DEV_DATA_DIR and an isolated store. No backup of the previous ignored store was found; source restoration was not restoration of that data.

No current documentation update performed live probes, provider operations, external messages, application changes or commits. Existing screenshots are baseline evidence, not approved final design. Source-only auth/recovery/context behaviors are distinguished from the earlier saved screenshots.

## Current page ledger

| Page | Review | Baseline evidence |
| --- | --- | --- |
| Dashboard | [dashboard.md](dashboard.md) | [Desktop](evidence/dashboard-desktop.png) |
| Targets | [targets.md](targets.md) | [Desktop](evidence/targets-desktop.png) |
| Target groups | [target-groups.md](target-groups.md) | [Desktop](evidence/target-groups-desktop.png) |
| Target group detail | [target-group-detail.md](target-group-detail.md) | [Desktop](evidence/target-group-detail-desktop.png) |
| Target detail | [target-detail.md](target-detail.md) | [Desktop](evidence/target-detail-desktop.png) |
| Vector library / check library | [checks.md](checks.md) | [Desktop](evidence/checks-desktop.png) |
| Check detail | [check-detail.md](check-detail.md) | [Desktop](evidence/check-detail-desktop.png) |
| Test policies / validation schedules | [test-policies.md](test-policies.md) | [Desktop](evidence/test-policies-desktop.png) |
| Validation schedule detail | [policy-detail.md](policy-detail.md) | [Desktop](evidence/policy-detail-desktop.png) |
| Findings queue | [findings.md](findings.md) | [Desktop](evidence/findings-desktop.png) |
| Finding detail and remediation | [finding-detail.md](finding-detail.md) | [Desktop](evidence/finding-detail-desktop.png) |
| Grouped finding detail | [finding-group-detail.md](finding-group-detail.md) | [Desktop](evidence/finding-group-detail-desktop.png) |
| Evidence artifact detail | [evidence-detail.md](evidence-detail.md) | [Desktop](evidence/evidence-detail-desktop.png) |
| Reports | [reports.md](reports.md) | [Desktop](evidence/reports-desktop.png) |
| Report detail | [report-detail.md](report-detail.md) | [Desktop](evidence/report-detail-desktop.png) |
| Integrations | [integrations.md](integrations.md) | [Desktop](evidence/integrations-desktop.png) |
| Notifications | [notifications.md](notifications.md) | [Desktop](evidence/notifications-desktop.png) |
| Audit log | [audit.md](audit.md) | [Desktop](evidence/audit-desktop.png) |
| Settings | [settings.md](settings.md) | [Desktop](evidence/settings-desktop.png) |
| Support | [support.md](support.md) | [Desktop](evidence/support-desktop.png) |
| Plan & usage / Billing | [subscription.md](subscription.md) | [Desktop](evidence/subscription-desktop.png) |
| Release evidence (auditor) | [release-evidence.md](release-evidence.md) | [Desktop](evidence/release-evidence-desktop.png) |
| Public landing | [landing.md](landing.md) | [Desktop](evidence/landing-desktop.png) |
| Customer sign-in | [login.md](login.md) | [Desktop](evidence/login-desktop.png) |
| Request access | [signup.md](signup.md) | [Desktop](evidence/signup-desktop.png) |
| Access request status | [signup-status.md](signup-status.md) | [Desktop](evidence/signup-status-desktop.png) |
| Invitation password setup | [set-password.md](set-password.md) | [Desktop](evidence/set-password-desktop.png) |
| Missing or unavailable route | [not-found.md](not-found.md) | [Desktop](evidence/not-found-desktop.png) |

## Evidence and future verification

- [Current page observations](evidence/route-observations.json) and [review index](evidence/page-review-index.json).
- [Dialog observations](evidence/dialog-observations.json), [provider/channel observations](evidence/extra-dialog-observations.json) and [tabs](evidence/tab-observations.json).
- [Viewport/theme observations](evidence/state-observations.json): historical retained checks, not a new accessibility certification.
- [Task contracts](21-all-page-data-and-task-review.md), [data semantics](23-data-meaning-and-workflow-state-contract.md), [direct-check flow](direct-check-execution-flow.md) and [future acceptance](17-design-acceptance-and-handoff-gates.md).

Current scope prioritizes exact target → direct check → evidence → remediation in place. Each page needs future permitted-state, error/empty, mobile/keyboard and task-comprehension validation. No feature is complete merely because a handoff exists.
