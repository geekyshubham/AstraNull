# Shared popup, dialog, inline-form and disclosure review

Observed interactions are in [dialog observations](evidence/dialog-observations.json) and [provider/channel observations](evidence/extra-dialog-observations.json). The review opened and dismissed forms/confirmations; final destructive actions, live traffic and external messages were not submitted.

## Specific findings

- [P2] **Footer spacing:** The [Slack connect screenshot](evidence/dialog-integrations-connect-slack.png) shows the primary action crowding the dialog’s bottom edge. Check the actual body/footer scroll/padding and keep a complete 16–24px safe inset. Do not fix only the screenshot by hiding actions.
- [P2] **Uneven form width:** [Create group](evidence/dialog-target-groups-create-target-group.png) leaves the only Name input narrow in a much wider dialog, while explanatory copy is long. Choose a small creation-dialog size or let its form field use the intended content measure.
- [P1] **Direct-check selection:** keep the target selected and show only applicable bounded checks; avoid an oversized catalog dialog. Follow the [direct-check flow](direct-check-execution-flow.md).
- [P2] **Inline versus modal consistency:** Add target on Targets and New rule on Notifications expand inline; Add target on Target groups opens a modal. These can be appropriate, but the new form must get a visible heading and focus, and Cancel/Close must be consistent. Do not report an inline form as a broken popup just because there is no native dialog.
- [P2] **Provider branching:** Read-only connection, manual metadata and single-domain declaration must use clear names. No provider modal should show a live capability that its actual backend lacks.
- [P1] **Security decisions:** Remove target, archive schedule, cancel/finalize run, accept risk, close finding, disable connector, retry deliveries, suspend tenant, revoke key and kill-switch actions need precise impact and scope. A generic confirmation cannot replace backend authorization or missing artifact gates.

## Overlay inventory and future requirements

| Surface | Overlays / inline flows reviewed or source-inspected | Recommended emphasis |
| --- | --- | --- |
| Dashboard | Tabs, drill-down links, refresh, theme; no existing coverage popup | Domain breakdown is proposed; unknown/stale/failure must be explicit. |
| Targets | Inline Add target; Edit tags; Remove | Exact endpoint, tag constraints, ownership next step. |
| Target groups | Create group; Add target | Minimal required fields, optional settings progressive. |
| Group detail | Add target; CSV import; DNS-zone import; member direct-check/verification actions | Exact scope, atomic import preview, no first-domain fallback. |
| Target detail | Run all checks review, category/detail disclosures, evidence and tabs | One target workflow, traceable request-to-verdict. |
| Library | Vector Review inspector; filter dropdowns; mapped check detail | Evidence limits and runnable mapping. |
| Schedules | Create; Archive; pause/resume/cadence source actions | Scope/check/time/review; editable timing, explicit series behavior. |
| Findings | Accept risk; Close; triage/retest/export source paths | Original evidence, decision rationale and lineage. |
| Integrations | Add provider/domain/manual snapshot; nine setup guides; four channel setup dialogs; edit/disable | Least access, capability truth, redaction and footer space. |
| Notifications | Inline New rule; retry/redrive preview and live confirmation | Configured versus delivered; inspectable affected attempt set. |
| Settings | Four tabs; access/security/retention forms; sensitive success states source-inspected | One-time secrets, impact, units, no forced credential generation during review. |
| Public | Login/intake/status/invitation forms | Mode-aware auth, validation, next step and safe recovery. |

## Shared implementation contract

Reuse native FormModal/ConfirmModal where appropriate. Title/description associated; visible Close; initial focus; trap; Escape; intentional backdrop behavior; restored focus; scrollable body with reachable footer; labels/help/errors associated; retained values on server failure; disabled and busy states; no double submit. Dirty-form behavior must be explicit. Select dropdowns should not clip inside scrolling dialogs: use the existing placement/portal mechanism, not arbitrary z-index values.

Review every category under dark/light, narrow viewport, keyboard, text zoom, slow response and reduced motion. Future agents should add workflow-specific checks, not tests that merely copy CSS values. No code or commits are requested by this review.

Skills: UI/UX Pro Max, Impeccable layout/harden/adapt/clarify/animate/polish and interaction-design; [actual references](05-skills-and-handoff.md).

## Shared visual/task handoff

Use [reference specifications](11-reference-screen-specifications.md), [component standard](12-component-visual-specification.md), [responsive budgets](14-content-and-responsive-task-budgets.md) and [feedback/navigation](16-feedback-responsiveness-and-daily-use.md). Page focus: R4; T6 focus/scroll continuity and T7 error/dirty-form recovery. See [acceptance gate](17-design-acceptance-and-handoff-gates.md). All references remain proposed until rendered and explicitly approved; user task results are Not run.
