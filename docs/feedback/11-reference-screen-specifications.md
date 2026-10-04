# Reference screen specifications and approval register

Added 2026-10-04. **Proposed specifications; none is an approved visual reference yet.** This Markdown-only task defines reproducible compositions and realistic states. Existing screenshots show the current UI, not the finished design. Rendered candidates and explicit approval belong to a later authorized design task.

## Shared frame

Desktop reference: 1440 × 1000 CSS pixels. Existing sidebar 248px, topbar 64px. Main area 1192px; 32px side gutters leave 1128px. Twelve-column grid: 72px columns and 24px gutters; 8/4-column composition yields 744px / 360px with a 24px gap.

Mobile reference: 375 × 812; 16px side gutters leave 343px. Topbar min-height 56px, then 20px top gutter. Tablet: 768 × 1024, 24px gutters, collapsed sidebar. Long text can grow; reference geometry must not clip translation or zoom.

Use [component specification](12-component-visual-specification.md), [surface decision](13-surface-color-decision.md), and [content/mobile budgets](14-content-and-responsive-task-budgets.md).

## Shared illustrative dataset

These are invented design scenarios, **not tenant results or an implemented test fixture**. Label rendered candidates Example workspace. Never use the hospital-assessment figures as live KPIs.

- 28 active declared targets: 24 distinct hostnames and four IP targets; four declared groups.
- Declared roles: 12 website, eight API, six login hosts, four unclassified hosts. Roles overlap; totals are not additive.
- WAF buckets across 24 hosts: 12 detected, three not detected, two inconclusive, four not checked, three stale. Stale retains its previous observation in detail but is not fresh coverage.
- CDN buckets: 16 detected, three not detected, one inconclusive, two not checked, two stale.
- Five declared critical targets have open findings; this is not a confirmed business-service count.
- Two targets with direct checks running; one confirmed comparable regression.
- Profile: checkout.example.com, declared Login + API, declared Critical, Payments team, ownership verified. Illustrative CDN Provider A, WAF Provider B; origin hosting unknown.

Freshness/window/version are future contract inputs; these examples authorize no new policy defaults.

## R1 — returning-user dashboard

~~~text
Readiness overview                             [Run validation] [Refresh]
Last evidence: 2h ago · Example workspace

28 declared targets | 5 critical targets with gaps | 2 running | 1 regression

Service-role coverage                         What to fix first
All hosts · Website · API · Login · Unknown    Origin access gap · Payments
WAF / CDN counts + unknown/stale               3 affected targets · [Review]
[Open filtered targets]                       WAF behavior gap · API team

Recent validation                             Changes since last assessment
Exact target · current step · event time       Confirmed change · [Evidence]
[Open live view]                               [View risk trends]
~~~

**Composition:** four headline facts use one ruled row, not decorative towers. Coverage takes eight columns, priority actions four. At most three visible priority actions; View all opens the queue. Concentration/history belongs to Risk trends. No large donut/path diagram precedes decisions.

**Populated:** show login/API gaps even when overall detection looks reassuring. Each count opens matching inventory; the critical target count deduplicates finding instances.

**Empty:** “Add your first target,” one short explanation and Add target. Optional How validation works disclosure. Hide meaningless zero-grid and score.

**Partial/error:** unavailable coverage occupies its reserved region with Retry; loaded findings/live work remain. Retained data has as-of time. Whole-page failure has one persistent recovery state, not zero metrics.

**Approval checks:** gap, unknown coverage and running work are recognizable before technical details.

## R2 — desktop host protection profile

~~~text
Targets / checkout.example.com                        [Run validation]
Ownership verified · Login + API · Critical            [Edit context]
Owner: Payments team · Group: Checkout

WAF: Provider B · detected · 2h ago [How identified]    Priority gap
CDN: Provider A · detected · 2h ago [How identified]    Declared origin reachable
Origin hosting: Unknown             [Why unknown]     [Evidence] [Review retest]

Dimension        Result                    Coverage / freshness
Application      Gaps found                8 of 12 evaluated
Origin lockdown  Gaps found                declared endpoint only
DNS              Insufficient evidence     2 inconclusive

[Overview] [Validate] [Findings] [Changes & history]
~~~

**Composition:** one identity/ownership summary. Attribution is a definition list; hosting has no shield/success style. Dimension rows align label/result/coverage. Validate owns the selected-check inspector.

**Populated:** application 8/12 evaluated = four pass, three fail, one inconclusive, four not run. Vendor detection is neutral. Gaps remain visible beside passing checks.

**Unmeasured:** verified host shows Not checked and a suitable bounded plan; no green placeholder or 0% efficacy.

**Partial/error:** unavailable source keeps historical observation with age and latest failure. Detail failure never defaults origin to Not exposed.

**Approval checks:** supporting provider evidence opens in one activation; application success cannot make untested DNS or network checks appear passed.

## R3 — inventory

~~~text
Targets                                           [Add target]
[Search declared targets] [Ownership] [Service role] [More filters]
View: Needs validation · 9 matching targets        [Save view, if supported]

Target / purpose        Ownership        Protection observation     Action
checkout.example.com    Verified         WAF B / CDN A · 2h ago     [Open]
API + Login · Critical                   Origin hosting unknown
api.example.com         Pending proof    Not checked                [Verify]
~~~

**Priorities:** target, ownership/next gate, WAF/CDN observation, last evidence, primary action. Owner/criticality/purpose may share one secondary line. Group/source/added/IDs are optional columns or detail. No repeated manual/manual or hostname/hostname.

**Populated:** total declared targets versus unique hosts are explicitly distinct; totals are independent of page size.

**Empty scope:** Add target. **No matches:** filters and Clear filters, not “add your first target.” **Error:** retained rows plus stale/error/retry, or reserved table error.

**Approval checks:** Open/Verify discoverable without scrolling to the last column; focusable rows/links are predictable.

## R4 — standard dialog and evidence drawer

Form width 560px; small confirmation 440px; evidence maximum 880px. At 375px: width 343px or safe full-screen evidence sheet. Header/body/footer padding 24px desktop / 16px mobile. Viewport-safe height; body scroll; footer reachable with software keyboard.

~~~text
Create target group                              [Close]
Targets sharing validation settings.

Name                                             (full content width)
[Checkout                                       ]
[More options]

                                        [Cancel] [Create group]
~~~

**Populated:** visible label, full-width field, 8px label gap, 16px field gaps. **Empty:** required input editable; any disabled prerequisite has a reason. **Error:** inline Enter a group name, retained value, field focus. Primary action never touches bottom edge.

Evidence drawer uses source/scope/time, recorded signals and Open source run. Close returns to the same row/scroll/focus. Avoid nested modals for ordinary details.

**Approval checks:** focus trap/restoration, Escape/backdrop/dirty handling, footer inset, long errors, zoom and interruption.

## R5 — mobile profile and live evidence

~~~text
[Back to Targets]                             [More]
checkout.example.com
Ownership verified · Critical · Login + API
[Run validation                                ]
Priority gap: declared origin reachable         [Review]

Protection observations
WAF Provider B                         [Evidence]
CDN Provider A                         [Evidence]
Origin hosting unknown                  [Why]

Readiness dimensions
Application · gaps found                8/12 evaluated
Origin · gaps found                      declared scope
DNS · insufficient evidence              [Details]

[Overview] [Validate] [Findings] [History]
~~~

**Task order:** identity/ownership → primary action → urgent gap → observations → dimensions. No decorative chart displaces the action. Large text may increase height; do not enforce a clipping one-screen rule.

**Validate:** active check/last event first, Request/Response/Evaluation/Evidence, reachable queue. Stop has consistent position while active; pause auto-scroll is a separate action. Never require a ten-column table for the main task.

**Unmeasured:** Verify ownership or Run suitable checks with the gate explained. **Disconnected/error:** stale/reconnect banner and retained selected evidence. Software keyboard cannot obscure submit/Stop.

**Approval checks:** provider evidence and Back work without hover; returning preserves context.

## Approval register

| Reference | Required candidates | Status |
| --- | --- | --- |
| R1 Dashboard | Populated/empty/partial error, dark/light, desktop/mobile | Specification only |
| R2 Profile | Populated/unmeasured/source error, both themes | Specification only |
| R3 Inventory | Populated/no targets/no matches/refresh failure, three layouts | Specification only |
| R4 Dialog/drawer | Default/error/busy/dirty close, desktop/mobile/zoom | Specification only |
| R5 Mobile | Populated/proof pending/disconnected validation, both themes | Specification only |
| R6 Contextual inspector | Primary proof/missing/denied/stale/member switching, desktop/mobile | Specification only |

Later approval record: artifact location, viewport, dataset/version, chosen surface option, reviewer/date, exceptions, shared-spec version. User/product design approves; frontend/backend check data and interaction feasibility. Do not label current screenshots or these wireframes as approved finished designs. [Acceptance gate](17-design-acceptance-and-handoff-gates.md) defines promotion.


## R6 — contextual investigation composition

Additional proposed reference; not rendered or approved. From a finding queue or affected-target list, one evidence activation reveals the adjacent inspector:

~~~text
Open findings · critical scope · same filters/page
Finding/member list             Exact target · check · observed time [Close]
> checkout.example.com          Outcome and why; limits
  api.example.com               Expected vs observed
                                Recorded operation and response summary
                                Source / freshness / integrity
                                [Review retest] [Open full investigation]
                                Advanced technical details
~~~

Answer and supporting summary appear together on initial load. Four technical selectors cannot hide the basic explanation. On mobile, safe full-width inspector restores the same originating row/scroll on close; member Next/Previous stays within the applied cohort.

Required candidates: populated primary proof; missing refs; read-denied source; unavailable partial data; original finding plus later pass; active trace with previous check selected; stale refresh; both themes/keyboard/zoom. Follow documents 19–23 and update the approval register only after future rendered review.
