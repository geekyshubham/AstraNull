# Design acceptance, usability study and handoff gates

2026-10-04. A proposed acceptance protocol, **not a test result or user study**. The supplied 6.5/10 UI and 8/10 handoff ratings are qualitative judgments from saved evidence, not empirical scores. Do not claim a higher rating because these documents are longer.

## G0 — contract and scope readiness

Before rendering a finished candidate:

- Authorized task states pages, allowed changes and commit/deploy scope.
- Product owner resolves count units, freshness, origin authorization, role/feature access and typed declarations.
- Frontend/backend agree available versus proposed fields using document 09.
- Spec version, illustrative dataset and pending surface option are recorded.
- Required unknown/error/pending states have valid data examples; unsupported controls are not mocked as working product behavior.

Code work is not authorized by the presence of this gate. This task remains Markdown-only.

## G1 — visual reference approval

Render R1–R5 from [reference specifications](11-reference-screen-specifications.md) in a separately authorized task. Review populated/empty/error/busy states, both themes, relevant desktop/tablet/mobile, zoom and long-content stress cases. Compare A/B surface choices with identical content and motion disabled.

Record artifact location, data/scope version, viewport, chosen shared surface/typography/control variants, approver/date and exceptions. User/product-design approval is explicit; engineering review verifies truth/feasibility. “Agent thinks it looks premium,” clean detector output and old screenshots do not approve a new reference.

If reference remains unapproved, label **Candidate**. No page author may independently fork shared fonts, colors, radii or status vocabulary.

## G2 — technical and evidence integrity

Required checks after future implementation:

- Data and count/list predicates agree across pagination, permissions and feature gates.
- Exact-target trace, provider family attribution and direct-check assurance remain evidence grounded.
- Keyboard/focus, text alternatives, contrast, touch targets, zoom and reduced motion are checked.
- 375/768/1024/1440px plus short viewport/keyboard and long-hostname conditions support the actual task.
- Every important loading, retained/stale, error, filtered empty, unknown, pending and disabled state has recovery.
- Refresh/updates do not steal focus, dismiss overlays, move selected rows under pointer or reset values.
- Shared component appearance matches approved references; differences are explained and recorded.
- New code is tested appropriately; no test merely mirrors arbitrary CSS values.

Technical checks do not replace G3.

## G3 — representative-user task study

Recruit in a later authorized research task, not through this documentation request. Proposed first formative cohort: 6–8 participants across customer security-owner and direct-check engineer roles. Include at least two mobile task sessions and keyboard use. Include both new and experienced customer users.

Use synthetic authorized evidence, not production traffic/credentials. Unmoderated real attack or provider messaging is not part of a usability study. Obtain appropriate recording consent; retain no secrets. Small cohorts diagnose usability issues; they do not statistically prove universal success.

### Tasks and provisional targets

| Task | Starting scenario / success criterion | Proposed target |
| --- | --- | --- |
| T1 Priority | Returning dashboard with multiple gaps. Identify highest-priority action, affected scope and reason. | ≥80% unassisted; median ≤30s; no wrong-target action. |
| T2 Unknown WAF | Profile with missing/stale/conflicting evidence. Explain why status is unknown and the safe next step. | ≥80% correct explanation; zero “unknown means protected” critical misunderstandings. |
| T3 Right check | Verified API target and incompatible alternatives. Choose suitable bounded check; review exact scope and bounds. | ≥80% unassisted within 2min excluding backend/DNS wait; zero unauthorized or wrong-target starts. |
| T5 Pending proof | New user declares target then proof stays pending. Find TXT instructions and understand what cannot run. | ≥80% unassisted; no invented need for cloud credentials/agents. |
| T6 Mobile/context | Open provider evidence, close, return to originating row; refresh while examining a prior check. | ≥80% completion; zero focus/selection/context loss. |
| T7 Recovery | Retained coverage with failed refresh; form with inline validation error. Recover without losing work/duplicate mutation. | ≥80% unassisted; no false success or duplicated start. |

Targets are proposals to calibrate in a pilot. Report raw n/N and median/range for this cohort; do not hide a failure behind a rounded percentage. Small-sample threshold example: with six participants ≥80% means at least five successes; one critical misconception still fails its zero-error gate. Observing an attempt to bypass an actual enforced gate is a comprehension/workflow finding, not proof backend controls failed.

### Measurement definitions

- **Unassisted success:** correct end state without facilitator instruction; ordinary visible help counts as interface use.
- **Assisted success:** facilitator supplies guidance; record separately.
- **Failure:** incorrect end state, abandonment, or time limit with no correct conclusion.
- **Critical error:** wrong target/tenant, assurance overclaim, exposing secrets, or unsafe execution decision. Record even if corrected later.
- **Hesitation:** pause ≥5s at a decision or repeated opening/backtracking; annotate context, not assumed incompetence.
- **Time:** include interface delays; record backend/DNS waiting separately rather than deleting it silently.
- **Understanding:** participant restates evidence/limits in their own words; clicking the expected link alone is insufficient.

Begin with neutral tasks, not “click the WAF evidence button.” Observe first; interview afterward. Capture first action, hesitation, wrong turns, assistance, perceived effort (1–7), interpretation, and end state. Add accessibility-specific sessions rather than pretending one keyboard run covers all users.

### Result record template

| Field | Record |
| --- | --- |
| Candidate/version | Artifact/spec/contract/fixture versions |
| Participant/context | Anonymous ID, role/experience, device/input |
| Task | T-ID, exact starting state |
| Outcome | Unassisted / assisted / failed, correct interpretation |
| Evidence | Steps, elapsed/interface/backend time, wrong turns, pauses |
| Critical issue | Description and source clip/note; no sensitive payload |
| Confidence/effort | Participant response, separate from success |
| Decision | Fix / retest / accepted limitation with owner/reason |

All result rows are **Not run** until research occurs. Never replace participants with agent self-ratings and call it a usability study.

## G4 — resolve and recheck

Any critical evidence/scope/security misunderstanding blocks acceptance. Repeated hesitation or wrong-route behavior prompts a hierarchy/copy/interaction change, not only smaller fonts or more animation. Retest affected tasks with new users where possible; document learning effects if reusing participants.

Every P1 has owner, decision, evidence and future task scope. Accepted limitations are explicit product decisions; budget exhaustion or detector silence does not close them.

## G5 — multi-agent handoff consistency

One shared foundation owner manages primitives/tokens; one contract owner manages data semantics; page agents own their explicitly assigned routes. Each authorized task references spec/reference/contract versions and dependent work. Parallel page work can start only after shared choices are known or clearly constrained by the existing default.

Delivery checklist for a later implementation:

1. Scope and acceptance IDs; chosen references.
2. Source/data changes, shared component impact and unresolved decisions.
3. Populated/empty/error/role screenshots with viewport/theme.
4. Technical and evidence verification results.
5. User-task result/remaining research status.
6. No hidden implementation placeholders, invented provider data or unsupported buttons.
7. Commit/deploy state exactly as authorized; no assumption that docs authorized code.

[Skills handoff](05-skills-and-handoff.md) supplies tooling. Approval and study steps are specified for future work, not a reason to stop this authorized document update.


## Task continuity acceptance — added 2026-10-04

Add these scenarios to future technical verification and representative research. All remain Not run here:

| ID | Completion criterion |
| --- | --- |
| T9 Evidence in context | From a finding row primary supporting proof appears after one activation; answer/limitations visible without mandatory run/tab/artifact traversal. |
| T10 Exact destination | Named schedule check opens that exact check; Support event View selects that event; cohort metrics carry matching visible filters. |
| T11 Scope continuity | From target, launch review inherits target/group; retest inherits original exact scope but rechecks current bounds/authorization. |
| T12 Return restoration | Inspector Close/browser Back restores list filters/search/sort/page/row/scroll and selected check; new events do not reorder under focus. |
| T13 Setup continuity | Failed delivery opens own attempt/config; provider/channel inspection returns to unfinished routing without losing safe draft. |
| T14 Snapshot continuity | Report preview/export retains caller scope; historical proof is not replaced by latest observations. |

Use ≥80% unassisted task completion as a provisional pilot target, report raw n/N, and require zero critical wrong-target/tenant/evidence/unsafe-action errors. Record task time, hesitation, re-selection and unnecessary route transitions. Do not optimize click counts by removing meaningful authorization or confirmation.

Documents 19–23 provide contracts; R6 is specification-only. Existing source-backed positive behavior must be retained. A freshly resolving route or clean screenshot alone does not prove these tasks are completed.
