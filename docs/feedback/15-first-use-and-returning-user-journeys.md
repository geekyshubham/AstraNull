# First-use and returning-user journeys

2026-10-04. Proposed experience contract. Guides future design/implementation; no signup, targets, checks, messages or traffic were created for this addition.

## J1 — first useful outcome

Success is understanding one exact target's evidence, including inconclusive/unknown limitations. A green pass is not required to complete onboarding. Start without cloud credentials, a new named group, an internal agent or an environment.

| Stage | What the user sees / does | Outcome and recovery |
| --- | --- | --- |
| Empty workspace | “Add your first target” plus a short outside-in explanation | One primary action; optional how-it-works. No meaningless score grid. |
| Declare | Kind/value, optional tags/group; optional purpose/owner/criticality if a typed contract exists | Validate inline; default group handled transparently. Preserve input on failure. |
| Verify ownership | Exact hostname TXT/challenge, Copy and Check now; current gate and expiry | Authoritative proof state; DNS delay/timeout/expired challenge explained. Nothing assumes proof from UI entry. |
| Choose checks | Suitable bounded checks for that target and required setup | Show scope/compatibility/evidence limits; no 721-vector promise or automatic first target. |
| Review | Exact target/check pairs, request bound, schedule/window, exclusions and current gates | Deliberate Start; conflict/limit errors preserve plan. Only supported bounded direct checks are in the current flow. |
| Observe | Current check, recorded operation/response/evaluation, event time | Disconnect/timeout/inconclusive distinct. Can inspect prior steps while work advances. |
| Understand | Plain conclusion, why, limits, supporting evidence and next action | Passed this check or gap/inconclusive; untested dimensions remain visible. |
| Continue | Add another target, set a suitable schedule, assign remediation, or exit | No forced connector/notification setup or fabricated completion confetti. |

## First-use design rules

- Show a concise progress trail only where it reflects the real sequence; saved state resumes at the real ownership/run gate.
- DNS proof is an asynchronous wait, not a UX failure. Explain where to publish, what was last checked and when retry is permitted. No invented countdown to verification.
- A target can be retained while proof is pending. Return via Targets or the profile; avoid trapping onboarding in a modal.
- Checks are suggested from actual compatibility/contracts; declaration-only checks are clearly labeled and do not simulate traffic.
- A task can end with inconclusive evidence and a useful next step. Do not encourage uncontrolled extra traffic to get a pass.
- Role-limited users can inspect evidence and see who may configure/run; they are not invited to escalate their own role.
- Typed owner/service metadata is a separate backend prerequisite; onboarding must remain usable without pretending those fields already exist.

## J2 — returning security owner

Arrival answers: What changed? What matters most? Is work currently running? What is unknown/stale?

1. Dashboard uses real unresolved gaps and current activity; confirmed changes use a defined baseline.
2. Open the most important gap to a target/finding profile with original evidence and declared business context.
3. Inspect the provider or readiness dimension in one activation.
4. Assign/plan remediation where supported; risk/closure decisions use explicit authorization and rationale.
5. Review a bounded exact-target retest; partial/inconclusive outcomes do not clear siblings.
6. Return to the same cohort, sort, selected row and scroll.

If “since your last visit” is unsupported, show “Compared with assessment on [recorded date]”; do not manufacture a baseline from browser visit time. New-to-you indicators must not imply new findings without evidence.

## J3 — returning validation engineer

Start at saved/current target cohort → find pending/stale compatible work → select the exact target → review a bounded plan → follow selected-check trace → explain result → return to inventory.

Saved view label and active filters remain visible. Back is contextual, not a dashboard reset. Live rows do not reorder under pointer/focus. An engineer can keep a completed check selected while the next runs; Jump to latest restores following explicitly.

## J4 — mobile incident review

Dashboard urgent gap or deep link → exact target/context → latest successful evidence and latest failed attempt → provider inspector → relevant finding/direct-check inspector. One primary action is visible; technical details are available on demand. Read-only and direct-check cancellation capability must be honest for the current role.

No desktop-only hover or far-right action is required. Interrupted network/switching tabs preserves target and selected evidence.


## Scenario record for future testing

For each journey record persona/role, starting route/state, intended target, permitted action, seeded evidence, successful end state and known asynchronous gates. Test pending proof, invalid input, empty compatibility, rate/concurrency conflict, stale/no data, stream disconnect, partial remediation and read-only roles.

[Acceptance protocol](17-design-acceptance-and-handoff-gates.md) measures completion, mistakes and hesitation. Do not record these journeys as passed until representative users have exercised rendered candidates.
