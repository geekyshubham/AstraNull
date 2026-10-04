# Direct checks on a target — current-release execution flow

Current handoff scope: declare target → prove ownership → select applicable direct check(s) → review bounds → execute → inspect result/evidence on that target. No standalone execution-history, session-detail or orchestration-detail page is assigned.

## Placement

Target detail owns check selection, execution status and primary proof. An inventory Open/Verify action leads to that exact target; Check library can explain an exact check and return to the same target. Group views may link members or shared direct-check schedules, but do not force a separate launch workflow or broad execution list.

The target/check relationship stays explicit. Support one check first; “Run selected checks” or “Run all applicable checks” may select multiple bounded checks if supported by existing contracts. A multi-check selection remains target-centered, not a new mandatory product object.

## Interaction

1. **Scope already known:** show target value/ID/group context and ownership. Do not ask the user to choose the target again.
2. **Choose suitable checks:** show actual compatibility, setup and evidence limits; search/categories are secondary. Restricted and monitor-only items cannot become executable through the picker.
3. **Review:** exact target/check pairs, request/operation upper bounds, limits, exclusions, safety window and current authorization. Only missing required choices are requested.
4. **Execute explicitly:** start only after current gates pass. Starting does not imply a verdict.
5. **Inspect in place:** active check, actual operation/response, evaluation and recorded evidence. Completed checks remain selectable while others proceed.
6. **Next action:** review gap, assign supported remediation, review a scoped retest, or schedule that direct check when supported.

No fake progress, broad traffic generator, arbitrary commands, undeclared-origin probing, or unreviewed retest replay.

## Data contract

Backend may already store execution or batch identifiers for scheduling, correlation, cancellation and provenance. These remain technical references, not customer navigation requirements. Reuse authorized existing APIs where suitable; do not delete backend contracts or introduce a replacement executor through this UX handoff.

The frontend needs exact target/check identity, current gate, recorded phase, actual request count or Not recorded, result/evaluation reasons, observation time/source and authorized evidence. Missing schema fields must be agreed before the UI promises them.

## States

Ownership pending/expired, setup missing, incompatible kind, no selected checks, gate/window/rate/concurrency denial, starting, awaiting response, evaluating, completed with result, completed awaiting evaluation, inconclusive, failed transport, cancelled and source disconnected.

Failure retains target/check selections. The next action points to the actual missing gate. Cancel stops only the authorized direct work it describes and preserves prior evidence; no broad tenant emergency controls are introduced.

## Acceptance

- From a target, launch review never requires target/group reselection.
- One check result opens its primary evidence in one action, beside its explanation.
- Multiple selected checks never force navigation into separate history/session pages.
- New responses preserve selected prior check, focus and scroll.
- Retest carries exact finding/target/check, but rechecks current limits and authorization.
- Mobile places active check, response/result and relevant cancellation controls within the target workspace.
- No deferred operational/admin workflow, program request, privileged approval or execution console is assigned.

Use documents 19–23, the shared components, UI/UX Pro Max, Impeccable shape/clarify/harden/adapt/animate/polish and interaction-design.
