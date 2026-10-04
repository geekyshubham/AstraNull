# Live direct-check evidence on the target

## Current-release placement

Live evidence lives in the target's direct-check workspace. The user selects the target/check, performs an authorized bounded operation, and sees what happened, why and the next step there. There is no separate execution-list or orchestration-detail handoff page.

Existing execution records/correlation/activity APIs can remain technical infrastructure. Their IDs are source metadata, not an extra product navigation tier. This handoff does not change backend APIs or authorization.

## Selected check inspector

~~~text
checkout.example.com · WAF response check
Running · latest recorded event 2s ago

Checks on this target          Selected check: purpose and scope
✓ DNS reachability            Expected versus observed behavior
→ WAF response check          Actual request / operation
· TLS posture                 Recorded response / transport state
                              Evaluation and evidence limitations
                              Source, observation time and artifact
[Run selected checks]          [Review retest, if permitted]
~~~

Answer and primary evidence appear together. Request/Response/Evaluation/Evidence panels are optional technical depth, not four mandatory steps to understand the outcome. [Contextual inspector](19-contextual-evidence-inspector.md) defines relationships and Back/Close behavior.

## What to show

| Field | Required rendering |
| --- | --- |
| Target/check | Exact authorized endpoint, check identity/version and permitted protocol/port/path. |
| Operation | Actual engine/method, recorded timestamp, timeout/bounds, permitted headers/signals. |
| Response | Actual response status or transport result, timing/summary, allowed metadata. |
| Evaluation | Expected behavior, observed signal, rule/version/reasons, scoped conclusion and limits. |
| Count/progress | Actual requests/operations sent versus reviewed bound; unknown is Not recorded. |
| Evidence | Exact originating event/artifact, observation time/freshness and real integrity state. |
| Work state | Planned, starting, receiving, evaluating, complete, inconclusive, denied, cancelled or disconnected. |

A refreshed UI timestamp is not a worker event. A timeout is not a blocked request. Completed execution without evaluation is not a pass. A detected provider is not efficacy evidence.

## Commands and protocols

If the actual engine invoked curl, show the sanitized recorded invocation/version. If it used Node HTTP, DNS, TCP or TLS tooling, label that engine and its structured operation. A reconstructed curl display is **Equivalent request, not the executed command**.

Do not fabricate terminal stdout, animate fake typing, or allow arbitrary user commands. Non-HTTP checks retain appropriate protocol fields instead of forcing everything into curl.

## Retention and redaction

Current metadata-only boundaries remain. Render recorded permitted response/request metadata and matched signal summaries. Raw bodies require separate privacy/retention/redaction authorization; they are not implicitly permitted by a terminal-like view.

Never expose cookies, tokens, webhook credentials, signed query secrets or unsafe payloads in client state, clipboard, logs or export. Inspection is read-only; exporting or starting a retest is explicit.

## Live behavior

- Keep a completed check selected while another executes; Follow active/Jump to latest is deliberate.
- Pause auto-scroll affects the viewport, not execution.
- Preserve target/check, selection and open inspector during polling.
- On disconnect, show last event and source age; reconnect/recover with deduplication and stale-response guards.
- Deferred checks show actual gate/resume facts, not an invented ETA.
- Bound/virtualize long trace data. Announce milestones politely, not every log line.
- Cancellation, where supported, is scoped to this target/direct work and explains prior evidence retention.
- Error/retry retains check selection and never silently switches scope.

Use existing authorized event/activity contracts after verifying their semantics. Streaming is optional future implementation, not an existing promised endpoint. No alternate execution system is introduced by this documentation.

## Motion

Brief emphasis on new recorded evidence, one small active-work indicator, stable result replacement. Actual values display immediately. No moving scanlines, fake count-up, or reordering under pointer/focus. Reduced motion has complete static status.

## Acceptance

1. Target → check → recorded operation/response/evaluation/source is understandable without leaving the target.
2. Primary evidence opens in one activation; absent, forbidden and failed source reads remain distinct.
3. Engine is accurate and reconstructed commands are labeled.
4. Inconclusive/transport failure/unknown counts/stale sources do not become reassuring assurance.
5. Scope and authorization are rechecked before execution/retest; inspection never starts traffic.
6. Selection/focus/scroll survive live updates and mobile evidence Close.
7. Bounded direct checks do not establish volumetric capacity.

Use [direct flow](direct-check-execution-flow.md), [profile](06-host-protection-profile.md), [engineering](09-engineering-consultation.md), [inspector](19-contextual-evidence-inspector.md), and the shared motion/component/task gates.
