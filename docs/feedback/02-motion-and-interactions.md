# Subtle motion and overlay specification

## Skills already available

Use [Impeccable animate](../../.agents/skills/impeccable/reference/animate.md) through the [Impeccable skill](../../.agents/skills/impeccable/SKILL.md), plus the installed [interaction-design skill](/Users/checkred_admin/.agents/skills/interaction-design/SKILL.md). No additional animation skill was installed: these already cover the requested work. No animation library is necessary for this review or for basic transitions.

## Motion budget

Preserve `DESIGN.md` motion tokens: micro 90ms, fast 120ms, base 200ms, slow 300ms. Use the existing ease-out curve; exits may be quicker. A screen should have one active work indicator plus feedback for the user's latest action, not dozens of moving widgets. The live validation timeline is the signature motion opportunity.

| Moment | Proposed motion | User purpose | Reduced-motion equivalent |
| --- | --- | --- | --- |
| Button press | 90ms color/1px press feedback | Acknowledges action | Immediate color change |
| Dialog/drawer opens | 200ms fade + 4–8px movement, backdrop fade | Connects trigger to surface | Immediate visible dialog with focus |
| Tab changes | 150–200ms content crossfade, stable rail | Shows new context without jumping | Immediate content replacement |
| Metric refresh | Render actual value immediately; briefly emphasize genuine change | Highlights new evidence | Final value immediately |
| Probe step starts | Small progress indicator on active row | Shows real work | Static “Running” with start time |
| Response arrives | Brief 150ms row emphasis | Identifies new observation | “New response” text badge |
| Verdict resolves | Icon/text replaces running state after actual event | Marks evaluation completion | Instant icon/text update |
| Copy command/TXT/hash | “Copied” feedback for ~2 seconds | Confirms clipboard action | Same feedback, no movement |
| Filter changes | Preserve table scroll/selection, short fade if needed | Maintains context | Immediate stable rows |
| Expansion | Careful disclosure/grid-based expansion if justified | Reveals detail without taking over | Immediate expansion |
| Stream disconnects | Static reconnect banner with last event time | Prevents false “still running” certainty | Same banner |

## Avoid

No fake typewriter command output, simulated network logs, randomly incrementing request counters, moving scanlines, decorative pulse loops, bouncing status pills, confetti for governance approvals, or animation of every page section. Do not animate width/height/padding/margin for routine progress. Content must render visible before any animation class is applied.

## Shared overlay contract

- Title and description are programmatically associated; initial focus enters the dialog, Tab stays inside, and Escape/Close returns to its trigger.
- Define small confirmation, medium form, and wide evidence sizes. Keep 16–24px margins from viewport edges and a safe maximum height; content scrolls, footer stays reachable.
- Put Cancel first and the explicit action second; name destructive actions by verb and object. Avoid “OK” for remove/revoke/stop.
- Do not close a form automatically on a retryable server error. Retain input, focus the first error, and display per-field help.
- Preserve focus when polling updates the underlying page. A table refresh must not dismiss a popup or reselect a target.
- Long check catalogs belong in a dedicated searchable picker or step, not a modal with a 222-entry select and an offscreen primary action.
- Browser backdrop/Escape behavior must be intentional when unsaved input exists; a dirty-form decision is an interaction spec, not an excuse to block every close.

## Validation for implementation agents

375/768/1024/1440px; dark/light; keyboard-only; 200% text zoom; reduced motion; slow/offline response; no layout jumps; no hidden content; dialogs inside safe viewport bounds; no background scroll while modal is open. Measure frame behavior if using more than CSS opacity/transform. Existing route/tab/surface motion is reusable; the task is to improve feedback where it is missing, not layer a second animation system over it.

## Continuity and stable work — strengthened contract

- **Continuity:** evidence drawer closes with the inverse of its entry behavior; return to the originating row, selection, focus and scroll. If that row disappears, use the nearest meaningful list context and explain it.
- **Interruptibility:** Close/Escape/back/reversal works immediately during transitions. Do not disable navigation until a 200ms animation finishes. A pending real mutation has its own cancellation/outcome semantics.
- **Stable live updates:** maintain ordering during pointer/keyboard interaction; selection and focus never move to a new result automatically. If re-sorting is deferred, show updates available and let the user apply them. Important failures remain visible.
- **Honest metrics:** no counting from zero on entry or refresh. Display actual recorded value immediately; a short emphasis can mark a real value change. Announce meaningful milestones, not every digit.
- **Controlled emphasis:** motion belongs to the current user action and active validation step. No endless charts/counters/status pulses competing for attention. Functional progress remains bounded and has a static equivalent.
- **Preserved context:** opening evidence does not reset the inspector/filters; returning restores context even after a successful background refresh.
- **Performance:** no repeated layout transitions or rerender-driven entrance; content is usable while motion runs. Verify short-height mobile, reduced motion and slower devices.

These are proposed behavior requirements, not newly tested animation results. [Feedback/timing](16-feedback-responsiveness-and-daily-use.md) and [task gate](17-design-acceptance-and-handoff-gates.md) define verification. Host profile and the request → response → evaluation inspector are the distinctive interactions; decorative effects are secondary.


## Inspector motion supports task continuity

Apply one consistent entry/exit family across provider, finding, run, artifact and audit inspection. Close restores originating selection/focus/scroll even while data refreshes. Switching a member/check updates its answer in place; it does not stage a page-reveal sequence or steal focus. Navigation and execute buttons have separate semantics. [Inspector contract](19-contextual-evidence-inspector.md) is the workflow requirement; motion never conceals absent proof.
