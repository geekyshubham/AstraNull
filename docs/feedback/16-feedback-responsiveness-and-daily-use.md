# Feedback, perceived responsiveness and daily-use controls

2026-10-04. Shared proposed behavior for every page, dialog and live view. No new persistence, mutation endpoint, global search or undo feature is implied.

## Feedback decision matrix

| Event | Default placement | Required behavior |
| --- | --- | --- |
| Field invalid | Inline at field, form error summary for multiple failures | Associate error/help; preserve values; focus first error on submit. |
| Small successful save | Inline near saved state | Show Saved with authoritative value; no toast and banner duplication. |
| Copy ID/TXT/redacted request | Local Copied feedback | Approximately 2s; screen-reader message; no result claim if clipboard fails. |
| Completed action elsewhere | Nonblocking toast with useful object/action | ~5s default; pause while hovered/focused, retain result in activity/state; never the only proof. |
| Data unavailable / refresh failed | Persistent section banner | Preserve available data, as-of and Retry; service/error distinction. |
| Stream disconnect / deferred execution | Persistent work status | Last successful event, actual recorded gate; no fake active state. |
| Destructive/security decision | Scoped confirmation before action, inline authoritative outcome after | Exact object/consequence/reason where supported; server permission/state remains authoritative. |
| Long operation | Inline busy/progress status | Immediate acknowledgment; actual counts only; cancellation only if supported. |
| Permission/gate denial | Persistent contextual reason | Identify next permitted step; no role escalation or inaccessible controls without explanation. |
| Important ongoing system state | Scoped persistent banner | Kill switch/source failure remains until resolved; never a disappearing toast. |

Toast is a delivery mechanism, not an evidence record. Critical failures/decisions remain discoverable in current state and audit. Do not show three simultaneous copies of the same success.

## Response-time behavior targets

These are proposed UX targets, not measured application performance:

- Within 100ms of activation: visible pressed/selected/busy acknowledgment from actual handler acceptance. Never manufacture backend success.
- First load exceeding ~300ms: skeleton matching expected layout. Avoid a split-second loader flash for immediate responses; content is not delayed to “feel meaningful.”
- Refresh: retain data and geometry, show refreshing status; no zero reset, whole-page blank or count-from-zero.
- After ~3s without response: concise “Still loading [section]”; keep controls/context where safe.
- After ~10s without response: offer supported retry/cancel/recovery and clear status; respect backend timeout and distinguish request uncertainty from confirmed failure.
- Unknown mutation outcome: reconcile authoritative state/idempotency before retry. Do not duplicate target creation, starts, exports or deliveries.
- Logs/polling: label execution event time versus refresh time; preserve selected check and stable keys. A busy indicator does not prove ongoing worker execution.

No artificial minimum latency or simulated progress. Measure response acknowledgment and main-thread work in the future implementation, including slow devices.

## Skeleton geometry

Dashboard: reserve headline row, coverage table footprint and three priority rows. Profile: reserve identity/observation/dimension regions; never show fake green states. Inventory: header/filter rail and five neutral row placeholders, with stable action footprint. Dialog: preserve shell/title/body/footer; loading a selector does not resize the overlay repeatedly.

Skeletons are aria-hidden with one polite status label. Reduced motion uses static placeholders. Region height may grow with real content; avoid arbitrary fixed heights that crop errors/translation. Images/logos have intrinsic size and no layout jump.

## Dirty forms and interruption

- Track changes against last authoritative saved values; typing then restoring the original value is clean.
- Clean form: Close/Escape/backdrop returns focus immediately.
- Dirty form: present Keep editing / Discard changes. If explicit Save is supported, offer Save only with real validation and error retention. No automatic saving of secrets or security decisions.
- A pending mutation cannot be undone by closing a dialog. Show background status/reconcile outcome; if cancellation exists, explain its semantics.
- Preserve nonsecret drafts across tab mistakes where supported; define expiry and tenant/user boundaries. Do not persist invitation tokens, passwords or provider/webhook credentials in browser storage.
- Navigation warnings are task-specific; read-only evidence dialogs never ask to discard changes.
- Undo is only for truly reversible supported actions (e.g. local filter reset or a backend-restorable archive). Give the actual recovery action and expiration. No invented undo for revoke, close/risk acceptance, kill-switch change, traffic already sent or irreversible retention.

## Efficient repeated use

| Control | Proposed behavior | Engineering prerequisite |
| --- | --- | --- |
| Persistent filters | Restore within route and tenant/user; visible active chips; Reset | Defined storage policy; URL-safe allowlist; no sensitive payloads. |
| Saved view | Name, filter criteria, sort, visible columns; Personal or Shared explicitly | Versioned tenant-scoped model/RBAC if shared/server saved; not just a decorative button. |
| Column preferences | Required identity/status/action cannot all be hidden; sensible reset | Shared schema/version and breakpoint rules; reconcile removed columns. |
| Back behavior | Return to original filter/sort/page/selection/scroll | Route state and stable entity IDs; deleted record has contextual fallback. |
| Contextual search | Search within declared Targets/Findings/checks with actual scope labels | Debounce/cancel stale queries; paginated authoritative totals. |
| Live updates | Keep ordering during active interaction; show “N updates available” when deferred | Stable data IDs, buffered/explicit re-sort rules and no hidden stale outcome. |
| Comparison baseline | Saved assessment scope/version/time, not guessed visit time | Retained observation/history model. |
| Global search / command palette | Later phase after route semantics stabilize | Permission-scoped backend search, keyboard/accessibility, meaningful results. |

Draft/persistence rules must be documented by feature; do not cache cross-tenant selection accidentally. A shared saved view requires an authorized write API and audit as appropriate. Until supported, label controls as future proposals in the handoff and omit nonfunctional UI affordances.

## Daily-use acceptance

User refreshes without losing row/focus; opens evidence and returns to same place; changes filters and sees correct totals; navigates Back with preserved scope; notices new results without a row moving under pointer; recovers slow/failed saves without duplication; understands whether closing/undo affects real work.

Follow [motion contract](02-motion-and-interactions.md), [component states](12-component-visual-specification.md), and [design gate](17-design-acceptance-and-handoff-gates.md). Use Impeccable harden/clarify/adapt/animate/polish and interaction-design.
