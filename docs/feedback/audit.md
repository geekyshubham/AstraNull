# Audit log — UX/UI review

Review: 2026-10-03–04. Status: feedback/proposed work only; no implementation is approved by this file.

## User goal

Find who changed what, when and under which scope, with inspectable evidence integrity.

## Inspected surface and evidence

Route: `/app#audit`. Observed heading: **Audit log**.
Source: `apps/web/react/src/pages/governance-pages.tsx: AuditPage`.
Browser evidence: [desktop](evidence/audit-desktop.png), [route observations](evidence/route-observations.json).

This review used local synthetic fixtures. Missing/stale fixture relationships or dates are explicitly separated from verified UI/source problems. No production provider or live external-probe execution is claimed.

## Proposed hierarchy

Event search and date range → append-only table with actor, action, object name and time → event details showing before/after where recorded and custody evidence.

## Prioritized findings

### 1. [P2] The table emphasizes raw identifiers over human context

**Observed / evidence:** Actor appears as role in the fixture and target is an object ID; hashes are abbreviated.
**User impact:** Investigators need the actual identity and affected object, not just Admin/Engineer.
**Recommendation:** Display actor identity plus role, resolve object name when authorized, and retain IDs/hashes as copyable technical details.
**Acceptance check:** No missing actor/object metadata is invented; identical roles remain distinguishable by recorded identity.

### 2. [P2] Essential investigation filters are limited

**Observed / evidence:** Observed filter rail has custody-only, actor and action plus search, with no clear time-window task.
**User impact:** Finding an incident’s changes is slow when the ledger grows.
**Recommendation:** Add date range, resource scope, actor identity, action category and shareable filters with server-side paging if needed.
**Acceptance check:** Deep-linked investigation preserves filters and correctly scopes timestamp timezone.

### 3. [P1] Recorded hash does not equal independently verified chain

**Observed / evidence:** Intro says custody-sealed event trail; rows count hashes as recorded.
**User impact:** Users can overread hash presence as verified integrity.
**Recommendation:** Use Recorded hash versus Verified chain labels and expose actual verification response/time where supported.
**Acceptance check:** Integrity wording is derived from verification evidence rather than the presence of entry_hash.

## Actions, dialogs, widgets and states

Inspect custody-only checkbox, actor/action selectors, search, keyboard table scroll and technical hash disclosure/copy. Export is a proposed capability if absent; do not add a decorative export button without a scoped backend contract.

Keep loading, retained/stale data, unavailable, no data, filtered-empty, disabled-by-role, invalid input, saving, error and success states distinct. Use the shared dialog/keyboard/focus contract; destructive confirmations state the exact affected object.

## Data and functionality prerequisites

Audit is append-only and tenant/role scoped. Event time, ingestion time and verification time are distinct. Before/after diffs require recorded mutation fields and proper redaction.

## Visual and motion direction

Use the existing theme tokens, restrained orange accents, familiar shared controls and visible 16–24px content insets. Give dense content a clear spacing owner; avoid nested surface borders and unexplained repeated pills. Animate only actual state changes with 90–200ms feedback and 200–300ms surface transitions; do not animate fake work or hide content before a reveal. Follow [motion specification](02-motion-and-interactions.md), including reduced motion and focus preservation.

## Skills for implementation

Use **UI/UX Pro Max**, then **Impeccable shape, clarify, adapt, harden, animate, polish**, plus **interaction-design** for forms, overlays and async feedback. Read [actual skill files and handoff](05-skills-and-handoff.md), [design direction](00-design-direction.md), and [naming](01-naming-and-navigation.md). Live validation pages also require [execution-trace specification](03-live-check-observability.md).

## Page acceptance criteria

Filter totals reflect query scope; no tampering controls; object links resolve real routes; hashes never imply verification by themselves; large ledgers are paginated rather than unbounded.

- Test 375/768/1024/1440px, dark/light, 200% text zoom, keyboard, reduced motion and touch targets.
- Validate the exact entity and role with real API behavior; do not synthesize missing provider/evidence/verdict data.
- Compare before/after screenshots and complete the primary workflow, including cancellation and recovery.
- Preserve outside-in-only scope, no default cloud access, and existing execution authorization.
- Update implementation docs/tracker only in a later authorized implementation task; this review does not mark features complete.

## Declared context and remediation audit

Future service-role/owner/criticality/origin-relationship edits and remediation decisions need tenant-scoped audited changes. Audit is provenance for a declaration or action, not proof that a fix was applied. Confirmation comes from evidence-backed retest under [remediation semantics](08-drift-concentration-remediation.md).

## Shared composition and task requirements

Apply [component standard](12-component-visual-specification.md), [content/mobile task budgets](14-content-and-responsive-task-budgets.md), and [feedback/persistence rules](16-feedback-responsiveness-and-daily-use.md). Reuse the appropriate R1–R5 [reference pattern](11-reference-screen-specifications.md), then verify this page’s primary task through [G0–G5 gates](17-design-acceptance-and-handoff-gates.md). No proposed screen, brand choice or usability result is approved/completed merely because this review exists.


## Data-to-decision and cross-page task contract

Source/saved-evidence review added 2026-10-04; proposed UX only, not new live verification.

| Contract | Page requirement |
| --- | --- |
| Decision / intended outcome | Inspect exact recorded action without searching another page. |
| Data and interpretation | Event time/actor identity/role/resource/metadata/hash. Audit decision not proof fix applied. |
| Current path / context | Existing row selection renders metadata drilldown; external support View arrives unfiltered. |
| Proposed continuation | Preserve inline inspector; accept exact incoming event/resource/time selection; recorded change plus context/evidence. |
| Carry automatically | Event/resource IDs, actor/time, safe caller filters. |
| Back / Close restores | Same ledger query/date/sort/page/row/scroll. |
| Loading / missing / permission | No events/no matches, missing event ID, sensitive resource redaction and denied access. |
| Task acceptance | Support View selects actual event; row inspection never requires a second search or unverifiable change claim. |

Apply [contextual inspector](19-contextual-evidence-inspector.md), [cross-page actions/return-state](20-cross-page-task-flow-contract.md), [data semantics](23-data-meaning-and-workflow-state-contract.md) and [confirmed source links](22-contextual-link-and-source-audit.md). Inspecting never executes; technical record routes remain optional depth. Verify completion using [design acceptance](17-design-acceptance-and-handoff-gates.md), not just route rendering.
