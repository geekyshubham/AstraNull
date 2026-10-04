# Settings — UX/UI review

Review: 2026-10-03–04. Status: feedback/proposed work only; no implementation is approved by this file.

## User goal

Manage organization, machine access, secret metadata and retention safely with understandable state and consequences.

## Inspected surface and evidence

Route: `/app#settings`. Observed heading: **Settings**.
Source: `apps/web/react/src/pages/page-components.tsx: SettingsPage`; `apps/web/react/src/lib/crud-ui.tsx`.
Browser evidence: [desktop](evidence/settings-desktop.png), [route observations](evidence/route-observations.json).

This review used local synthetic fixtures. Missing/stale fixture relationships or dates are explicitly separated from verified UI/source problems. No production provider or live external-probe execution is claimed.

## Proposed hierarchy

Organization | Access | Security | Privacy tabs; each has a single main task, saved-state summary and local forms. Keep session details technical and secondary.

## Prioritized findings

### 1. [P1] Access and security have sensitive one-time workflows

**Observed / evidence:** Service accounts support creation/rotation/revocation, security vault stores/rotates secrets, and one-time outputs require careful handling.
**User impact:** A visually polished but unclear flow can cause lost credentials or accidental access revocation.
**Recommendation:** Clearly distinguish label/scope/expiry/secret metadata; use one-time copy/save acknowledgement, confirm rotation/revoke impact, and keep secrets out of histories/URLs.
**Acceptance check:** Secret shown once stays redacted in lists, errors, console, screenshots and refresh; old credential impact is explicit.

### 2. [P2] Organization mixes editable identity and technical session facts

**Observed / evidence:** Organization tab combines display name/region with user ID/role/tenant/auth mode and links elsewhere.
**User impact:** Users must distinguish editable tenant data from diagnostic session metadata.
**Recommendation:** Keep editable profile primary and read-only access posture under a concise disclosure; label support-managed SSO/users honestly.
**Acceptance check:** No nonfunctional SSO/users control suggests self-service capability that does not exist.

### 3. [P1] Retention needs units and deletion consequences

**Observed / evidence:** Privacy controls manage retention over different evidence/metadata categories.
**User impact:** A bare number or generic save can hide irreversible retention impact.
**Recommendation:** Explain units, category, minimum constraints, prospective deletion behavior and effective date; require an explicit review when retention is reduced.
**Acceptance check:** A lower retention value states what can be removed and when; API constraints/errors remain authoritative.

## Actions, dialogs, widgets and states

All four tabs were visited. Inspect organization save validation, Access create/rotate/revoke forms, Security store/rotate forms and Privacy retention inputs; confirmations can be opened without submitting. One-time-secret success states are specified from source rather than generated during this review. Preserve dirty values across tab mistakes or warn before discarding.

Keep loading, retained/stale data, unavailable, no data, filtered-empty, disabled-by-role, invalid input, saving, error and success states distinct. Use the shared dialog/keyboard/focus contract; destructive confirmations state the exact affected object.

## Data and functionality prerequisites

Use tenant/service account/secret/retention APIs and permission scopes. Agent bootstrap tokens and environments remain removed by ADR-0008. No invented IdP/user administration.

## Visual and motion direction

Use the existing theme tokens, restrained orange accents, familiar shared controls and visible 16–24px content insets. Give dense content a clear spacing owner; avoid nested surface borders and unexplained repeated pills. Animate only actual state changes with 90–200ms feedback and 200–300ms surface transitions; do not animate fake work or hide content before a reveal. Follow [motion specification](02-motion-and-interactions.md), including reduced motion and focus preservation.

## Skills for implementation

Use **UI/UX Pro Max**, then **Impeccable shape, clarify, adapt, harden, animate, polish**, plus **interaction-design** for forms, overlays and async feedback. Read [actual skill files and handoff](05-skills-and-handoff.md), [design direction](00-design-direction.md), and [naming](01-naming-and-navigation.md). Live validation pages also require [execution-trace specification](03-live-check-observability.md).

## Page acceptance criteria

Tab labels/field labels are consistent; units clear; busy controls prevent duplicate mutation; role restrictions show explanation; one-time outputs are not recopied into the DOM after dismissal; retention changes are auditable.

- Test 375/768/1024/1440px, dark/light, 200% text zoom, keyboard, reduced motion and touch targets.
- Validate the exact entity and role with real API behavior; do not synthesize missing provider/evidence/verdict data.
- Compare before/after screenshots and complete the primary workflow, including cancellation and recovery.
- Preserve outside-in-only scope, no default cloud access, and existing execution authorization.
- Update implementation docs/tracker only in a later authorized implementation task; this review does not mark features complete.

## Where declared host context is edited

Prefer target-level Edit context for purpose/owner/criticality, and group-level explicitly labeled defaults for inheritance. Settings may govern a typed vocabulary only if a real contract exists; do not bury per-host ownership in tenant settings or turn free-form tags into silent mandatory classifications. See [host profile](06-host-protection-profile.md) and [engineering declarations](09-engineering-consultation.md).

## Shared composition and task requirements

Apply [component standard](12-component-visual-specification.md), [content/mobile task budgets](14-content-and-responsive-task-budgets.md), and [feedback/persistence rules](16-feedback-responsiveness-and-daily-use.md). Reuse the appropriate R1–R5 [reference pattern](11-reference-screen-specifications.md), then verify this page’s primary task through [G0–G5 gates](17-design-acceptance-and-handoff-gates.md). No proposed screen, brand choice or usability result is approved/completed merely because this review exists.


## Data-to-decision and cross-page task contract

Source/saved-evidence review added 2026-10-04; proposed UX only, not new live verification.

| Contract | Page requirement |
| --- | --- |
| Decision / intended outcome | Complete one account/security change with local feedback. |
| Data and interpretation | Tenant identity/session facts, service-account scope/status, vault metadata, retention units/impact; one-time secret vs stored list. |
| Current path / context | Four tabs with task forms and technical facts; sensitive confirmation/output source-inspected. |
| Proposed continuation | Task-focused local editor/result; related audit context can open inspector; preserve safe drafts between sections. |
| Carry automatically | Tenant/task/credential identity, scopes/expiry/retention and safe fields. |
| Back / Close restores | Same tab/task after audit/inspection; do not restore secrets from storage. |
| Loading / missing / permission | Dirty/busy/error, expired/revoked key, missing tenant, read-only mutation, retention consequence. |
| Task acceptance | Save/revoke/rotate shows authoritative own object result and clear impact without page reset. |

Apply [contextual inspector](19-contextual-evidence-inspector.md), [cross-page actions/return-state](20-cross-page-task-flow-contract.md), [data semantics](23-data-meaning-and-workflow-state-contract.md) and [confirmed source links](22-contextual-link-and-source-audit.md). Inspecting never executes; technical record routes remain optional depth. Verify completion using [design acceptance](17-design-acceptance-and-handoff-gates.md), not just route rendering.
