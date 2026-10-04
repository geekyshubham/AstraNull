# AstraNull design direction and shared UX review

Review: 2026-10-03–04, Asia/Kolkata. Deliverable: feedback only. All exploratory implementation changes were reverted; no commit was made.

## Design judgment

The existing product has a recognizable identity and many real workflows. Its weakness is not the orange/black palette: the interface often presents technical implementation detail before a user's decision, repeats summaries, and gives status, eligibility, detection, and evidence confidence similar visual weight. Increasing animation alone will not solve that.

The next design should feel like a calm security operations workspace: **scope → ownership → observations → outcome → next action**. A security owner should understand the dashboard in ten seconds; an engineer should be able to inspect the exact evidence without leaving the workflow.

## Keep

- Existing orange accent, black dark surfaces, and white light surfaces from `DESIGN.md`; retain token-based themes and the current font families.
- Shared primitives, Lucide icons, named scrollable table regions, error/empty states, and native dialogs.
- Exact-target evidence relationships, explicit unknown/inconclusive results, and authorized bounded direct checks.
- ADR-0008: declared targets, tags, secondary groups, external-only probes. No agent setup, environment management, or mandatory cloud integration.

## Change the hierarchy

| Layer | User question | Recommended treatment |
| --- | --- | --- |
| Page header | Where am I and what can I do? | Clear title, one short sentence, one primary action; secondary actions stay neutral. |
| Summary | What matters now? | Three to five decision-relevant facts with explicit denominator, scope, and freshness. |
| Work area | What do I inspect or change? | One table, timeline, or split workspace; minimal nested card chrome. |
| Evidence | Why should I trust this? | Exact target, observation time, provenance, evaluation rule, source links. |
| Advanced | What are the technical details? | Disclosures, tabs, or an evidence drawer; do not lead with raw keys and internal IDs. |

## Spacing and geometry

Use the existing 4/8/12/16/20/24/32/40/48px scale. Page gutter: 32px desktop, 20–24px tablet, 16px narrow mobile. Section gap: 24px; card padding: 24px desktop, 16px mobile; label-to-control: 8px; field-to-field: 16px; related action gap: 8–12px. A surface must have an owner for spacing even when an ARIA tab panel uses `display: contents`.

Dashboard layout detail: `.dashboard-overview` inherits shared `.tab-panel { display: contents }`, and the parent dashboard owns the gap between the resulting layout boxes. The inspected baseline has visible section gaps; `display: contents` by itself is **not a verified spacing defect**. Preserve or deliberately replace this spacing owner during redesign and measure rendered gaps rather than adding arbitrary margins. Investigate any actually touching widgets at their specific surface. In `dashboard-page.css`, the factor bar also transitions `width`; use a full-width fill with transform-based scale instead.

Do not apply table minimum widths indiscriminately. The dashboard's compact tables should fit their own workspace; wide inventory tables can scroll locally with a clear edge affordance, a visible primary identifier, and keyboard access. On mobile, do not make a user scroll horizontally merely to find the main action.

## Typography, status, and chart rules

- Headings use the established display face; body and controls use Inter; mono is for actual identifiers/code/time, not every line of explanatory text.
- Body text normally 14–16px with readable line height; micro-labels 11–12px sparingly. Avoid an entire workflow made of uppercase pills.
- Criticality, severity, lifecycle, ownership, and evidence certainty are separate dimensions. Do not add a red `CRITICAL` stamp to an ordinary informational count because a generic tile variant defaults to it.
- Detection is neutral observation. Green is reserved for a validated success in a stated scope. A provider logo is context, not proof.
- Every chart has a textual equivalent, units, denominator, observation window, and drill-down. Unknown must be visible in the denominator. WAF and CDN overlap; never add them as disjoint categories.
- Dark/light contrast must be measured, including secondary text, focus rings, disabled controls, legends, and placeholders. This review does not claim full WCAG compliance from screenshots.

## Interaction rules

Reuse `FormModal`, `ConfirmModal`, `Select`, `Tabs`, `DataTable`, `Button`, and `EmptyState`. Native dialogs need title/description, bounded scrollable content, visible footer, Escape/backdrop behavior, focus trapping and restoration, and retained input after server errors. Destructive actions state the exact object and consequence. Field validation belongs next to the field; submitting a long form must not produce only a distant generic banner.

Remove customer-visible Classic/Refined/Premium design experiment switches when one presentation is chosen. These names sound like plan or feature tiers and force the customer to make a design decision. Do not remove the underlying route or functions simply to hide an unfinished state.

## Skills and execution order

1. Read [skill guide](05-skills-and-handoff.md), `PRODUCT.md`, `DESIGN.md`, ADR-0008, and the requested page feedback.
2. Use **UI/UX Pro Max** to generate recommendations; preserve the established brand when its generic search suggests unrelated landing patterns or replacement fonts/colors.
3. Use **Impeccable shape/layout/clarify** for information hierarchy and copy; **harden/adapt** for states, keyboard, and breakpoints.
4. Use **Impeccable animate** and the installed **interaction-design** skill for intentional feedback; then **polish**.
5. Verify the real workflow, both themes, reduced motion, and failure states. Capture new screenshots. Never use a detector's clean output as proof of good design.

## Suggested sequencing

Updated sequence for the protection-profile addition: host identity/provenance and target protection profile first; inventory/segmented dashboard second; live direct-check evidence third; retained changes/concentration/remediation fourth. Shared overlay/spacing work applies throughout; schedules/library, integrations/notifications, reports/settings/audit and customer/public refinements then consume the same contracts. Page files contain acceptance criteria; this feedback is a proposed backlog, not a completed implementation record.

## Protection-profile extension

[Host profile](06-host-protection-profile.md), [segmented dashboard](07-dashboard-protection-analytics.md), [changes/remediation](08-drift-concentration-remediation.md) and [engineering consultation](09-engineering-consultation.md) refine the earlier page recommendations. Reorganize existing surfaces; do not create a separate data/verdict engine or another dashboard of equally weighted cards.


## Reproducible visual and task standard

[Reference specifications](11-reference-screen-specifications.md), [component geometry](12-component-visual-specification.md), [surface decision](13-surface-color-decision.md), [content/mobile budgets](14-content-and-responsive-task-budgets.md), [journeys](15-first-use-and-returning-user-journeys.md), [feedback](16-feedback-responsiveness-and-daily-use.md) and [acceptance gate](17-design-acceptance-and-handoff-gates.md) define the next shared preparation phase. They are proposed, not implemented brand changes or approved mockups.

Prepare the common reference set and journeys before parallel page implementation. A restrained raised dark surface is an explicit pending option; existing DESIGN.md wins until approval. Craft is measured by task comprehension and coherent shared components, not an invented numerical rating or additional document volume.


## Task continuity before more visual finishing

Every surface should answer the user's decision with its relevant supporting data and one clear continuation. The [contextual evidence inspector](19-contextual-evidence-inspector.md) and [cross-page flow](20-cross-page-task-flow-contract.md) refine prior tab/route recommendations: answer and proof together, technical depth optional. Renaming the same object chain into tabs does not solve the task.

After shared contract/reference preparation, prioritize exact action destinations, target/direct-check/member context and return state before decorative polish. Existing inline evidence, audit drill-down and access-reference continuity are foundations. [All-page contracts](21-all-page-data-and-task-review.md) and [data semantics](23-data-meaning-and-workflow-state-contract.md) specify the decision on every route.

## Current-release task boundary

[Scope correction](24-current-release-scope.md) supersedes earlier release assumptions. Current navigation and workspace specifications cover customer/public pages and target-centered direct checks. Live check evidence and contextual inspection remain; standalone execution list/detail and deferred operational/admin workflows are removed.
