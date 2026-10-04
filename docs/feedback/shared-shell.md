# Shared shell, navigation, typography and tables

Source: `components/layout/app-shell.tsx`, `lib/navigation.ts`, `components/ui/*`, `styles.css`, `DESIGN.md`.

## What works

Recognizable brand, predictable sidebar, meaningful navigation sections, theme toggle, breadcrumbs and named table scroll regions. Dark/light support and keyboard semantics already exist. Keep them.

## Recommended improvements

- [P2] **Targets-first ordering:** Targets above Target groups. Group settings are a secondary organization concept under ADR-0008. Avoid another Environment or Agent tier.
- [P2] **Separate account controls from governance:** Plan & usage, Settings and Support are account tasks; they compete with Audit/Reports/Integrations in a long governance section. Preserve current customer role-scoped access; exclude future-release surfaces.
- [P2] **Sidebar scroll discoverability:** At shorter viewports, lower links such as Billing may lie beneath the visible navigation. Use a clear scroll affordance, keep account controls reachable, and do not let a large developer-role block dominate the footer.
- [P2] **Consistent breadcrumbs:** Several detail views repeat shell breadcrumb, inline breadcrumb and Back link. Choose one contextual trail plus a return action that preserves list filters. Technical IDs should not become every breadcrumb label.
- [P2] **Table column budgeting:** Current Targets and scan tables require horizontal scroll even at desktop. Scrolling is legitimate for expert metadata, but the target, outcome and main action should remain easy to see. Use column priority and details rather than shrinking all text.
- [P2] **Presentation experiment controls:** Classic/Refined/Premium selectors belong in development/design review, not the customer's primary workflow. Decide one presentation before production polish.
- [P1] **Status vocabulary:** Color cannot substitute for explanation. Keep execution state, ownership, compatibility, confidence, finding severity and protection efficacy distinct.

## Layout specification

Use 32px desktop / 20–24px tablet / 16px mobile page gutters; 24px section/card rhythm; 8px label-to-field and 16px field gaps. Preserve established type faces and root tokens. Table primary labels need readable body text; reserve mono for identifiers and timestamps. Avoid excessive 10px uppercase labels or broad green status for ordinary counts.

Collapsed navigation must have tooltips/accessibility labels and keyboard focus. Mobile drawer needs focus trap, Escape/backdrop dismissal and restored trigger focus; background should not be interactive while open. Theme choice persists without a flash. Breadcrumb transitions never reset selected filters by accident.

## Motion

Reuse the existing route/tab/surface motion and reduced-motion contract. Small accent-rail/chevron feedback is enough for navigation. Do not create a second page reveal sequence or move data rows while an operator is selecting evidence.

## Verification

Review at 375/768/1024/1440px and a short 768px-height desktop, keyboard-only, 200% text zoom, dark/light and reduced motion. Page-level horizontal overflow is prohibited; named table regions may scroll. Test each user role and missing-route/expired-auth recovery. No current source changes are part of this feedback.

Skills: UI/UX Pro Max, Impeccable layout/adapt/clarify/harden/animate/polish, interaction-design.

## Shared visual/task handoff

Use [reference specifications](11-reference-screen-specifications.md), [component standard](12-component-visual-specification.md), [responsive budgets](14-content-and-responsive-task-budgets.md) and [feedback/navigation](16-feedback-responsiveness-and-daily-use.md). Page focus: R1–R5 navigation frame; T6 Back/context and mobile task flow. See [acceptance gate](17-design-acceptance-and-handoff-gates.md). All references remain proposed until rendered and explicitly approved; user task results are Not run.
