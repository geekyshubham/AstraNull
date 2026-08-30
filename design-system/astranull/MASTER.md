# AstraNull unified design system

This run uses the portal's implemented token system in `apps/web/react/src/styles.css` as the runtime source of truth. `DESIGN.md` supplies product principles. Generic ui-ux-pro-max palette/font suggestions are intentionally not adopted because identity preservation wins.

## Product character
Calm, rigorous, defensible, evidence-first. This is an operational security console—not a hacker terminal, growth-SaaS dashboard, cloud inventory scanner, or self-service traffic generator.

## Tokens
- Color: use existing `--bg`, `--surface`, `--surface-raised`, `--fg`, `--fg-2`, `--muted`, `--meta`, `--border*`, `--accent`, `--signal`, and semantic status tokens. No raw colors in TSX.
- Type: use `--font-display`, `--font-body`, and `--font-mono`; fixed product scale `--text-xs` through `--text-2xl`.
- Space: 4pt scale `--space-1`, `--space-2`, `--space-3`, `--space-4`, `--space-5`, `--space-6`, `--space-8`, `--space-12`.
- Shape: `--radius-sm`, `--radius-md`, `--radius-lg`, `--radius-pill`.
- Motion: `--motion-fast`, `--motion-base`, `--motion-ease`; no layout-shifting hover and always respect reduced motion.
- Focus/elevation: `--focus-ring`, `--elev-ring`, `--elev-raised`, `--card-shadow*`.

## Component rules
- Tables: one `DataTable` chrome, quiet raised header, 52px desktop rows, soft separators, visible hover/focus, mobile labeled cards, compact aligned actions.
- Callouts: one leading SVG icon, title/body hierarchy, equal-size actions, semantic full-border/background treatment; never a colored side stripe.
- Buttons: shared Button variants/sizes; 44px touch target, stable hover, visible focus, `sm` in dense tables/detail actions.
- Forms: labels above controls, explicit help/error text, no implicit target selection, no modal when inline progressive disclosure is clearer.
- Status: text plus icon/badge; never color alone. Pending, not observed, inconclusive, not detected, detected, and error remain distinct.

## Surface direction
- Public: more whitespace, same tokens and control language.
- Auth: restrained compact card; badges fit content.
- Lists: table-first, filters/actions above data, honest loading/error/empty states.
- Details: page header, compact evidence summary, primary table/workflow, supporting governance panels.
- Operations: evidence and safe boundaries before decorative metrics.

## Quality gates
WCAG AA, keyboard complete, no horizontal page overflow at 390/820/1440, long IDs wrap safely, every async action has busy/error/success behavior, no fake controls or inferred verification, no emoji icons, no raw secrets, and no page-local palette.
