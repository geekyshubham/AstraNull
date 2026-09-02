# AstraNull shared design system

Authoritative foundation for `apps/web/react`, aligned to the latest Open Design project `6ecf11be-6a37-4ece-9b67-208b74aea6b6`. The Open Design HTML is a visual and information-architecture reference only; React remains responsible for routing, authorization, live data, mutations, redaction, and accessibility.

## Product character

Calm, rigorous, defensible, and evidence-first. AstraNull is an operational security console—not a hacker terminal, generic growth dashboard, cloud inventory scanner, or self-service traffic generator.

- Dark is the default theme; light is fully supported.
- Orange is the only brand/primary accent and is used sparingly.
- Semantic green, amber, and red communicate status only.
- No aurora, neon/cyan identity, gradients as decoration, glass-card stacks, scanlines, glow, or page-load choreography.
- All component colors come from root theme tokens; no raw page/component colors.

## Typography

- Display/headings: `"Space Grotesk", "Inter", system-ui`.
- Body/UI: `"Inter", system-ui`.
- Identifiers, digests, timestamps, table labels: `"JetBrains Mono", ui-monospace`.
- Headings use compact line-height and measured negative tracking; body remains 16px/1.5.

## Core tokens

### Dark (default)

```css
--bg: #000000;
--surface: #000000;
--surface-sunk: #000000;
--fg: #f0f0f0;
--fg-2: #a1a4a5;
--border: rgba(214, 235, 253, 0.19);
--border-soft: rgba(217, 237, 254, 0.145);
--border-strong: rgba(214, 235, 253, 0.34);
--accent: #ff801f;
--accent-on: #000000;
--success: #11ff99;
--warn: #ffc53d;
--danger: #ff2047;
```

Dark depth comes from frost hairlines, not charcoal layers or glass blur. Canvas, cards, and raised surfaces remain pure black.

### Light

```css
--bg: #f7f7f5;
--surface: #ffffff;
--surface-sunk: #f0f0ed;
--fg: #16181c;
--fg-2: #565b63;
--border: rgba(19, 22, 28, 0.13);
--border-soft: rgba(19, 22, 28, 0.075);
--border-strong: rgba(19, 22, 28, 0.24);
--accent: #ff801f;
--accent-on: #000000;
--success: #0a7c46;
--warn: #96590a;
--danger: #c11533;
```

Light depth comes from a tinted canvas, white surfaces, recessed wells, and restrained shadows. Orange stays byte-identical across themes. Because orange ink is only about 2.34:1 on the light canvas, primary controls use black-on-orange fills and light-theme focus uses neutral dark ink.

## Geometry and spacing

- Radius scale: 4 / 8 / 16 / pill.
- Spacing scale: 4 / 8 / 12 / 16 / 20 / 24 / 32 / 40 / 48.
- Sidebar: 248px expanded; responsive drawer below 1120px.
- Main page measure: 1560px where the shell owns width.

## Motion system

Motion is a signal, not decoration. Every animation in the portal answers "what
just changed?" — a route arrived, a value moved, a surface opened, work is in
flight. Nothing animates to draw attention to itself.

### Duration tiers

| Tier | Token | Use |
| --- | --- | --- |
| Micro | `--motion-micro` 90ms | Press feedback, accent-rail opacity |
| Fast | `--motion-fast` 120ms | Hover, focus, color changes |
| Base | `--motion-base` 200ms | Surfaces, drawers, modals, route enter, scroll affordance |
| Slow | `--motion-slow` 300ms | Loading, value changes, reveal |
| Measure | `--motion-measure` 900ms | Chart and gauge value sweeps only |

Easing is `--ease-out-soft` (`cubic-bezier(0.16, 1, 0.3, 1)`) for entrances and
`--motion-ease` for the legacy shared transitions.

### Sanctioned vocabulary

- **Route enter** — 200ms opacity plus 8px rise, replayed on navigation only.
  `RouteTransition` keys on the route, so a page load stays still; this remains a
  navigation response, not page-load choreography.
- **Tab panel rise** — 240ms, on deliberate tab change only.
- **Value tween** — `useAnimatedNumber` counts a metric toward its new value on
  the 300ms tier; gauge arcs sweep on the measure tier. The settled string is
  always byte-identical to a static render.
- **Micro-interaction** — hover wash, focus ring, 1px button press, nav accent rail.
- **Functional loading** — spinner rotation (800ms) and skeleton shimmer.
- **Surface enter** — modal and drawer open on the base tier.
- **Scroll-reveal** — marketing surfaces only, via `Reveal`. Never inside the
  operator console: an operator scanning a table must not wait on a reveal.

Still excluded: aurora, neon/cyan identity, decorative gradients, glass-card
stacks, scanlines, glow, decorative infinite motion, and parallax.

### Accessibility contract

- Animate only opacity and transform where practical.
- `prefers-reduced-motion: reduce` disables all animation and transition and
  restores auto scrolling; computed-style browser guards pin this behavior.
- Motion helpers default to "reduced" until the preference is read, so no tween
  can start before the preference is known. `Reveal` renders visible whenever
  motion is unavailable, so content is never trapped in a pre-animation state.

## Variant specificity rule

The shared foundation declares component bases as `[data-ui='button'].btn` and
`[data-ui='badge'].badge` — two classes. **Any rule that overrides a base
declaration must match that specificity**, e.g. `[data-ui='badge'].badge-danger`
or `.badge.badge-danger`, listed after the base.

This is not stylistic. Single-class variant rules lost silently to the base
regardless of source order, and the rendered result was: secondary buttons with a
transparent border and fill (an outlined control rendering as a bare text label),
compact 34px density never applying, and every status chip resolving to the same
grey — semantic pass/review/gap color absent from the dark theme entirely. The
tokens and the contrast tests described the intended design the whole time; only
the cascade disagreed. Theme overrides go one level higher again
(`:root[data-theme="light"] [data-ui='badge'].badge-danger`).

Pages that inject styles as a runtime `<style>` element land after this sheet in
the cascade. Shared geometry that must stay authoritative over them is written as
`body <their selector>`.

Two shared selectors are descendant, not child: `.queue-list div` and
`.kv-list div` box, pad, and vertically centre *every* div inside the list. That
is correct for a flat row list and wrong the moment a row has internal
structure — a nested stack renders as a box inside a box, horizontally centred
(`align-items: center` centres across the axis once the stack is a column). Give
any structured row an explicit reset, or the row will inherit list chrome it was
never meant to have.

## Shared components

- **Brand:** boxed 40px mark, orange core, Space Grotesk wordmark.
- **Buttons:** one orange/black default primary CTA; neutral secondary; quiet ghost; outlined danger. Desktop density is 40px, compact 34px; all coarse/mobile targets are at least 44px.
- **Cards:** 8px radius, 24px default padding, pure-black dark/white light surface, frost border; no divided raised-charcoal card chrome.
- **Chips/badges:** inset pill, mono uppercase label, semantic tint only for state.
- **Tabs:** inset pill rail with pill selections, horizontal overflow, complete roving-keyboard behavior.
- **Inputs/selects:** 4px radius, 44px control height, recessed token surface, visible compliant focus, bounded popup placement.
- **Tables:** scroll within their named keyboard-focusable region; mono uppercase masthead, 2px separation, zebra rhythm, orange hover wash and left edge, tabular numerics. Do not collapse data tables into unreadable mobile cards. `DataTable` wraps the scroll region in `.table-scroller`, which shades whichever horizontal edge still has content behind it and shades nothing when the table fits — a column clipped mid-word at the card edge is otherwise indistinguishable from truncated data.
- **Chips in narrow columns:** badges never break inside a word. `overflow-wrap: anywhere` made a badge's min-content one character wide, so a `HOSTNAME` chip in an auto-layout column rendered as eight stacked letters. Use `.badge-identifier` for chips that genuinely carry a long unbroken identifier.
- **Filter rails:** micro-labels are mono uppercase, matching the table masthead they sit against; search fields and selects share the 4px input radius and 44px control height.
- **Progress:** 7px pill track, semantic fills, transform-based value update.
- **Empty state:** 56px inset icon visual, concise heading/body, optional real action.

## Theme and accessibility contract

- The early inline boot script applies saved `localStorage['astranull.theme']` before CSS/React; absent an explicit light preference, dark remains the default. The shell toggle persists changes.
- Maintain WCAG AA body/secondary contrast in both themes. Never use color as the sole state signal.
- Every interactive element has a visible focus state and keyboard semantics; wrapped search controls expose focus on their visible container.
- Scrollable tab rails have a contextual accessible name and retain roving-keyboard navigation without an extra tab stop.
- Mobile/coarse touch targets are at least 44px; shell menu/theme icons remain 18px inside 44px controls; no page-level horizontal overflow.
- Long identifiers wrap safely; tables, code, and matrices own their internal horizontal scrolling.
- Preserve loading, error, empty, cached-data, disabled, and authorization states.

## Validation

Required foundation gates: `npm run web:typecheck`, `npm run lint`, `npm run lint:portal`, `npm run web:build`, focused primitive/shell/accessibility tests, and Playwright smoke over dashboard, auth, and a detail route in dark/light at desktop/mobile.
