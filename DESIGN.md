# AstraNull — DESIGN.md

Design system for the AstraNull portal (`apps/web/react`). Register: **product** (design serves the product). Anchored on the Open Design prototype (`.grok-ui-reference/prototype-*`). Two themes: **dark (default)** and **light**.

## Principles
- Calm, rigorous, defensible. Evidence-first. One accent (orange), used sparingly.
- Every value is a CSS custom property token. No raw hex in components (enforced by `npm run lint:portal`).
- Anti-slop: no gradient text, no >1px side-stripe accent borders, no emoji feature icons, no decorative eyebrow-on-every-section.

## Typography
- Display: `"Space Grotesk", "Inter", system-ui` — headings/KPI values, tracking `-0.04em`.
- Body: `"Inter", system-ui` — 16px / 1.5.
- Mono: `"JetBrains Mono", ui-monospace` — IDs, digests, timestamps, KPI labels.

## Radii / spacing / motion
- Radii: 4 / 8 / 16 / 9999. Spacing scale 4→32. Motion 150/200ms, `cubic-bezier(0.2,0,0,1)`, honor `prefers-reduced-motion`.

## Theme architecture
- Tokens live in `:root` (dark default). Light theme overrides live under `:root[data-theme="light"]`.
- `color-scheme: dark` on `:root`; `color-scheme: light` under `[data-theme="light"]`.
- A **theme toggle** (sun/moon) sits in the topbar; persists to `localStorage['astranull.theme']`; initial theme applied in `main.tsx` before render (respect saved value, else `prefers-color-scheme`). No FOUC.

## Dark theme tokens (current, keep)
```
--bg #000000  --surface #000000  --surface-raised #000000
--fg #f0f0f0  --fg-2 #a1a4a5  --muted #7e8386  --meta #74797c
--border rgba(214,235,253,0.19)  --border-soft rgba(217,237,254,0.145)  --border-strong rgba(214,235,253,0.34)
--accent #ff801f  --accent-on #000000
--success #11ff99  --warn #ffc53d  --danger #ff2047
--elev-ring 0 0 0 1px var(--border)   --elev-raised (dark drop shadow)
```

## Light theme tokens (NEW — `:root[data-theme="light"]`)
Clean white surfaces, near-black ink, dark hairline borders on white, retained orange accent, and DARKER semantic colors (the neon dark values fail contrast on white). Verify body text ≥4.5:1.
```
--void-black stays; override:
--bg #ffffff
--surface #ffffff
--surface-raised #f6f7f9
--fg #0b0d0f            (near-black ink, ~19.5:1 on white)
--fg-2 #44484d          (secondary, ~8.9:1)
--text-secondary #44484d
--muted #5b6066         (~6.4:1)
--meta #767b81          (~4.6:1, tertiary/meta)
--frost-border rgba(9,20,36,0.14)   (dark hairline on white)
--border rgba(9,20,36,0.14)
--border-soft rgba(9,20,36,0.08)
--border-strong rgba(9,20,36,0.24)
--accent #ff801f  (keep brand orange for fills)
--accent-on #ffffff  (white text on orange fills in light theme)
--accent-hover color-mix(in oklab, var(--accent), black 8%)
--accent-active color-mix(in oklab, var(--accent), black 16%)
--on-danger #ffffff
--success #0a9d63   (green, ~3.3:1 large / used as badge fill + dark text)
--warn #b45309      (amber)
--danger #d61f43    (red)
--info var(--accent)
--proof-surface color-mix(in oklab, var(--fg), transparent 96%)
--elev-ring 0 0 0 1px var(--border)
--elev-raised 0 1px 2px rgb(9 20 36 / 8%), 0 4px 12px rgb(9 20 36 / 6%)
--focus-ring 0 0 0 2px var(--bg), 0 0 0 4px var(--accent)
color-scheme light
```
Badges: on light theme, semantic badges use the darker semantic color at low-alpha background + the semantic color as text (existing badge rules use color-mix on the semantic token, so they adapt; verify contrast). Verdict tones: danger=Gap, warn=Review, success=Pass (unchanged).

## Components (both themes must look correct)
Shell (sidebar, breadcrumb+search topbar, compact footer), underline tabs, design-system `Select` (dark/light chevron), flat joined KPI grid (`.metric-grid`/`.kpi-cell`), `DataTable`, `Badge`, `Button` (primary=orange, secondary, ghost, danger), cards/panels, readiness donut, empty states. All driven by tokens.

## Quality bar (target 10/10)
- Contrast AA for body/meta in BOTH themes.
- No horizontal overflow at 360/768/1440.
- Visible focus on every interactive; reduced-motion honored.
- `npx impeccable detect apps/web/react/src` → `[]` (or only justified inline-ignored).
- Table-first read layouts; CRUD forms preserved.
