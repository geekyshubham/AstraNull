# Component-level visual specification

2026-10-04. Proposed shared composition targets, **not CSS or DESIGN.md changes**. Retain existing fonts, orange accent and primitives. New role tokens require a reviewed shared update; no page-specific hardcoded exceptions.

## Typography

| Role | Font / weight | Reference size / line height | Rules |
| --- | --- | --- | --- |
| Page title | Space Grotesk 600 | 32/40px desktop; 24/32px mobile | One H1; −0.025em tracking; long hostname wraps. |
| Section title | Space Grotesk 600 | 20/28px | Major work areas; no uppercase eyebrow for each panel. |
| Panel title | Inter 600 | 16/24px | Providers, dimensions, forms. |
| Body / label | Inter 400 / 500 | 14/20px; primary instructions 16/24px | Prose max 70ch; labels visible. |
| Button / tab | Inter 600 | 14/20px | Same vocabulary throughout. |
| Supporting metadata | Inter 400 | 12/18px | Never the sole explanation of a gate. |
| Metric | Space Grotesk 600 | 28/32px | Actual value immediately; tabular numerals. |
| Code / exact ID | JetBrains Mono 400 | 12/18px metadata; 13/20px trace | Local scroll/wrap; human labels remain sans. |

Implement scalable units, growth for zoom/translation and visible font fallbacks. Existing text tokens do not map exactly to every proposed role: consolidate shared role tokens deliberately. Tracking no tighter than −0.04em.

## Geometry

| Component | Reference geometry | Alignment / behavior |
| --- | --- | --- |
| Button | 40px desktop; min 44px coarse/mobile; 20px horizontal padding | Existing pill; icon 18px, 8px gap. |
| Compact row action | 34px visual desktop; min 44px touch target | 14px icon, 6px gap; not compact-only on touch. |
| Icon-only action | 40 × 40 desktop; 44 × 44 touch | 18px centered icon; label and focus. |
| Input/select/search | Min 44px; 12px side inset; 4px radius | Label 8px above; icon 18px plus 8px gap. |
| Textarea | Min 96px; 12px padding | Grows; shared label/error behavior. |
| Checkbox/radio | 18–20px mark; min 44px clickable label row on touch | 8px label gap; helper aligns to text. |
| Status badge | Min 24px; 8px horizontal / 4px vertical padding | 12/16px text; 12px icon; word labels. |
| Tabs | Min 40px desktop / 44px touch; 16px side padding | One rail; selection shape/weight plus text. |
| Section surface | 24px inset desktop / 16px mobile; 8px radius | One boundary; subareas use rule or space. |
| Table header | Min 40px; 12px vertical / 16px horizontal inset | 12/16px text; headers can wrap. |
| Simple row | Min 52px | 14/20px primary, 12/18px secondary; grows. |
| Rich target row | Min 64px | Two visible text levels; aligned action. |
| Provider observation | Min 56px; 12px vertical rhythm | Logo 20–24px plus text; explicit Evidence action. |
| Dimension row | Min 56px | Aligned label/result/coverage; details expand. |
| Progress/coverage | 6–8px track | Text outside; transform progress; unknown labeled. |
| Form / confirmation | 560px / 440px widths | 24px desktop / 16px mobile insets; footer reachable. |
| Evidence overlay | Max 880px; safe mobile sheet | Source/identity/time retained; returns to origin. |

All dimensions are minimums, not clipping heights. Before replacing an existing variant, compare shared candidates; preserve selector specificity documented in DESIGN.md.

## Rhythm and alignment

4px base; 8px icon/label gap; 12px compact relation; 16px field/item gap; 20px summaries; 24px sections/columns; 32px desktop page gutters. Optical corrections must be owned once in the primitive, not random page offsets.

Inputs, selects and buttons align in filter rails. Metric links have one focus target, not nested buttons. Lucide icons remain consistent; logos keep text labels. Numeric columns right-align. Long identifiers are copyable/wrap or have a meaningful detail path, not hover-only truncation.

Measure body/supporting/placeholder contrast at 4.5:1 and relevant controls/icons/focus at 3:1 on actual composited backgrounds. Do not assume a token name proves contrast.

## States

| State | Required treatment |
| --- | --- |
| Default | Clear verb/object and semantic style. |
| Hover | 120ms wash/border/text feedback on fine pointers only. |
| Focus | Shared 2px ring / 2px offset, measured in both themes; not clipped. |
| Active | Immediate pressed feedback; optional 1px motion with static alternative. |
| Disabled | Clear state plus visible reason for important actions. |
| Busy | Saving/Starting/Verifying label, reserved width, no duplicate submit. |
| Invalid | Text error and field treatment; associated help; not color alone. |
| Success | Authoritative result; feedback follows shared policy. |
| Retained/stale | Real value plus as-of/error state; never zero substitute. |
| Selected | Stable selection; updates cannot steal focus or reorder under pointer. |

Create a shared state sheet for applicable states before route-specific work. [Feedback contract](16-feedback-responsiveness-and-daily-use.md) controls notification choice and timings.

Emergency stop may use a deliberate danger action. Large expert tables may scroll locally; mobile's main task cannot require reaching the far-right edge. Do not alter action semantics to satisfy a screenshot.

## Consistency gate

Compare headers, fields, tables, badges, tabs, overlays and traces across R1–R5. Exceptions require reason/scope/shared owner. [Surface decision](13-surface-color-decision.md) controls colors; no theme change is approved here. Use UI/UX Pro Max and Impeccable layout/typeset/harden/adapt/polish.
