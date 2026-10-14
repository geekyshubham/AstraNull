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
- **Chips/badges:** inset pill, mono uppercase label, semantic tint only for state. `Badge` adds no sans/mixed-case variant; the mono uppercase chip is the only shared chip style.
- **Tabs:** inset pill rail with pill selections, horizontal overflow, complete roving-keyboard behavior. When the rail overflows, the edge that still hides tabs fades out (`data-scroll-edges`, the same `useScrollEdges` hook as tables); never wrap a tab rail onto multiple rows.
- **Inputs/selects:** 4px radius, 44px control height, recessed token surface, visible compliant focus, bounded popup placement. The custom `Select` menu opens with fixed viewport coordinates taken from its trigger, so a card's `overflow: hidden` never clips options; the trigger references the listbox (`aria-controls`) only while it is open. A `placeholder` shows muted trigger text until a real option is chosen.
- **Tables:** scroll within their named keyboard-focusable region; mono uppercase masthead, 2px separation, zebra rhythm, orange hover wash and left edge, tabular numerics. Do not collapse data tables into unreadable mobile cards; the one sanctioned exception is the refined list tables (`.rf-stack-table`), which at ≤640px stack each record into labelled label/value rows because every row is a self-contained record. `DataTable` wraps the scroll region in `.table-scroller`, which shades whichever horizontal edge still has content behind it and shades nothing when the table fits — a column clipped mid-word at the card edge is otherwise indistinguishable from truncated data. A column may pass an optional `header` node (for example a select-all checkbox); the `th` renders it in place of `label`, while `label` stays the stacked-row `data-label`.
- **Confirm dialogs:** `ConfirmModal` may require a reason (`confirmWithReason`): a labelled textarea with a hint follows the description, confirm stays disabled until the trimmed reason meets `minLength`, and the text resets on close. Use it for every decision whose reason is recorded or shown to someone else (reject, suspend, disable, close, reopen). Irreversible traffic or account actions keep the danger tone and name the tenant or record.
- **Check layer and control chips:** `CheckClassChips` shows the network layer a check exercises (muted chip with a layers icon, e.g. `L4 · TCP`) and the protection control it tests (stronger-ink chip with a shield icon: `WAF`, `NFW`, `Edge`, `DDoS`, `DNS`). Both stay neutral because they are values, not state; the icon and text carry the distinction. Abbreviations are never hover-only: each control chip carries visually-hidden full text, and every list that shows them renders `CheckClassLegend` once above the rows. Detail pages use `CheckClassSummary`, which adds a plain sentence. Data comes from `classifyCheck` (`src/contracts/checkClassification.mjs`). Declaration-only checks add a dashed muted `Declaration only` chip (file icon) with visually-hidden "sends no traffic" text; the legend explains it.
- **Check prerequisites:** a check's prerequisite comes from the server's per-target answer (`GET /v1/checks?scope=all&target_id=` → `requires_additional_input` + `additional_input_reason`). Each reason code has one plain label, detail sentence, CTA and Controls section (`ADDITIONAL_INPUT_REASON_COPY` in `apps/web/react/src/lib/control-declarations.mjs`), e.g. `Needs a port`, `Needs a declared deny rule or a host:port target`, `Needs a declared TCP deny rule`, `Needs a declared UDP deny rule`, `Needs a declared connection limit`, `Needs a declared rate-limit canary route`, `Needs origin lockdown declared`, `Needs a denied perspective declared`, `Needs two perspectives`. The chip is warn-toned when the customer can close the gap; `SOC only`, `Not available yet` and the pre-answer `Checking this target` stay neutral. The client never derives the requirement from `runnable_requires`: before the answer loads a target-dependent check waits and is left out of run-all, category select-all and multi-select. A "Before it can run" row links to the reason's Controls section. Scan exclusions carry the same codes and use the same words and deep link. SOC-only checks never get a run button; they link to the SOC request path.
- **Control declarations editor:** one ruled `fieldset` per declaration (legend + one-paragraph hint that says what it unlocks), recessed 44px inputs, editable tables inside named scroll regions, and a sticky save bar that names the dirty state. Errors appear inline under the field (`aria-invalid` + `aria-describedby`) and in a focused error summary whose links move focus to the field; server `400 invalid_control_declarations` field paths map onto the same inputs. Leaving the tab or page with unsaved changes asks first. Saves send `If-Match` with the loaded revision's ETag. A `412` (or `428`) keeps the draft, disables Save and shows a focused, warn-outlined conflict panel ("Someone else saved these controls. Review their version, then re-apply your changes") with `Load latest`; the loaded version is compared with the draft section by section in a table that names the items only one side has, then the user explicitly chooses `Keep my draft and review` (their version becomes the baseline, the draft stays) or `Use their version` (confirmed). Nothing is ever overwritten silently.
- **Nested choice inside a declaration:** a follow-up choice that belongs to one declaration (for example the rate-limit canary's "When the limit is reached, the WAF should: Block / Block or challenge") is a borderless `fieldset.cd-subset` under a soft top rule with its question as the legend, radios side by side on wide screens and stacked on narrow ones. Each option carries a one-line consequence, and the server default is preselected so a save never drops a stored value.
- **Fix-verified closure basis:** a `fix_verified` finding names how it was proved, from `verification_basis` on the finding or its `finding.fix_verified` audit event: "Fixed — violation no longer reproduced (same perspective, ≥2 agreeing samples, all declared ports probed)" for violation-only checks, "Fixed — passing retest" otherwise, and "Fixed — verified by a later re-check (how it was verified is not recorded)" when neither source says. The same label names the audit row.
- **Closure basis in lists:** where fix-verified findings are listed, a short muted line under the status badge reads "No longer reproduced" or "Passing retest", only when the list item itself carries `verification_basis`; nothing is inferred when the field is absent.
- **Refusals that point outside Controls:** a refusal whose fix lives elsewhere on the target (for example `origin_binding_required`, "Needs one verified origin binding") deep-links to that section (Overview → Origin relations) with the same CTA styling as Controls links.
- **Origin lockdown prerequisite:** the Controls origin section says the check needs both `origin.lockdown_expected` and exactly one active origin relation, and shows the relation count under the choices (dashed note; solid warn outline only when lockdown is declared with no relation, or with several) with a link to Origin relations on the Overview tab (`tab=overview&section=origin-relations` focuses that heading). The rule-coverage CTA for origin lockdown opens this section.
- **Rule coverage matrix:** WAF and network-firewall tables (rule family, assurance, status, covered by, next step) under a status count strip, a layer filter and an assurance legend. Assurance chips are neutral values; status chips carry semantic tone plus an icon and text. "Not assessable" and "Out of scope" always show their reason, never "0 of 0". Missing declarations become a direct CTA into Controls. `Partial` assurance renders as a dashed chip with a dot icon and its reason in small text beneath, so it never reads like a full verdict.
- **Probe outcome evidence:** outcome chips (`Blocked`, `Challenged`, `Allowed`, `Redirected`, `Source penalized`), a per-placement table with a plain-language footnote, callouts for source penalties and normalization gaps, network facts with transport outcomes in words, IPv4/IPv6 parity and probe perspective, and a quiet dashed metadata row for grading and signature versions. Transport outcomes stay neutral in tone because whether an open port matters depends on what was declared. Suspected blocks on an unverified vendor signature, local probe errors and closed ports that do not identify a control always read as inconclusive, and a validated reflector reply reads as "open reflector reachable", never as a firewall-rule violation.
- **Not tested (missing input):** a run that finished with `explanation_reason: required_input_missing` sent nothing, so it reads as a muted "Not tested" chip, never as inconclusive or a gap. Run detail, scan steps, target check rows, run tables and the evidence inspector show the server's plain message (fallback: "Not tested — this check needs <input> on the target, so nothing was sent."), a quiet line that no requests were sent, and the matching Controls CTA from `ADDITIONAL_INPUT_REASON_COPY` when the missing input maps to a section (`NotTestedNote` / `NotTestedBadge`, `lib/missing-input.mjs`). Target check rows count it as "not tested", outside the inconclusive share. The UI adds no demo-specific gating; the per-target `requires_additional_input` answer alone decides what is runnable.
- **Per-port and perspective evidence:** a multi-port deny result renders a per-port table (port, what came back in words, the published "Violates your deny rule" / "No violation seen" result, IPv4/IPv6 parity). Declared ports beyond the request budget are listed in a quiet dashed note ("Not probed within the safe request budget") and never get an implied result. A perspective that is not authenticated with its own worker key carries the same dashed note: "Perspective not authenticated — result cannot prove an allowlist gap".
- **Verdict replay:** run and finding detail offer one secondary button, "Re-check this verdict with current rules", that fetches `GET /v1/test-runs/:id/verdict-replay` only on click. The result renders in a polite live region: `Unchanged`, or "Would now be" with the new verdict chip beside the stored one, plus a dashed note when grading or signature versions changed ("Grading rules changed — re-run to restore credit"). A missing replay (404) reads as a plain sentence, not an error banner. It never writes or changes the stored verdict. When the server re-graded the stored responses it reads "Re-graded with current signatures" (check-badge icon); otherwise a quiet line says only the verdict logic was re-applied, with `regrade_unavailable_reason` in words (no stored response details, or responses missing a status code), so signature changes are not implied.
- **Efficacy ("Is it working?"):** per-layer status from fresh, current-version results only, with the inconclusive share beside every ratio and managed rule markers reported separately from custom canary rules. Custom canary rollup members use the server's per-member `fresh` / `version_gap` answer (`custom_canary_rollups[].rolled_up_pairs`), so a version-gapped or stale member is ignored even when its run looks recent. A member's answer applies only to the run it graded (`last_run_id`); another run of the same check is judged on its own age. Under the custom canary line a disclosure lists each member with its verdict chip, counted / not-counted text and a link to its run.
- **Chips in narrow columns:** badges never break inside a word. `overflow-wrap: anywhere` made a badge's min-content one character wide, so a `HOSTNAME` chip in an auto-layout column rendered as eight stacked letters. Use `.badge-identifier` for chips that genuinely carry a long unbroken identifier.
- **Filter rails:** micro-labels are mono uppercase, matching the table masthead they sit against; search fields and selects share the 4px input radius and 44px control height.
- **Progress:** 7px pill track, semantic fills, transform-based value update.
- **Empty state:** 56px inset icon visual, concise heading/body, optional real action. Inside a card the heading drops to the base size so it never outranks the card title; an empty `DataTable` is the card's content, not a second bordered box.
- **Page header:** H1 uses the shared `--page-title-size/-weight/-tracking` tokens on classic and refined pages alike. No eyebrow or kicker labels above headings; the breadcrumb already names the section. Customers never see a Staff crumb or sidebar group (`routeCrumb`). Detail views name the open record in the document title (`useEntityDocumentTitle`), never in the breadcrumb. Context that carries information (tenant, staff-only surface, SOC workspace, report framework) renders as a muted `PageTitle` context badge beside the H1. At ≤700px header actions form an even, left-aligned grid.
- **Key/value lists:** `.kv-list` rows are direct-child grid rows — label column (9–14rem) and start-aligned value — separated by hairlines, not boxed. Nested divs inside a row carry no row chrome. One column at ≤480px.
- **Paired cards:** cards in a two-column grid size to their own content (`align-items: start`); never stretch a short card into an empty half.
- **Disclosures:** `<summary>` markers are CSS-drawn chevrons or lucide icons that rotate on `[open]`; never `+`/`−`/`▸` text glyphs.
- **Entity links:** links inside facts and table cells use `.detail-entity-link` (underlined text link), not ghost buttons.
- **Status tone:** orange is brand only; the `info` tone (`--info`) is neutral emphasis ink, never orange. Scheduled/approved/neutral labels are `muted`; running is `warn`; verified ownership (including DNS) is `success`. Zero-count severity chips are `muted`.

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
