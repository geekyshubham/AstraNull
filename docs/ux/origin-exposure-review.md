# Origin exposure UI review

Date: 2026-10-16. Mode: **Evaluate + Modify**, preserving AstraNull's existing React components, flat ruled layout, tokens, typography and orange primary action. Scope: target Overview source associations, exact origin evidence and reviewed paired identity plans.

`ui-design-studio` was loaded. Its companion skills and Better Design MCP were not available; their checklist was applied directly. No dependencies, installers, remote design uploads, credentials or customer data were added or sent to design services.

## Evidence and limits

There are no before screenshots or measured before scores for the new workflow. The Before column below is therefore **not measured**, not an invented baseline; a numerical delta cannot be claimed. After scores are an engineering assessment on a 1–5 scale, not an automated certification or human sign-off.

The combined Chromium run passes **47/47**, zero retries/skips: 15 origin workflow cases plus 32 existing protection-validation cases. Source: `/tmp/astranull-origin-browser-final.log`. Browser scenarios use isolated fixtures and the local API; paired plan responses are mocked and never started. Real reviewed starts, authority and finalization are covered separately by Node/PostgreSQL tests. Final source-label follow-up is recorded in `PROGRESS.md`.

Screenshots from that passing run were visually inspected at dark 1440px and light 390px:

- `/tmp/astranull-origin-browser-final/tests-e2e-journeys-portal--705d9--accessible-source-evidence-chromium/origin-overview-dark-1440.png`
- `/tmp/astranull-origin-browser-final/tests-e2e-journeys-portal--d030c--accessible-source-evidence-chromium/origin-overview-light-390.png`

All four theme/width cases save full-page screenshots after returning to the top, without hiding sticky application chrome. Automated checks cover 390/1440px, light/dark, escaped long references, IPv6 wrapping, keyboard disclosure, reduced-motion preference, panel-scoped WCAG 2/2.1/2.2 AA axe and 44px coarse-pointer source controls. These are not all-page accessibility certification, real Google Fonts metrics, or a performance benchmark. The shared hermetic stylesheet fixture uses system-font fallbacks.

Latest review follow-up: the complete origin/evidence-target journeys pass **54/54**, zero failures/skips/retries (`/tmp/astranull-review-origin-session-and-evidence-v3.json`). The served-bundle responsive run passes **10/10** across light/dark 375/768/1024/1440px and equivalent 200% reflow (`/tmp/astranull-review-origin-responsive-v6/report.json`), with zero panel/page overflow, scoped axe violations or strict diagnostics. Full-page 375/1440px screenshots in both themes were inspected. This adds short-viewports, long imported references, keyboard dialog/disclosure and 44px coarse-touch evidence; it is not native browser zoom or human acceptance. Earlier temporary keyboard-harness failures remain retained: instrumentation showed focus leaving the document for native browser chrome while the dialog stayed modal/open, not background page focus. The corrected check permits only that native escape and still rejects focused background content. Whole-source release gates remain separate.

## Scorecard

| Dimension | Before | After / 5 | Evidence |
|---|---|---:|---|
| Visual hierarchy | Not measured | 4 | Three-step evidence/authority sequence; collection is the primary action and source details are secondary. `origin-exposure.tsx` workflow/toolbar; desktop screenshot. |
| Typography | Not measured | 4 | Existing font tokens, monospace addresses/provenance and bounded explanatory text. `origin-exposure.css`; desktop/mobile screenshots. |
| Color and contrast | Not measured | 4 | Existing semantic badges and both themes; links are persistently underlined. Four scoped axe cases pass. |
| Layout and spacing | Not measured | 4 | Token spacing, ruled records, desktop columns collapse on mobile; no tested page/panel overflow. `origin-exposure.css`; browser suite. |
| Consistency | Not measured | 5 | Reuses Badge, Button, ConfirmModal, existing request/session/Inspector APIs and portal tokens. No UI dependency additions. |
| States and interaction | Not measured | 4 | Loading, disabled, forbidden, read-only, failed read/retry, empty, unavailable coverage, explicit review/cancel and persisted import covered. Pagination/mutation races have guards but not every browser permutation is exercised. |
| Accessibility | Not measured | 4 | Explicit field names, section headings, keyboard disclosure/focus, status/error semantics and 44px coarse-pointer controls; panel-scoped axe passes. No universal certification. |
| Responsiveness | Not measured | 4 | 390/1440px in both themes, long source/digest wrapping and IPv6. Existing comparison suite also covers 375/768/1024/1440px. |
| Motion | Not measured | 5 | No animation/effects added; reduced-motion browser preference covered. |
| Performance | Not measured | 3 | No dependencies, images, external fetches or effects; paged persisted reads. Whole-app Vite build is about 2.35 MB JS / 636 kB gzip and 416 kB CSS / 62.5 kB gzip. Incremental feature cost, CLS and runtime render cost were not independently measured. |
| Copy | Not measured | 4 | Unknown/stale/unavailable sources remain explicit. Association, declaration, response, nonce identity and WAF/lockdown/capacity conclusions are not conflated. API/runtime authority remains the final gate. |

## Findings and disposition

- **High — evidence/authority conflation:** source records are explicitly unverified; they cannot create or start targets, bindings or application probes. Historical evidence is separate from current authorization. Pair review lists both destinations, proof references, scope and limits; missing paired plans cannot open Start confirmation.
- **Medium — inaccessible exact field names:** explicit labelled-by references were added to source type, source reference, file and comparison mode controls. Keyboard and locator regressions cover the rendered workflow.
- **Medium — link affordance/contrast:** persistent underlines and focus outlines fix the axe text-link finding without changing the palette.
- **Medium — empty versus failed sources:** unavailable reads are not rendered as empty; latest DNS-question failures and partial coverage remain visible. Retry is explicit and passive. Whole-browser review reproduced unnecessary 404 hydration while the feature was default-off; the authenticated tenant feature response now exposes exact `origin_clues` opt-in and the Overview skips all clue reads and mutations unless it is true. Backend gates and default-off/demo behavior are unchanged. A real disabled-server regression fails before repair; the complete origin UI suite then passes 16/16, zero retries/skips (`/tmp/astranull-review-origin-feature-hydration-{red,green}.log`).
- **Medium — session-scoped opt-in:** a same-route dev-role transition reproduced two replacement-session clue reads before its own feature hydration completed. App now associates each generation-approved payload with the route-scoped session identity and withholds deployment features on a mismatch. The delayed-feature browser regression is red before repair, then all 17 origin UI cases pass with strict diagnostics in `/tmp/astranull-review-origin-session-and-evidence-v2.json`; that combined run still fails a later, unrelated archived-relation locator and is not a complete evidence-target or release pass. Backend authorization is unchanged. The initial route-changing attempt only encountered a loading mask and was not proof of this issue.
- **Medium — mobile provenance overflow:** addresses, references, digests and details wrap; the workflow and metadata collapse to one column.
- **Open — broader acceptance:** no person has signed off the rendered UI. The shared ConfirmModal mobile scroll/title issue previously tracked under PV-07 remains outside this slice. Full release/scale/performance gates, source-bound delivery reconciliation and authorized live canary acceptance are separate and must not be inferred from these local screenshots or tests.

## Changed UI surfaces

- `apps/web/react/src/components/targets/origin-exposure.tsx` and `.css`
- `apps/web/react/src/lib/origin-exposure.mjs` and `.d.mts`
- `apps/web/react/src/pages/target-detail-view.tsx`
- `apps/web/react/src/components/targets/origin-relations.tsx`
- `apps/web/react/src/components/targets/entry-paths/path-comparison.tsx`
- `apps/web/react/src/lib/protection-validation-api.ts`
- `apps/web/react/src/lib/control-declarations.mjs`
- `src/lib/checkPresentation.mjs`

Backend scope, tests and unresolved operational gates: [origin execution](../backend/current-release-origin-execution.md), [test strategy](../backend/05-test-strategy.md), [research](../detection/24-origin-exposure.md) and `PROGRESS.md`.
