# Contextual evidence inspector — answer beside the result

2026-10-04. Proposed UX/data contract, not implemented UI. Source reviewed with the saved current-release browser evidence. No fresh all-page live click-through or new user-study result is claimed.

## Core decision

**View evidence opens the relevant proof where the result appears, in one user action.** It must not mean “go to a run, select another tab, locate an artifact.” Target/check/recorded-execution/artifact identities remain provenance. The current product journey is target → direct check → result/evidence in place; internal execution IDs do not require a separate navigation page.

Answer **What happened? Why? What should I do?** together. Four technical tabs are not a substitute for a coherent answer.

## Presentation

Desktop: inspector beside the current list/work area when enough width exists; otherwise a single evidence drawer. Mobile: safe full-width evidence workspace/sheet, reachable Back/Close and retained originating context. Do not squeeze a two-column inspector into a narrow viewport or stack modals.

Initial view:
1. Exact target and check/result identity, observation time and scope.
2. Recorded outcome, plain-language explanation and limitations.
3. Expected versus observed behavior.
4. Relevant recorded operation/request and response summary.
5. Source/provenance, evidence freshness and current integrity-verification state.
6. Permission-appropriate next action: review retest, inspect related finding, or expand investigation.

The answer and primary supporting evidence are visible together. Request/Response/Evaluation/Evidence selectors, raw events, full redacted artifacts, hashes and custody details hold secondary depth. [Live trace](03-live-check-observability.md) governs safe content; provider-specific proof uses [host profile](06-host-protection-profile.md).

## Entry-specific resolver contract

| Entry | Required selection | Initial proof | Guard against |
| --- | --- | --- | --- |
| Finding row/result | Finding ID, exact target, originating run/evidence refs | Evidence that opened that finding; subsequent retest separately | Replacing original failure with latest passing run. |
| Grouped finding member | Group key plus selected target/member finding ID | That member’s outcome and sources | Representative evidence silently used for siblings. |
| Direct check result | Exact check-target pair and recorded execution/event | That outcome’s operation/response/evaluation | Latest check on another host. |
| Provider badge | Target ID, family/provider/layer and observation | Recorded family-specific signals, time and run/artifact | WAF vendor used as CDN/hosting attribution. |
| Dashboard gap/action | Exact finding or a named cohort/filter/snapshot | Single finding inspector or matching cohort with visible predicates | General list with missing filter. |
| Artifact link | Exact artifact and source context | Available record/content plus actual integrity status | “Recorded digest” treated as verified custody. |
| Report result | Report snapshot plus captured refs | Historical snapshot evidence; live state separately | Today's results rewriting old report. |
| Audit event | Exact event/resource context | Recorded actor/change/time and permitted refs | Claiming audit action proves infrastructure fix. |

A click may trigger several authorized data reads; “one action” measures user interaction, not one HTTP call or instantaneous load. Loading must preserve context and show what is being fetched. No guessed IDs or broad latest-record fallback.

## No-evidence and contradiction behavior

- No source refs: “Supporting evidence not recorded for this result,” explain available metadata and offer only meaningful recovery.
- Pending evaluation: show actual execution phase/recorded events; no fabricated completed explanation.
- Ref exists but read fails: evidence unavailable + Retry; do not label no evidence.
- Permission denies artifact: show access boundary; do not fetch through a privileged alternate endpoint.
- Partial metadata: render recorded fields; omitted request/response says Not recorded.
- Conflicting findings/current pass: preserve original evidence, latest result, their timestamps and unresolved lifecycle.
- Multiple primary artifacts: select using explicit relationship/evaluation refs; list relevant alternatives. Do not pick arbitrary first artifact.
- Deleted/retained-expired source: mark unavailable/expired explicitly, retain permitted identity and safe return.

## Next actions and execution boundary

Inspecting a result never starts a probe, verifies DNS, exports a bundle, delivers a message, or changes lifecycle. Use separate explicit buttons. Retest opens a scoped review with target/check preselected and current authorization/bounds rechecked; it is not an automatic replay of unsafe or expired scope.

Open full investigation is a link to the permitted target/check or artifact context. It carries selected record/section through a supported route contract. Until a target/check evidence address exists, use an honest in-place loading/error state; do not introduce a separate history/detail page as the required route to proof.

Standalone evidence artifacts may remain useful for bookmarks and forensic work; direct-check results are shared through the target/check inspector. Shared links resolve their own entity and authorization on cold load; they cannot depend on browser-only background state.

## Navigation state

Store origin route and its allowlisted search/filter/sort/page/row/check/expanded-section state plus scroll/focus reference. Close restores it; browser Back behaves consistently with the inspector history policy. Choose one policy per shared inspector:

- Opening pushes an inspectable address/state; Back closes it before leaving the list.
- Switching related records replaces selection or advances bounded inspector history deliberately.
- Expand to full page retains a return reference; direct load has a real canonical parent fallback.

URL schemas are proposed. Current detail routes support entity IDs but not every filter/section contract. Opaque references are navigation hints, never authorization. Revalidate tenant/record access server-side. Do not place credentials, raw payloads, invitation tokens or arbitrary metadata in URL/storage.

If the original row vanished, return to the same filtered list and nearest relevant context with explanation. New live data does not jump scroll, dismiss the inspector or steal focus.

## Frontend and backend handoff

Reuse existing evidence/error/custody formatting, dialog primitives, named scrollers and selected-row patterns. Audit’s existing drill-down demonstrates contextual inspection; enhance it rather than rebuilding that feature from scratch.

Frontend: one shared inspector controller/schema, recorded-summary rendering, responsive layout, keyboard/focus, stale-result cancellation, stable selection and contextual return. Avoid loading every source artifact on page arrival.

Backend: permission-scoped relationship projection if current reads cannot deliver the relevant evidence, exact finding/run/target/artifact linkage, redaction, source age and integrity result. Endpoints listed in source remain authoritative; a normalized inspector payload is a proposal, not a new implemented API.

Tie async reads to the active entity/tenant generation; late responses must not populate the inspector for a different selection. Cache only safe permitted data with defined freshness; invalidate/revalidate on role or tenant change. Bound raw-event/history reads.

## Acceptance IDs

- EI-01: finding row → primary supporting evidence is visible after one activation, with no mandatory route/tab/artifact hunt.
- EI-02: provider click → matching family-specific source with exact target/time.
- EI-03: original gap and later pass both remain distinguishable; no source substitution.
- EI-04: group member Next/Previous changes selected member only; no loop back through the list.
- EI-05: Close/Back restores filters/page/selection/scroll/focus; full deep link works from a fresh session after authorization.
- EI-06: no refs, denied source, partial data and failed fetch have distinct messages and safe recovery.
- EI-07: selected completed check stays selected during live updates; late responses never cross entity/tenant.
- EI-08: no inspection click executes traffic/exports/messages; retest is a separate governed review.
- EI-09: answer and supporting summary appear together; technical tabs are optional depth.
- EI-10: dark/light, keyboard, mobile, text zoom and reduced motion remain usable.

Use UI/UX Pro Max, Impeccable shape/clarify/harden/adapt/animate/polish and existing [shared standards](12-component-visual-specification.md). A senior engineer should agree evidence relationships before page agents wire misleading “View evidence” controls.
