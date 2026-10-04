# Contextual destinations and source review

2026-10-04. Current source plus retained current-release browser observations. This is a task/navigation and data-reading review, not a new live all-page audit. Line references are inspection locations and can drift after implementation.

## Confirmed destination problems

| Source location | Current action | Why it fails intent | Proposed contract |
| --- | --- | --- | --- |
| target-detail-view.tsx:1153 | Open evidence → internal result-record page | Label promises proof but opens a different object/workflow | Direct-check evidence inspector in the target workspace. |
| Existing result detail rendering | Proof components split before a complete answer | User must reconstruct the check result | Outcome + primary evidence together in target detail; technical depth optional. |
| page-components.tsx:2096 | Named check → #checks | Specificity lost; user searches library again | Exact check preview/detail with check_id and caller scope. |
| page-components.tsx:2783 | Individual support event View → #audit | No event selection/filter carried | Event ID/resource/time lookup; exact inline audit drilldown. |
| finding-detail-view.tsx:159,492,508 | Artifact selection → evidence-detail | Useful deep link, but primary explanation can require leaving finding | Inspector first, standalone artifact optional. |
| refined/finding-group-detail.tsx:328 | Lead finding for full evidence | Lead source doesn't answer each selected member | Per-member adjacent inspector and next/previous. |

These are proposed UX improvements, not applied patches. Exact target→run links and artifact links are valid navigation when the label matches; the issue is forcing object hopping for a simple evidence question.

## Existing good patterns verified

- AuditPage in governance-pages.tsx:1325 onward selects a row and renders custody/metadata below it; it also distinguishes no matches from no entries. Preserve selected drill-down; improve concise interpretation, placement and exact incoming-event context.
- SignupPage in public-pages.tsx:1893 links Check status with the returned request ID.
- SignupStatusPage at 1938 onward reads/trims the query ID and performs lookup.
- SetPasswordPage at 1469 onward preloads an invitation token from query and removes it from the address bar. Manual paste is a fallback, not the only supported path.
- TargetsPage:284 navigates a newly created target to its own detail; target links are explicit.
- Target profile and group controls already carry some direct-check/group context. Unify/preserve those rather than describing every start as wholly absent.
- Finding detail contains explanation, triage/remediation and an evidence bundle with its own loading/error/retry state. The required improvement is coherent first-proof access, not recreating evidence from scratch.
- Existing shared DataTable prevents nested controls from accidentally activating row navigation. Keep that event-ownership behavior in inspector-enabled rows.

Some earlier handoff statements described missing first-use/request continuity too broadly. This current-source clarification supersedes them: preserve implemented ID/token/context behavior and test actual remaining transitions.

## Navigation implementation boundary

lib/route-params.ts currently builds entity-ID links and optional tenant scope; finding groups use a canonical key. It does not establish all proposed inspector/cohort/search/report-preview parameters. Centralize a reviewed typed contract instead of each page inventing hashes. Router and route-access remain authoritative.

Every named action should resolve an exact authorized entity, scoped collection, editor, or execution review. If only a broad route exists, label it View all runs/audit/checks truthfully until a contextual destination is implemented.

## Data-to-decision source checks

Route dataset definitions in lib/types.ts load different subsets. New inspector must fetch authorized missing source data rather than assume another visited page already populated cache. Cold deep links must work. Do not preload every artifact/detail to make a table look instant.

The source renderer is not automatically a source of truth: current vendor/source inference and unknown defaults in document 09 remain hazards. The inspector must display recorded relationships and distinguish absent data from forbidden/error/stale state.

Support subscription-summary open counts and report historical snapshots can differ from current finding state. Label source/as-of and reconcile definitions; do not treat every discrepancy as an arithmetic UI bug without inspecting the contract. Returned IDs are identifiers, not proof of integrity.

## What was not done

No new pages were live-clicked for this addition, no user study was run, no provider/contact/test traffic or external messages were sent, and no code/tests/data were changed. New docs use prior browser evidence as baseline and source inspection to validate action intent. This prevents a handoff recommendation from pretending to be new execution evidence.

## Source attribution

Apple's official tab-bar documentation was checked via its documentation data response. It recommends preserving navigation state when switching sections and separates navigation from actions. AstraNull adapts this principle through documents 16,19,20; it does not copy native tab geometry/materials or claim native platform compliance. [Apple navigation guidance](https://developer.apple.com/design/human-interface-guidelines/tab-bars).

Existing source paths are implementation references, not assignment of deferred pages. Current source paths are under apps/web/react/src/pages unless noted above. [All-page review](21-all-page-data-and-task-review.md) records each route’s decision, visible data and continuation contract.
