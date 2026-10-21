# Assistant advisory surfaces

Status: implemented locally; integrated acceptance and production enablement remain separate. See [ADR-0039](../adr/0039-assistant-advisory-snapshots-and-personal-widgets.md), [API contracts](../api.md) and [test strategy](../backend/05-test-strategy.md).

## Shared interaction contract

All five surfaces are optional, outside-in and advisory. Use existing typography, semantic light/dark tokens, shared controls and restrained state-change motion. No decorative glow, page-load choreography, fabricated progress percentage or invented chart. Reduced motion renders the final state immediately. Text and configuration snippets are escaped, never executable markup.

Generation is explicit. Loading, unavailable runner, invalid output, cancellation and explicit retry are distinct states. A computed fallback is not labelled AI-written. AI text identifies itself as advisory and cites only the exact authorized snapshot. Old results must not appear after target, provider, filter, session or credential changes. Client polling disposal is not proof of server/model cancellation; explicit cancellation and late-creation cleanup use the existing job DELETE endpoint. Cancellation cannot guarantee interruption of an already-running external process.

Snapshots are dated and bounded. Missing observations are unknown, not proof of protection. Generation does not change findings, scores, provider configuration, schedules or runs. Current result retrieval rechecks source access; it does not assert that evidence content is unchanged since generation.

## Finding: provider fix packs

Place the Generate action beside existing provider guidance, retaining that guidance even on error. The provider choice is a remediation lens, not new attribution evidence. Show prerequisites, ordered changes for manual review, verification, rollback, limitations and official source links. Copy only inert text. There is no Apply, automatic retest or close-finding action. Changing provider or finding discards the previous pack and cancels pending work.

Acceptance: explicit generation/copy/cancel/retry; unavailable and invalid-answer fallback; source/provider binding; inert malicious text; session/provider disposal; no infrastructure or execution mutation.

## Target Overview: combined-risk stories

Keep observed finding metadata separate from conditional hypotheses. Every hypothesis cites one or more supplied findings; a combined story does not establish exploitation or causality. Expandable facts expose recorded status, severity, age labels, evidence IDs and an entry to the existing evidence inspector. Missing evidence and incomplete selection remain visible. No readiness credit or new finding grouping is created.

Acceptance: exact single-target scope, observed/hypothetical distinction, citations/inspector links, unknown/stale/incomplete labels, empty state, invalid-answer fallback, cancel/retry and stale-route disposal.

## Target Overview: validation recommender

Show a bounded proposal from the complete target-specific check catalog. Explain selected order and excluded prerequisites. AI can suggest only existing eligible candidate IDs. Users may adjust at most twelve checks. Require an explicit exact-target/check review checkbox before opening the normal scan launcher with that selection prefilled. Opening the launcher must not submit. Existing final review, ownership, declarations, scope, governance and backend admission remain authoritative. Read-only roles see proposals but no launch action.

Acceptance: exact checked IDs and target reach launcher; no run/schedule POST before ordinary confirmation; missing/partial catalog fails closed; unsupported check IDs rejected; unavailable AI retains computed candidates; cancellation and role/session changes dispose results.

## Findings: natural-language filters

Provide a question field and explicit Preview action. Show the exact supported predicates before Apply. Apply replaces real server-query state, switches to individual findings and resets pagination; it does not filter only loaded rows. Clear returns to ordinary filters. Shared URLs contain validated predicates only, never the raw question.

Supported AND predicates: `q`, `status`, `severity`, `check_id`, `target_id`, `test_run_id`. Literal search requires an explicit quoted search. Unsupported OR, negation, providers, dates, SQL, ambiguous identities or multiple values are refused with an explanation, not approximated into a broader query. Existing server totals remain authoritative.

Acceptance: preview/apply/clear, exact URL and query equivalence, pagination reset, unsupported/invalid/foreign IDs, no prompt in URL/storage, explicit retry and scope/input disposal.

## Dashboard: personal AI widgets

Use predefined Measured summary or Finding list renderers. Name, question and exact severity/declared-target filters are durable personal definitions, not generated code. A question never changes data predicates or creates a metric. Preview deterministic data before Save. Show an explicit conflict/reload action rather than overwriting edits from another tab. Remove uses confirmation and deletes only the definition. When current target access is unavailable, show a generic unavailable card using only the owned definition's ID/version, with no saved name, question, target or data. Explicit removal remains available so hidden definitions cannot permanently consume the twelve-widget quota; editing and data refresh remain denied.

Reload and Refresh data requery observations without asking a model. Ask AI is separate and explicit. Never automatically regenerate commentary on reload. Keep count completeness, sample limits, source links and refresh time visible; no findings is not proof of protection. Counts use at most 200 matching findings and lists show at most six. Unknown completeness must be labelled as a bounded sample rather than a workspace total. Commentary cites the displayed authorized snapshot and is not saved in the definition or browser storage.

Acceptance: preview/save/edit/version conflict/reload/remove; current scope revalidation; tenant/user isolation; no silent AI calls; explicit cancellation including late creation; invalid citations; stale definition/version rejection; empty/unavailable state with retry; same-session credential disposal.

## Rendered verification

Exercise 375, 768, 1024 and 1440 px in light and dark themes, keyboard focus/disclosures, reduced motion, page/panel overflow and scoped serious/critical axe checks. Attach strict browser failure collection before navigation, use zero retries and preserve intentional exact API fault allowances. System-font fixtures do not prove Google Fonts metrics or provider availability. Screenshots and automated checks do not substitute for human design approval or production/live-model acceptance. Record actual completed gates in `PROGRESS.md`, not inferred coverage.
