# Surface notes — Vibe annotations 2026-08-29

## Public landing and login
Keep the existing source fixes: split the readiness delta into two rows, `#proof` lead padding of `--space-5`, and content-fit auth badges.

## Environment/list tables
Use shared `DataTable`; no environment-specific table skin. Numeric/status/action columns may add reusable alignment metadata only.

## Target groups and target detail
Remove page-level `stack-tight`; use plain-language protection summary → target inventory → verification → schedules/rules → governance. On target detail, show detected WAF, CDN, cloud-hosting, and origin-access layers before the verification ledger. Detection is never presented as effectiveness. API-provided plain-language summaries win; cautious evidence-derived copy is the fallback. DNS challenges bind to an explicit target. Eligibility fails closed. LOA copy separates safe checks from SOC-gated execution.

## Dashboard executive brief
The Overview tab answers four questions before technical metrics: readiness for the scenarios actually tested, reported protection layers, categorical WAF effectiveness, and up to three evidence-backed fixes. Never turn a score into an unconditional claim of DDoS readiness. Keep the existing KPI row, posture chart, tables, and weighted factors as progressive engineering detail. Technical verdict keys and evidence tiers remain available in an accessible glossary rather than leading the page.

## Plain-language evidence vocabulary
- `E1`: Declared only. Not tested live; customer evidence is still needed.
- `E2`: Connection observed. Live network behavior only.
- `E3`: Behavior observed. Live application or protection behavior.
- `E4`: SOC-governed. High-scale validation remains staff controlled.
- `E5`: Monitoring only. No active check.

Lead with outcome language such as “Protection stopped the test traffic,” “Attack traffic reached your server,” and “Not enough evidence.” Preserve raw values in provenance titles or secondary technical keys so engineers and auditors do not lose precision.

## Integrations and Targets
Provider directory is an intake surface, not cloud discovery. Show supported/manual mode honestly. Single-domain declaration uses the same normalization/provenance contract as imports. Targets is table-first with provider/source, concrete verification provenance, eligibility reason, group, created time, and safe actions.

## Subscription
Error/retry before empty state. Flatten plan facts, keep the entitlement table authoritative, show usage as reported counts with freshness, and use 3/2/1 responsive columns.

## Agents
Registered-agent evidence table comes first. Never silently choose the first target group for a token. Keep trust/update/install operations secondary and responsive; compact mobile rows to essential evidence.

## Refined variant (Test policies, Runs, Findings)
Opt-in per page through the Classic/Refined switch in the header (role=group "Page design", aria-pressed); Classic stays the default. All Refined styles are scoped under `.refined` in `styles/refined.css` and use tokens only. Header uses a fixed rem step, summary strips hold real counts (two columns on phones with dividers that follow the grid), stat numerals use the body font with tabular figures, segmented controls stay one row, and disabled controls keep full opacity with `--muted` text. On phones, tables marked `.rf-stack-table` become label/value cards so status, SLA, and owner stay visible without sideways scroll.

## Grouped-alert detail
Refined Findings groups findings by alert (same check plus normalized issue) and links each row to `#finding-group-detail?key=`. The detail page shows the alert's severity, meaning, and every affected asset with status, SLA, and owner, each linking to the existing finding detail for triage and retest. It has only a Refined layout; choosing Classic saves that preference and returns to `#findings`. Severity counts and badges share one normalization (S1-S4 map to critical/high/medium/low).
