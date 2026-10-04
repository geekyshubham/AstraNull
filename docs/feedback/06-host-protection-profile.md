# Host protection profile — product and UX specification

Added 2026-10-04 from the user-supplied protection-profile brief and senior frontend/backend consultations. **Markdown handoff only.** Existing field support is distinguished from proposed contracts in [engineering review](09-engineering-consultation.md). This extends the original reviews; it is not evidence that the features have been implemented or newly browser-tested.

## Design decision

Make **Target detail → Protection overview** the primary host profile. It is a view of an existing declared target, not a new Host object, cloud inventory or agent/environment page. The customer-facing inventory remains **Targets** because scope includes hostnames, IPs, CIDRs and supported URL targets. Within a hostname view, “Host protection profile” is useful task language.

The profile answers: Who serves this endpoint? What controls have been observed? What did the checks establish? What remains unknown or untested? What should the owner do next?

## Placement and hierarchy

| Area | What belongs there | Interaction |
| --- | --- | --- |
| Header | Hostname, ownership, declared service purpose, owner, criticality, group/tags | Edit declared context when authorized; copy identifier. Technical ID stays secondary. |
| Protection overview | CDN, WAF, hosting, and DNS provider observations as separate labeled rows | Each provider badge opens its own evidence inspector. Unknown is an explicit value. |
| Readiness dimensions | Application, origin lockdown, network/transport, DNS and customer operational checks | Open applicable checks/evidence for that exact target and dimension. |
| Priority actions | Most important unresolved finding/change, affected endpoints, owner and retest path | Open remediation context; retest review restates scope and bounds. |
| Validate tab | One check queue and selected-check Request/Response/Evaluation/Evidence view | Launch bounded checks, follow running work, inspect earlier results. |
| Changes & history tab | Confirmed provider/behavior changes, previous evidence, remediation/retest lineage | Compare before/after observations and open source runs. |
| Findings tab | Exact-target unresolved and resolved finding context | Preserve source evidence and lifecycle; no universal group closure. |

Recommended target tabs: **Overview · Validate · Findings · Changes & history**. Existing Protection path/WAF-CDN evidence/Recent runs content should be reorganized into these tasks, rather than adding another profile card above every existing workflow. Tab migration and aliases are proposed work; preserve existing deep links until explicitly handled.

## Desktop wireframe

```text
Targets / checkout.example.com                   [Run validation]
Ownership verified   Login + API · Declared       [Edit context]
Owner: Payments team · Criticality: Critical · tags: payments

PROTECTION OBSERVATIONS                           NEXT ACTIONS
CDN: Provider A · observed 2h ago  [How identified] Review origin exposure
WAF: Provider B · observed 2h ago  [How identified] Owner: Payments team
Origin hosting: Unknown          [Why unknown]    [Evidence] [Review retest]
DNS provider: Not checked        [What we know]

READINESS BY DIMENSION
Application    Gaps found              8/12 applicable checks evaluated
Origin         Passed tested checks    declared origin only · last observed
DNS            Insufficient evidence   2 inconclusive · 3 not checked
Network        Not applicable          no declared compatible scope
Operations     Declarations recorded   rehearsal evidence not recorded

[Overview] [Validate] [Findings] [Changes & history]
```

Illustrative content above is not a tenant result. Use a flat, ruled definition list for observations and a compact dimension table. Avoid four identical nested provider cards or a second large donut. At 375px, retain identity, next action and status, then stack dimensions; evidence opens full-width within safe dialog/drawer margins.

## Field-level behavior

| Field | Required representation | Provenance / limitation |
| --- | --- | --- |
| Identity | Exact hostname/value and target kind | Customer declaration; never create inventory from inferred IPs. |
| Service purpose | Website, API, login portal, DNS service, network endpoint, or Unclassified; multiple roles allowed | Declared and Observed/Suggested sources are labeled separately. An owner must confirm suggestions if used as business context. |
| Owner | Declared team/contact; Unassigned if absent | Finding assignee, WAF owner_hint and service owner are not automatically the same entity. |
| Criticality | Customer-declared value or explicitly inherited group declaration | Finding severity is not business criticality; never infer sensitive business purpose from a hostname. |
| CDN | Provider/product, signal state, last observation, provenance | A provider may have multiple products/roles; presence does not prove capacity or blocking. |
| WAF | Provider/product; detected, not detected, inconclusive, not checked | Fingerprinting and evidence-backed effectiveness are separate. |
| Hosting | Origin hosting/provider when attributable; otherwise **Origin hosting unknown** | Cloudflare edge addressing does not identify the origin cloud. An observed cloud/edge signal is labeled by its actual layer. |
| DNS provider | Recorded authoritative-DNS provider signal/declaration | Do not infer it from CDN/WAF vendor. Unavailable source remains unknown. |
| WAF effectiveness | Applicable check evidence: blocked, application reached only if established, inconclusive, not checked | A passed transport request or HTTP status alone does not establish application reach or WAF blocking mode. |
| Origin exposure | Authorized checks against an explicitly declared/bound origin endpoint | No undeclared endpoint probing; no estate-wide inference from one direct-origin observation. |
| Validation coverage | Evaluated applicable check-target pairs versus applicable plan; conclusive and inconclusive separate | Scope/catalog version and evidence window are visible; stale evidence is not current completion. |
| Maintenance | TLS/certificate/DNS/reachability problems in a separate section | Operational investigation signals, not automatic DDoS failure verdicts. |

An unreachable or broken-TLS declared target stays visible. Explain transport failure and unknown protection; do not remove it from the denominator to improve the coverage percentage.

## Provider evidence inspector

Clicking a specific provider badge opens **How we identified this**, scoped to that family and target. Show observed signal and method, DNS/CNAME chain or address attribution where recorded, permitted HTTP fingerprints, per-layer confidence/conflict, corpus/version, observation time, exact run and artifact. Include a concise limitation and current freshness.

Provide keyboard activation, associated title/description, preserved scroll, Escape/Close and focus restoration. Confidence is displayed only if the backend supplies a meaningful per-layer value. Do not invent a percentage from a provider logo, assume missing sources, call every resolved IP Anycast, or substitute a WAF vendor as CDN/hosting attribution. Sources must be recorded, not a generic explanatory sentence.

## Dimensional readiness semantics

- **Application:** bounded application/rate-limit/timeout/control behavior in the recorded scenario.
- **Origin lockdown:** directly reachable/not reachable/inconclusive for the authorized declared origin and observation window.
- **Network/transport:** bounded protocol/reachability findings for declared compatible endpoints.
- **DNS:** applicable bounded DNS evidence; authoritative DNS and web host associations need explicit scope.
- **Operations:** distinguish contacts/authorization/stop-process declarations from recorded rehearsal evidence.

Each row shows status, scope, observation time, applicability, tested/remaining counts and a source link. “Passed tested checks” is preferable to “DDoS protected.” A score may summarize published readiness only with formula/version, evidence age, coverage and unknown dimensions. Bounded checks do not establish volumetric capacity.

## Required empty/error states

Not checked; ownership pending; detecting; usable negative observation; conflicting/inconclusive; historical but stale; source unavailable; optional integration disabled; no compatible declared scope; no conclusive effectiveness checks; context unassigned. Detection uncertainty and stale historical facts may coexist; preserve both rather than overwriting historical identity with a blank.

## Motion and skills

Use [motion guidance](02-motion-and-interactions.md). A provider evidence drawer can enter over 200ms; a new observation briefly emphasizes the changed row. No fake traffic path, guaranteed green shield, animated vendor carousel or staged “analysis” typing. Reduced motion displays settled data immediately.

Use UI/UX Pro Max for hierarchy/comparison, Impeccable shape/layout/clarify/harden/adapt/animate/polish and interaction-design. Reuse existing domain-protection, Tabs, DataTable, disclosure, provider-logo and dialog primitives; [actual skill references](05-skills-and-handoff.md).

## Acceptance criteria

1. CDN, WAF, edge/cloud hosting, origin hosting and DNS roles never borrow attribution from each other.
2. Every displayed provider/claim can be opened to recorded family-specific evidence or labeled declaration.
3. Declared purpose/owner/criticality and observed service behavior remain separately sourced; unknown is visible.
4. A WAF detected but untested host does not appear as effectiveness validated.
5. Zero compatible scope is Not applicable; failed/unreachable scope is investigated, not excluded silently.
6. Each dimensional result is exact-target scoped; direct bounded checks do not establish volumetric capacity.
7. One target validation flow remains after reorganization, with stable deep links, keyboard, mobile and reduced-motion behavior.
8. Rich metadata fields/history not supported today are implemented and verified before the UI promises them.

## Shared visual/task handoff

Use [reference specifications](11-reference-screen-specifications.md), [component standard](12-component-visual-specification.md), [responsive budgets](14-content-and-responsive-task-budgets.md) and [feedback/navigation](16-feedback-responsiveness-and-daily-use.md). Page focus: R2/R5; J1/J2/J4; T2 unknown and T4 dimensional evidence. See [acceptance gate](17-design-acceptance-and-handoff-gates.md). All references remain proposed until rendered and explicitly approved; user task results are Not run.
