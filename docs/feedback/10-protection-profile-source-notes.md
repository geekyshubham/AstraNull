# Protection-profile source notes and requirement traceability

Added 2026-10-04. User input: attached “Yes—AstraNull should give every host a clear protection profile” text. The original attachment was read; its referenced 12-page assessment PDF was **not independently reviewed in this addition**. Preserve that distinction from the pasted text’s account of a prior review.

## User-supplied example

The brief reports 142 of 178 web applications classified as WAF protected, but only 12 of 31 login pages. Treat these as quoted report classifications illustrating segmented exposure, not independently verified results, AstraNull tenant data, sample KPI values or production evidence. Website/application/host/login-endpoint denominators are different.

## External references checked

The cited public IONIX pages were opened on 2026-10-04 to verify the design-pattern attribution. Vendor statements are product claims, not independent validation of their operation or AstraNull capabilities.

- IONIX presents coverage, effectiveness and ongoing posture monitoring as related WAF workflows. AstraNull can use that decision structure while keeping customer-declared scope and measured limitations. [WAF posture](https://www.ionix.io/waf-posture-management/).
- IONIX describes prioritization using business context and dependencies. AstraNull’s business importance and ownership must be declared/sourced, and unavailable traffic data stays unknown. [Risk prioritization](https://www.ionix.io/risk-prioritization/).
- IONIX describes consolidated action items and post-remediation checking. AstraNull should preserve each affected target’s evidence and retest outcome when consolidating work. [Remediation workflow](https://www.ionix.io/accelerated-remediation/).
- The linked WAF article describes behavioral validation and policy/coverage capabilities. It does not establish those configuration facts for an AstraNull host; explicit optional integration evidence remains necessary. [WAF capability article](https://www.ionix.io/blog/new-waf-posture-management-solution/).

Do not copy competitor automatic discovery, inferred estate ownership, autonomous configuration writes, marketing compliance assertions or promised fix SLAs into AstraNull’s core workflow.

## Requirement-to-handoff map

| Requirement from supplied brief | UX placement | Main handoff |
| --- | --- | --- |
| Identity, owner, criticality, purpose, tags/group | Target header/facts and authorized context editor | [Host profile](06-host-protection-profile.md), [engineering](09-engineering-consultation.md). |
| CDN/WAF/hosting separate, origin cloud unknown | Protection overview | [Host profile](06-host-protection-profile.md). |
| Provider badge → how identified | Family-scoped evidence inspector | [Host profile](06-host-protection-profile.md), [engineering](09-engineering-consultation.md). |
| WAF efficacy, origin reachability, dimensional DDoS readiness | Profile dimension table and exact-check evidence | [Host profile](06-host-protection-profile.md), [live trace](03-live-check-observability.md). |
| Coverage/unmeasured/stale/remaining | Profile check plan and dashboard cohort table | [Analytics](07-dashboard-protection-analytics.md). |
| Websites/API/login views | Declared-role cohorts in Targets and dashboard | [Analytics](07-dashboard-protection-analytics.md), [naming](01-naming-and-navigation.md). |
| Critical services with gaps and top remediation actions | Dashboard Overview priority block | [Analytics](07-dashboard-protection-analytics.md). |
| Authorized declared origins reachable | Profile origin dimension; scoped dashboard list | [Host profile](06-host-protection-profile.md), [origin boundary](09-engineering-consultation.md). |
| Drift and history | Target Changes & history; Risk trends; opt-in alerts | [Changes/remediation](08-drift-concentration-remediation.md). |
| CDN/DNS/hosting concentration | Dashboard Risk trends and group context | [Changes/remediation](08-drift-concentration-remediation.md). |
| Certificate/TLS/DNS/service failures | Separate Maintenance section/filter | [Changes/remediation](08-drift-concentration-remediation.md). |
| Consolidated work then per-host retest | Finding group/detail, dashboard actions, target history | [Changes/remediation](08-drift-concentration-remediation.md). |
| Optional rule counts, modes, config changes | Profile/integration detail only with permission/source | [Engineering](09-engineering-consultation.md). |
| Exact operation/response/evaluation in live view | Target Validate, scan and run detail | [Live trace](03-live-check-observability.md). |
| Honest units, overlaps, zero denominator, unknown and unreachable assets | Every profile/metric/list/report | [Analytics](07-dashboard-protection-analytics.md), [engineering](09-engineering-consultation.md). |

## Delivery order

Host identity/provenance and protection profile first; consistent inventory/segmented dashboard second; live direct-check evidence third; retained drift/concentration/remediation workflows fourth. Shared spacing, status language and overlay accessibility are maintained throughout. Reports and notifications consume the same sourced decisions rather than implementing independent verdict logic.

This addition is documentation only. It contains UX recommendations and future engineering responsibilities, not executed provider testing or new feature completion claims.
