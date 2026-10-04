# Naming, information architecture, and product vocabulary

## Recommendation

Keep **Targets** as the broad product object because scope includes domains/hostnames, IPs, and CIDRs. Lead with the customer's language inside a task: “Add a domain,” “Verify domain ownership,” “Check checkout.example.com.” Keep **Target groups** as a secondary way to share ownership, safe windows, and governance; do not imply that creating a group is always the first onboarding step.

Do not rename all targets to “Domains”: that would hide legitimate IP/CIDR scope. Do not invent environments or agent placement to make the navigation seem familiar. API object names need not change when a screen label improves.

## Proposed navigation

- Overview: Dashboard.
- Scope: **Targets**, then **Target groups** (current order is reversed).
- Validation: **Check library** (with advanced vector taxonomy), **Validation schedules**, **Findings**.
- Governance: Reports, Integrations, Notifications, Audit log.
- Account: Settings, Support, Plan & usage. Customer evidence access remains role-scoped.

This is a proposal, not an approved migration. Preserve hash routes, bookmarks, permission checks, and test fixtures if user-facing labels change.

## Vocabulary decisions

| Current term | Suggested user-facing term | Why / boundary |
| --- | --- | --- |
| Target | Target; domain/hostname/IP in context | Correct technical umbrella with a concrete example. |
| Target group | Target group; helper “Targets sharing validation settings” | “Service group” is attractive but may overstate a business-service relationship the customer never declared. |
| Test policies | Validation schedules | Current primary action is Create schedule and most visible content is cadence, target binding, and safe windows. Keep Policy for actual enforcement rules. |
| Selected checks | Run selected checks / Run all applicable checks | Multiple bounded checks stay in the target workspace; do not create a separate customer execution/session object or page. |
| Vector library | Check library, advanced “Vector catalog” | 721 taxonomy entries are not 721 executable checks. Do not promise runnability by catalog size. |
| E1–E5 | Declaration only, connection observed, behavior observed, future-release restricted, monitor only | Show the evidence meaning first; retain the code in a tooltip/technical view. |
| Protected | Passed this check / observed blocking | Universal protection cannot be inferred from one result or a provider fingerprint. |
| WAF/CDN detected | WAF/CDN detected | A signal. Do not label it “protected” until effectiveness evidence and its freshness are present. |
| No WAF | WAF not detected | Absence of a signature is not proof that no WAF exists. |
| No result / Not measured | Not checked / Unknown / Inconclusive | Pick based on actual state: never run, missing observation, or attempted without a conclusion. |
| Ready for validation | Ownership verified / Can start this check | Readiness also depends on check fit, windows, concurrency, rate limits, and authorization gates. |
| Eligibility | Check compatibility | Distinguish kind compatibility from runtime authorization and readiness. |
| Billing | Plan & usage | Current screen shows entitlement and usage metadata; it does not provide a payment/invoice workflow. |
| Dead-letter queue / DLQ | Failed deliveries (advanced: dead-letter queue) | Give a support operator a recovery task, not a queue acronym. |
| Custody / sealed | Evidence integrity / custody | A recorded hash is not an independently verified chain. Show verification method and time. |
| Tenant | Workspace / organization in customer copy | Keep Tenant in technical details when tenant isolation matters. |
| Classic / Premium / Refined | Remove experiment switch from customer UI | These are design variants, not clear workflow choices or verified entitlement tiers. |

## Copy examples

Dashboard: “See coverage, open gaps, and what to validate next.”
Ownership: “Add this TXT record at your DNS provider. We will only check the declared hostname.”
Unknown coverage: “No recent usable observation. Verify ownership, then run edge detection.”
Run outcome: “This bounded request was blocked at the edge. Origin reachability has not been validated.”
Finding closure: “Close this finding? The original evidence remains in the audit record. Add the resolution reason.”

## Acceptance criteria for future changes

- Labels match the action and data shown, with the same term across list, detail, dialog, report, and notification.
- Every count explicitly distinguishes targets, unique hostnames, groups, vectors, runnable checks, runs, sessions, and findings.
- No screen says a pending-ownership target is ready to execute.
- The product consistently says AstraNull; do not adopt “Astral” as an accidental alternate brand.
- Targets can be added without creating a named group; a default grouping remains an implementation detail.
- The current customer shell excludes future-release execution/admin surfaces and dormant agent/environment pages.

## Host/service vocabulary addition

A Host protection profile is a view of an existing declared target. Keep Targets as the broad inventory label; use Host for normalized hostname cohorts, Service only for explicit service identity, and Login endpoint only for a declared endpoint—not a hostname role. Multiple service roles overlap; [analytics definitions](07-dashboard-protection-analytics.md) take precedence over broad count labels.
