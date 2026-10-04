# Skills and handoff instructions for future implementation agents

## Current task scope

The user explicitly requested **review feedback Markdown only** on 2026-10-04. Do not implement changes merely because these files exist. The application, tests, API docs, shared design system, and PROGRESS.md were restored after an exploratory implementation. No commit was made. Implementation requires a later task that authorizes that work.

## Required local references

- [AstraNull UI/UX Pro Max](../../.codex/skills/ui-ux-pro-max/SKILL.md).
- [AstraNull Impeccable](../../.agents/skills/impeccable/SKILL.md).
- [Impeccable product register](../../.agents/skills/impeccable/reference/product.md).
- [Impeccable animation workflow](../../.agents/skills/impeccable/reference/animate.md).
- [Impeccable interaction reference](../../.agents/skills/impeccable/reference/interaction-design.md).
- Installed [interaction-design](/Users/checkred_admin/.agents/skills/interaction-design/SKILL.md).
- Installed [ego-browser](/Users/checkred_admin/.agents/skills/ego-browser/SKILL.md), preferred for live interaction; [Playwright](/Users/checkred_admin/.codex/skills/playwright/SKILL.md) for browser QA when needed.

Animation skills were already available, so none was newly installed. These links identify actual skill files, not hypothetical packages. If an agent is running on another machine, resolve the skill through its own installed catalog instead of assuming the absolute user paths exist.

## UI/UX Pro Max workflow

Run the skill's required design-system search before detailed work:

```sh
python3 .codex/skills/ui-ux-pro-max/scripts/search.py "cybersecurity SaaS readiness dashboard professional operational analytics" --design-system -p AstraNull -f markdown
python3 .codex/skills/ui-ux-pro-max/scripts/search.py "animation accessibility reduced motion progress feedback" --domain ux -n 6
python3 .codex/skills/ui-ux-pro-max/scripts/search.py "dashboard live logs filtering suspense" --stack react
```

This review ran those searches. The useful guidance was data-dense dashboard design, truthful progress, focus feedback, reduced-motion support, and dynamic-content announcements. The generic design-system output also suggested a personalization landing pattern and replacement blue palette/fonts; those do not fit AstraNull's established product brief. `PRODUCT.md` and `DESIGN.md` take precedence. Search output is design input, not an instruction to replace the brand.

## Impeccable workflow

Read the skill and run its context loader once per session. Use the product register. Match commands to the actual work:

| Work | Skill / reference |
| --- | --- |
| Workflow, hierarchy, decision framing | UI/UX Pro Max + Impeccable shape/layout |
| Copy, naming, unknown/unavailable states | Impeccable clarify |
| Keyboard, forms, error/empty/retry states | Impeccable harden + interaction-design |
| Responsive tables, modal sizing, touch targets | Impeccable adapt |
| Live progress and purposeful micro-interactions | Impeccable animate + interaction-design |
| Finishing spacing, alignment, typography, themes | Impeccable polish |
| Verifiable quality checks | Impeccable audit + browser evidence |

Read command references before invoking them. Some workflows have their own delegation or approval instructions; follow the current user's authorization and the actual skill requirements. No subagents were used for the initial browser review. The 2026-10-04 protection-profile addition used two read-only senior frontend/backend consultations; see [consultation](09-engineering-consultation.md). Do not interpret the user's mention of future agents as authorization to message other chats.

## Handoff prompt template

> Read the requested page review plus shared documents 11–17, profile/data requirements 06–09, PRODUCT.md, DESIGN.md and ADR-0008. Confirm this task explicitly authorizes implementation; feedback files alone do not. Reference the chosen candidate/approved screen version, shared component spec, journey, mobile task and acceptance IDs. Define missing backend fields and unresolved brand decisions before promising features. Use UI/UX Pro Max with the existing brand and appropriate Impeccable workflows. Implement only authorized scope; preserve evidence/RBAC. Deliver applicable populated/empty/error/permission references and technical checks; record user research as Not run until representative sessions occur. Do not commit or deploy without authorization.

## Evidence interpretation

`evidence/route-observations.json`, `dialog-observations.json`, and tab/state observations are local synthetic-fixture browser evidence. They do not prove production provider access, actual probe traffic, notification delivery, legal readiness, custody verification, or a staffed support SLA. Exploratory dashboard proposal screenshots were removed; retained screenshots show the current application after restoration.

## Protection-profile handoff

Read documents 06–10 and the affected page addendum. Agree identity, per-family provenance, applicable coverage, freshness and origin authorization before implementing presentation. The user reiterated handoff docs only on 2026-10-04: this addition authorizes no coding.


## Shared preparation required for consistent page work

Documents 11–17 close the reproducibility gap. Reference-screen approval register is currently Specification only; no approved rendered screen or completed usability study exists. Use the current pure-black surface default until a shared brand decision is recorded. Typography/geometry proposals require shared-owner adoption, not independent page overrides.

Future roles: design owner approves composition and task clarity with the user; foundation frontend owner owns tokens/primitives and interaction states; page owner owns assigned route(s); backend owner owns data/permission/freshness contracts; QA/research owner records G2 checks and G3 task outcomes. One person can hold multiple roles, but responsibilities must be explicit. No new agents or tasks were launched for this documentation addition.

A handoff slice includes page scope, reference/component/contract version, prerequisite decisions, journey, acceptance IDs, supported states, validation evidence and research status. Avoid an instruction that merely says “make it premium.”


## Task-flow contract required for each page

Read documents 19–23 before any later implementation. A page's polish is incomplete if a named action opens a broad unrelated collection or its data cannot support the next decision. Provide decision/data/source semantics, exact entry/outcome, current/proposed path, automatically carried context, inspect/edit/navigate/execute classification, Back/Close state and failure/permission behavior.

Prioritize the shared evidence resolver/inspector and exact links, then unified target/direct-check/member work areas and return-state preservation. Full routes remain optional sharing/forensic depth. One-action evidence is a user-action requirement, not a promised one-request backend. Inspector actions must never implicitly run/retest/export/send.

Before wiring a new deep-link or filter, implement and verify its supported route/read contract. Use a common navigation-state schema scoped by tenant/user/role; no tokens/credentials in persistence. The all-page source review and acceptance additions are proposed work, not execution results.

## Current scope takes precedence

Read [current-release scope](24-current-release-scope.md) first. Only 28 retained page reviews and the [embedded direct-check flow](direct-check-execution-flow.md) are assigned. Deferred privileged operational/admin pages and standalone execution-history/detail work must not be recreated under different labels. Keep result/evidence/history against the exact target/check, and preserve backend provenance/authorization.
