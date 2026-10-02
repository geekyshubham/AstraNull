# ADR-0009: Classic "rule" and Refined "alert" are different finding groupings

## Status

Accepted (2026-10-02). Records a design difference that shipped with the Refined Findings variant (RUX-016) and was raised as G02 in `UNCOMMITTED_CHANGES_REVIEW.md`.

## Context

The Findings page has two design variants (`lib/design-variant.ts`). Both collapse near-identical findings into one row, but they use different identity keys:

| Variant | Entity | Key | Source |
|---|---|---|---|
| Classic | rule | `findingRuleKey()`: `rule:<plain-language outcome/title>`, falling back to `check:<id>`, then `id:<id>` | `apps/web/react/src/lib/findings-helpers.ts` |
| Refined | alert | `findingGroupKey()`: `<check id>\|<issue identity>`; the issue is the recorded verdict for generated titles, else the title with target tokens removed, else the vector family | `apps/web/react/src/lib/finding-groups.mjs` |

Earlier comments described the variants as "presentation only", which hid that counts and drilldown membership change with the variant.

## Decision

Keep both keys and treat them as two separate entities.

- A **rule** answers "what outcome was observed, on how many assets", across checks. One verdict, for example `edge_exposed` ("Direct server access was found"), emitted by several checks is one rule.
- An **alert** answers "which check found which issue, on how many assets". The same verdict from two checks is two alerts. Target-specific tokens in a title are stripped, so one check's per-asset titles are one alert, but they stay separate rules.
- Data, actions, and permission gates stay shared between variants. Grouping is the documented exception.

## Consequences

| Area | Classic (rule) | Refined (alert) |
|---|---|---|
| Group count | Can be lower (checks merged) or higher (per-asset custom titles split) | Per check, target tokens normalized |
| Asset count | `countFindingAssets` / `findingAssetIdentity` over rule members | `group.assets` over alert members |
| Drilldown | `finding-detail?id=<representative>&focus=rule-assets`; siblings from `findingRuleSiblings` | `#finding-group-detail?key=<findingGroupKey>`; members from `findGroupByKey` |

Switching variants can therefore change the numbers a user sees for the same records. Neither view invents records; both are derived from recorded finding, target, target-group, and check fields.

A change to either key is a contract change. `tests/unit/finding-grouping-contracts.test.mjs` pins both keys with a fixture where the same two findings are one rule and two alerts (and the reverse case), and must be updated deliberately alongside this ADR. Unifying the two keys, or making Refined the default, needs a product/UX decision first (RUX-016).
