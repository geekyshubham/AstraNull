# Direct target workspace

The current workspace is Targets, with direct single-domain and multiple-domain selection. See [ADR-0019](../adr/0019-direct-domain-selection.md) and the [implementation record](../implementation/target-only-domain-workflows.md).

Targets supports direct intake, CSV import, ownership proof, removal, tags, findings, and validation history. Each target detail opens its observations, all applicable bounded checks, missing catalog prerequisites, evidence, origin relations, entry paths, authorization, and Stop controls. Assessments, schedules, findings filters, and reports use explicit target identities.

No customer group screen, group selector, or group column is present. Legacy bookmarks open Targets. Merely opening a page or selecting domains never starts a probe.
