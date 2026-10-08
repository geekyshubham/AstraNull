# Declared targets and direct domain selection

Current product model: [ADR-0019](../adr/0019-direct-domain-selection.md).

Customers declare a domain, hostname, URL, IP, DNS zone, or protocol endpoint directly, manually or through bounded CSV/API import. The target keeps its identity, tags, purpose, owner, criticality, ownership proof, and recorded evidence. No cloud credentials or automatic inventory discovery are required.

Assessments and schedules select one or more explicit declared targets. Selection and planning are passive. Every target/check pair is checked for applicability before dispatch; unsupported endpoints and absent customer setup remain explicit. New domains do not silently join a recurring assessment.

Each dispatch retains ownership, safe-window, request-volume, cooldown, tenant rate, concurrency, kill-switch, and subscription checks. High-scale requests remain governed by SOC and exact-target authorization. A complete catalog is visible, while readiness scores count only eligible evidence.

Customer grouping screens and selectors have been removed. Existing policy and historical custody storage are retained internally so the model change does not reset budgets or erase evidence.
