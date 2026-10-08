# ADR-0019: Direct domain selection

Status: Accepted, 2026-10-08. Supersedes the customer grouping model in ADR-0004 and ADR-0008 section 4.

Customers declare and select targets directly. A validation assessment selects an exact `target_id` or an explicit `target_ids` set. There is no customer group navigation, detail page, grouping picker, column, prerequisite, or group-wide implicit selection. Old grouping bookmarks resolve to Targets.

Existing execution-policy records remain internal compatibility storage. Removing the customer model must not erase evidence, target IDs, authorization signatures, rate-budget history, safe windows, or cooldowns. A selected target resolves its existing policy on the server; customers cannot authorize another target by supplying a hostname or arbitrary policy reference. Cross-policy assessments capture each selected target's policy binding, execute sequentially, and enforce that policy at each dispatch. Recurrence retains the explicit selected IDs instead of expanding to newly added targets.

Readiness coverage and freshness count evidence-backed declared domains individually; a validated sibling cannot cover another domain. The published factor weights remain 44/28/17/11.

New governed requests bind approval artifacts and scope hashes to the explicit target IDs. Authorization checks cover every selected target; unrelated domains in retained policy storage never enter that scope. SOC approval and high-scale execution controls remain mandatory.

The portal requests the direct representation with `x-astranull-target-model: direct`. It omits obsolete grouping identity fields. Compatibility integrations and immutable historical evidence/export payloads retain their original representation so custody digests and existing signed proof remain verifiable. The portal does not read the old grouping catalog. Historical records remain unchanged. Migration 0072 replaces the legacy one-authorization-per-policy index with an indexed lookup and a serialized database overlap guard. Separate domains can hold separate signatures; concurrent signatures for overlapping domain scope remain rejected. Target detail, confirmation, and SOC start authorization resolve signatures by the exact domain.

Direct target routes include ownership challenge reads/issue/verification, authorization, removal, and CSV intake. Opening a domain, selecting domains, reading history, and reviewing a plan remain passive.
