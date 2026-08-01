-- 0040_findings_created_at_index.sql
-- Index for the target-detail findings keyset page.
--
-- Findings pagination in src/persistence/postgres/portalRevampRepository.mjs seeks with a
-- row-tuple predicate and sorts by the same composite:
--   SELECT ... FROM findings
--    WHERE tenant_id = $1 AND target_id = $2
--      AND (created_at, id) < ($3::timestamptz, $4::text)
--    ORDER BY created_at DESC, id DESC
--    LIMIT $5
-- No existing index covers created_at. findings_by_target(target_id) and
-- findings_by_target_state(target_id, status) from 0032 stop at the equality columns, and
-- idx_findings_tenant_status(tenant_id, status, severity) does not match this predicate at
-- all, so the planner had to read every finding for the target and top-N heapsort it. On a
-- target with 40k findings that is a Seq Scan; the seek predicate cannot be pushed into an
-- index and each page costs the same as the first.
--
-- Column order mirrors the query exactly: the two equality columns first (tenant_id leads
-- because it is also the RLS predicate, so it is present on every access path), then the
-- sort tuple in its DECLARED direction. DESC/DESC matters here: a plain ascending index can
-- serve this with a backward scan, but the tuple comparison (created_at, id) < (...) only
-- becomes a pure index range seek when the index direction matches the ORDER BY, which is
-- what turns the paginated case from a filter into a seek.
--
-- Additive and idempotent: an index changes no rows and no query results, only the plan.

CREATE INDEX IF NOT EXISTS idx_findings_tenant_target_created
  ON findings(tenant_id, target_id, created_at DESC, id DESC);
