-- ADR-0008: outside-in only, targets-first. Environments become a target tag.
--
-- Additive, idempotent data backfill only. No table or column is dropped: per ADR-0008 §5 the
-- `environments` table and the `target_groups.environment_id` column stay in the database,
-- dormant and unread, until a separate approved cleanup migration removes them.
--
-- This migration:
--   1. For every non-deleted target whose group still carries a non-null environment_id,
--      appends the tag `env:<slug(lower(environment name))>` into `metadata_json.tags`
--      (JSONB string array), without introducing duplicates.
--   2. Fixes `validation_mode = 'external_only'` on every target group (agent-assisted is gone).
--   3. Clears `environment_id` on every target group so the dormant link no longer resolves.
--
-- Runs inside the migration runner's transaction under the migration role. Re-running is a
-- no-op: step 1 dedupes against tags already present, and steps 2/3 are idempotent assignments.

SET LOCAL lock_timeout = '15s';
SET LOCAL statement_timeout = '5min';

-- Step 1: backfill env:<slug> tags from the (still-populated) environment link.
-- slug(name): lowercase, collapse every run of non [a-z0-9] characters to '-', trim leading and
-- trailing '-', then cap at 44 characters. Empty/degenerate names yield no tag.
WITH env_tag AS (
  SELECT
    t.id AS target_id,
    ('env:' || substring(
      trim(BOTH '-' FROM regexp_replace(lower(e.name), '[^a-z0-9]+', '-', 'g'))
      FROM 1 FOR 44
    )) AS tag
  FROM targets t
  JOIN target_groups tg
    ON tg.tenant_id = t.tenant_id AND tg.id = t.target_group_id
  JOIN environments e
    ON e.tenant_id = tg.tenant_id AND e.id = tg.environment_id
  WHERE t.deleted_at IS NULL
    AND tg.environment_id IS NOT NULL
),
valid_env_tag AS (
  -- Drop degenerate slugs (e.g. name was all punctuation) that would produce a bare "env:".
  SELECT target_id, tag
  FROM env_tag
  WHERE tag <> 'env:'
)
UPDATE targets t
SET metadata_json = jsonb_set(
  COALESCE(t.metadata_json, '{}'::jsonb),
  '{tags}',
  (
    -- Existing string tags (if any) plus the env tag, deduplicated, first-seen order preserved.
    SELECT COALESCE(jsonb_agg(tag_value ORDER BY first_ord), '[]'::jsonb)
    FROM (
      SELECT tag_value, MIN(ord) AS first_ord
      FROM (
        SELECT existing.value AS tag_value, existing.ordinality AS ord
        FROM jsonb_array_elements_text(
          CASE
            WHEN jsonb_typeof(COALESCE(t.metadata_json -> 'tags', '[]'::jsonb)) = 'array'
              THEN t.metadata_json -> 'tags'
            ELSE '[]'::jsonb
          END
        ) WITH ORDINALITY AS existing(value, ordinality)
        UNION ALL
        SELECT v.tag, 1000000
      ) merged
      GROUP BY tag_value
    ) deduped
  ),
  true
)
FROM valid_env_tag v
WHERE v.target_id = t.id
  -- Only touch rows that do not already carry this env tag (keeps the migration idempotent).
  AND NOT (
    jsonb_typeof(COALESCE(t.metadata_json -> 'tags', '[]'::jsonb)) = 'array'
    AND COALESCE(t.metadata_json -> 'tags', '[]'::jsonb) ? v.tag
  );

-- Step 2: every group is external_only now.
UPDATE target_groups
SET validation_mode = 'external_only'
WHERE validation_mode IS DISTINCT FROM 'external_only';

-- Step 3: sever the dormant environment link so no response resolves it.
UPDATE target_groups
SET environment_id = NULL
WHERE environment_id IS NOT NULL;
