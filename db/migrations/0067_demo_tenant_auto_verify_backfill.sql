-- 0067_demo_tenant_auto_verify_backfill.sql
-- Backfill target_verifications with user_confirmed for demo accounts (ADR-0016).

INSERT INTO target_verifications (
  id,
  tenant_id,
  target_id,
  state,
  source_kind,
  source_ref,
  transitioned_at,
  transitioned_by,
  audit_entry_id
)
SELECT
  'tv_demo_' || substr(md5(t.tenant_id || ':' || t.id), 1, 16),
  t.tenant_id,
  t.id,
  'user_confirmed',
  'manual_override',
  '{"method":"demo_auto_verify","demo":true}'::jsonb,
  COALESCE(t.created_at, CURRENT_TIMESTAMP),
  'system:demo_auto_verify_backfill',
  'aud_demo_auto_verify_backfill'
FROM targets t
WHERE (
  t.tenant_id = 'ten_demo'
  OR t.tenant_id = 'Astra-D1TrtI4HMTSrwKRW-9'
  OR t.tenant_id LIKE 'Astra-%'
  OR t.tenant_id ILIKE '%demo%'
)
AND t.deleted_at IS NULL
AND NOT EXISTS (
  SELECT 1 FROM target_verifications tv
  WHERE tv.tenant_id = t.tenant_id
    AND tv.target_id = t.id
    AND tv.state = 'user_confirmed'
)
ON CONFLICT (id) DO NOTHING;

UPDATE target_groups tg
SET ownership_status = 'user_confirmed'
WHERE (
  tg.tenant_id = 'ten_demo'
  OR tg.tenant_id = 'Astra-D1TrtI4HMTSrwKRW-9'
  OR tg.tenant_id LIKE 'Astra-%'
  OR tg.tenant_id ILIKE '%demo%'
)
AND tg.deleted_at IS NULL;
