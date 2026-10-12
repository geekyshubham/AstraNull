import { canonicalJsonStringify } from '../lib/custody.mjs';
import { createHash } from 'node:crypto';
import { deriveAssuranceScope } from '../lib/assuranceScope.mjs';
import { approvedScenarioVersion, deriveCheckDefinitionVersion } from '../lib/checkDefinitionVersion.mjs';

export const REVIEWED_OPERATION_VERSION = 'reviewed-inert-operation.v1';
export const REVIEWED_OPERATION_MAX_LIFETIME_MS = 24 * 60 * 60 * 1000;
const TEMPLATES = new Set(['marker-query-v1', 'inert-json-v1']);
const KINDS = new Set(['waf_class_marker_probe', 'waf_evasion_marker_probe', 'waf_enforcement_probe', 'waf_inspection_limit_probe']);
const INPUT_KEYS = new Set(['target_id', 'check_id', 'template', 'semantics', 'side_effects', 'expires_at', 'reviewed_plan_digest']);
const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const hash = (value) => createHash('sha256').update(canonicalJsonStringify(value)).digest('hex');

export class ReviewedOperationError extends Error {
  constructor(code, status = 400) { super(code); this.code = code; this.status = status; }
}
const reject = (code, status) => { throw new ReviewedOperationError(code, status); };

/** A review pins declarations and fixed serializers; it is not observed enforcement or a traffic grant. */
export function buildReviewedOperationPlan(body, { tenantId, target, check, now = new Date() } = {}) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) reject('invalid_operation');
  if (Object.keys(body).some((key) => !INPUT_KEYS.has(key))) reject('operation_field_not_allowed');
  if (typeof body.target_id !== 'string' || typeof body.check_id !== 'string'
    || !ID.test(body.target_id) || !ID.test(body.check_id)) reject('invalid_operation_identity');
  if (!target || target.tenant_id !== tenantId || target.id !== body.target_id) reject('target_not_found', 404);
  if (target.deleted_at) reject('target_not_active', 409);
  if (target.kind !== 'url') reject('exact_url_target_required');
  let endpoint;
  try { endpoint = new URL(target.value); } catch { reject('invalid_operation_endpoint'); }
  if (!['http:', 'https:'].includes(endpoint.protocol) || endpoint.username || endpoint.password
    || endpoint.search || endpoint.hash || !endpoint.hostname) reject('invalid_operation_endpoint');
  if (target.port != null && target.port !== Number(endpoint.port || (endpoint.protocol === 'https:' ? 443 : 80))) reject('operation_endpoint_port_mismatch');
  if (!check || check.check_id !== body.check_id || check.safety_class !== 'safe'
    || !check.supported_targets?.includes('url') || !KINDS.has(check.probe_profile?.kind)) reject('operation_check_not_supported');
  if (!TEMPLATES.has(body.template) || (body.template === 'inert-json-v1' && check.probe_profile.kind !== 'waf_evasion_marker_probe')) reject('operation_template_not_supported');
  if (body.semantics !== 'inert_diagnostic' || body.side_effects !== 'none') reject('inert_semantics_required');
  if (typeof body.expires_at !== 'string'
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(body.expires_at)) reject('operation_expiry_invalid');
  const at = new Date(now).getTime(), until = Date.parse(body.expires_at);
  if (!Number.isFinite(at) || !Number.isFinite(until) || until <= at || until - at > REVIEWED_OPERATION_MAX_LIFETIME_MS
    || new Date(until).toISOString() !== (body.expires_at.includes('.') ? body.expires_at : body.expires_at.replace('Z', '.000Z'))) reject('operation_expiry_invalid');
  const plan = {
    version: REVIEWED_OPERATION_VERSION, tenant_id: tenantId, target_id: target.id,
    target_definition_digest: deriveAssuranceScope({ target }).target.definition_digest,
    check_id: check.check_id, check_version: deriveCheckDefinitionVersion(check).check_version,
    check_definition_digest: deriveCheckDefinitionVersion(check).digest, scenario_version: approvedScenarioVersion(check),
    endpoint: endpoint.href, method: body.template === 'marker-query-v1' ? 'GET' : 'POST',
    template: body.template, semantics: 'inert_diagnostic', side_effects: 'none',
    request_schema: body.template === 'marker-query-v1' ? 'fixed-asn-probe-query.v1' : 'fixed-asn-marker-json.v1',
    expires_at: new Date(until).toISOString(),
    maximum_body_bytes: body.template === 'inert-json-v1' ? 1024 : 0,
    maximum_probe_operations: 4,
  };
  return { plan, plan_digest: hash(plan), grants_execution: false, execution_available: false };
}

export function reviewedOperationGap(row, { tenantId, target, check, now = new Date() } = {}) {
  if (!row || row.tenant_id !== tenantId || row.target_id !== target?.id) return 'operation_not_found';
  if (row.revoked_at) return 'operation_revoked';
  const plan = row.plan;
  if (!plan || plan.version !== REVIEWED_OPERATION_VERSION || plan.tenant_id !== tenantId || plan.target_id !== row.target_id
    || row.plan_digest !== hash(plan) || !row.approved_by || !['owner', 'admin'].includes(row.approved_role)) return 'operation_review_invalid';
  if (typeof row.approved_at !== 'string'
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(row.approved_at)) return 'operation_review_invalid';
  const at = new Date(now).getTime(), approved = Date.parse(row.approved_at), until = Date.parse(plan.expires_at);
  if (!Number.isFinite(approved) || new Date(approved).toISOString() !== row.approved_at) return 'operation_review_invalid';
  if (!Number.isFinite(at) || !Number.isFinite(approved) || !Number.isFinite(until) || approved > at
    || until <= approved || until - approved > REVIEWED_OPERATION_MAX_LIFETIME_MS) return 'operation_review_invalid';
  if (until <= at) return 'operation_expired';
  if (!target || target.deleted_at || target.tenant_id !== tenantId
    || plan.target_definition_digest !== deriveAssuranceScope({ target }).target.definition_digest) return 'operation_target_changed';
  if (!check || plan.check_id !== check.check_id || plan.check_version !== deriveCheckDefinitionVersion(check).check_version
    || plan.check_definition_digest !== deriveCheckDefinitionVersion(check).digest || plan.scenario_version !== approvedScenarioVersion(check)) return 'operation_check_changed';
  try {
    const reconstructed = buildReviewedOperationPlan({ target_id: target.id, check_id: check.check_id, template: plan.template,
      semantics: plan.semantics, side_effects: plan.side_effects, expires_at: plan.expires_at }, { tenantId, target, check, now: row.approved_at });
    if (reconstructed.plan_digest !== row.plan_digest) return 'operation_review_invalid';
  } catch { return 'operation_review_invalid'; }
  return null;
}
