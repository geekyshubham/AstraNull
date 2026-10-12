import { createHash } from 'node:crypto';
import { canonicalJsonStringify } from '../lib/custody.mjs';
import { deriveAssuranceScope } from '../lib/assuranceScope.mjs';

export const CVE_APPLICABILITY_REVIEW_VERSION = 'cve-component-declaration.v1';
export const CVE_APPLICABILITY_NO_EXECUTION = Object.freeze({ grants_execution: false, execution_available: false });
const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const COMPONENT = /^[A-Za-z0-9@][A-Za-z0-9@._+/-]{0,127}$/;
const VERSION = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const KEYS = new Set(['cve_pipeline_item_id', 'cve_id', 'cve_asset_match_id', 'waf_asset_id', 'component',
  'component_version', 'declared_applicability', 'source', 'supporting_metadata', 'reviewed_plan_digest']);
const SOURCES = new Set(['manual', 'sbom', 'cmdb', 'vendor_advisory']);
const SUPPORT_KINDS = new Set(['sbom', 'cmdb', 'vendor_advisory', 'change_record']);
const APPLICABILITY = new Set(['applicable', 'not_applicable', 'unknown']);
const object = (value) => value != null && typeof value === 'object' && !Array.isArray(value);
const hash = (value) => createHash('sha256').update(canonicalJsonStringify(value)).digest('hex');
const pick = (row, keys) => Object.fromEntries(keys.map((key) => [key, row?.[key] ?? null]));
export class CveApplicabilityReviewError extends Error {
  constructor(code, status = 400) { super(code); this.code = code; this.status = status; }
}
const reject = (code, status) => { throw new CveApplicabilityReviewError(code, status); };

/** Hash definitions, not mutable validation results, playbooks, display labels or timestamps. */
export function cveApplicabilityDefinitionDigests({ asset, item, match, target = null }) {
  const summary = item?.triage_summary_json ?? {};
  return {
    asset_definition_digest: hash({ ...pick(asset, ['id', 'tenant_id', 'target_id', 'target_group_id',
      'canonical_url', 'asset_kind', 'expected_waf_required', 'expected_vendor_hint']),
    target_definition_digest: target ? deriveAssuranceScope({ target }).target.definition_digest : null }),
    item_definition_digest: hash({ ...pick(item, ['id', 'tenant_id', 'cve_id', 'severity', 'known_exploited']),
      public_poc_signal: item?.public_poc_signal ?? item?.poc_indicator ?? false,
      affected_products: item?.affected_products ?? summary.affected_products ?? [],
      affected_versions: item?.affected_versions ?? summary.affected_versions ?? [],
      vendor_advisories: item?.vendor_advisories ?? summary.vendor_advisories ?? [],
      description_summary: item?.description_summary ?? summary.description_summary ?? null }),
    match_definition_digest: hash(pick(match, ['id', 'tenant_id', 'cve_pipeline_item_id', 'waf_asset_id',
      'match_source', 'confidence_level', 'match_confidence', 'match_reasons', 'requires_review', 'exposure_claim_allowed'])),
  };
}

function lineage(body, { tenantId, asset, item, match, target = null }) {
  if (!item || item.tenant_id !== tenantId || item.id !== body.cve_pipeline_item_id) reject('cve_pipeline_item_not_found', 404);
  if (!match || match.tenant_id !== tenantId || match.id !== body.cve_asset_match_id) reject('cve_asset_match_not_found', 404);
  if (!asset || asset.tenant_id !== tenantId || asset.id !== body.waf_asset_id) reject('waf_asset_not_found', 404);
  if (item.cve_id !== body.cve_id || match.cve_pipeline_item_id !== item.id || match.waf_asset_id !== asset.id) reject('cve_review_lineage_mismatch', 409);
  if (asset.deleted_at || (asset.target_id && (!target || target.tenant_id !== tenantId || target.id !== asset.target_id || target.deleted_at))) reject('cve_review_asset_not_current', 409);
}

/** A customer declaration only. No scanner, observed exposure, enforcement or dispatch grant. */
export function buildCveApplicabilityReviewPlan(body, context = {}) {
  if (!object(body)) reject('invalid_cve_review');
  if (Object.keys(body).some((key) => !KEYS.has(key))) reject('cve_review_field_not_allowed');
  for (const key of ['cve_pipeline_item_id', 'cve_asset_match_id', 'waf_asset_id']) {
    if (typeof body[key] !== 'string' || !ID.test(body[key])) reject('invalid_cve_review_identity');
  }
  if (typeof body.cve_id !== 'string' || !/^CVE-\d{4}-\d{4,19}$/.test(body.cve_id)) reject('invalid_cve_review_identity');
  if (typeof body.component !== 'string' || !COMPONENT.test(body.component)
    || typeof body.component_version !== 'string' || !VERSION.test(body.component_version)) reject('invalid_component_declaration');
  if (!APPLICABILITY.has(body.declared_applicability) || !SOURCES.has(body.source)) reject('invalid_applicability_declaration');
  const support = body.supporting_metadata === undefined ? [] : body.supporting_metadata;
  if (!Array.isArray(support) || support.length > 8) reject('invalid_cve_review_support');
  for (const entry of support) {
    if (!object(entry) || Object.keys(entry).length !== 3 || Object.keys(entry).some((key) => !['kind', 'reference_id', 'sha256'].includes(key))
      || !SUPPORT_KINDS.has(entry.kind) || typeof entry.reference_id !== 'string' || !ID.test(entry.reference_id)
      || typeof entry.sha256 !== 'string' || !DIGEST.test(entry.sha256)) reject('invalid_cve_review_support');
  }
  lineage(body, context);
  const plan = {
    version: CVE_APPLICABILITY_REVIEW_VERSION, tenant_id: context.tenantId,
    ...pick(body, ['cve_pipeline_item_id', 'cve_id', 'cve_asset_match_id', 'waf_asset_id', 'component',
      'component_version', 'declared_applicability', 'source']),
    supporting_metadata: structuredClone(support), ...cveApplicabilityDefinitionDigests(context),
    evidence_classification: 'customer_declaration', external_applicability_verified: false,
    exposure_claim_allowed: false, observed_enforcement: false, ...CVE_APPLICABILITY_NO_EXECUTION,
  };
  return { plan, plan_digest: hash(plan), ...CVE_APPLICABILITY_NO_EXECUTION };
}

/** Read-only projection: null means the declaration review is current, never externally verified. */
export function cveApplicabilityReviewGap(row, context = {}, now = new Date()) {
  if (!row || row.tenant_id !== context.tenantId) return 'cve_review_not_found';
  if (row.revoked_at) return 'cve_review_revoked';
  const plan = row.plan;
  if (!object(plan) || plan.version !== CVE_APPLICABILITY_REVIEW_VERSION || plan.tenant_id !== row.tenant_id
    || row.plan_digest !== hash(plan) || typeof row.approved_by !== 'string' || !ID.test(row.approved_by) || !['owner', 'admin'].includes(row.approved_role)
    || typeof row.approved_at !== 'string' || !Number.isFinite(new Date(now).getTime()) || !Number.isFinite(Date.parse(row.approved_at)) || Date.parse(row.approved_at) > new Date(now).getTime()
    || ['cve_pipeline_item_id', 'cve_id', 'cve_asset_match_id', 'waf_asset_id'].some((key) => row[key] !== plan[key])) return 'cve_review_invalid';
  try { lineage(plan, context); } catch { return 'cve_review_lineage_changed'; }
  const current = cveApplicabilityDefinitionDigests(context);
  for (const key of ['asset_definition_digest', 'item_definition_digest', 'match_definition_digest']) {
    if (plan[key] !== current[key]) return `cve_review_${key.replace('_definition_digest', '')}_changed`;
  }
  try {
    const rebuilt = buildCveApplicabilityReviewPlan(pick(plan, ['cve_pipeline_item_id', 'cve_id', 'cve_asset_match_id',
      'waf_asset_id', 'component', 'component_version', 'declared_applicability', 'source', 'supporting_metadata']), context);
    if (rebuilt.plan_digest !== row.plan_digest) return 'cve_review_invalid';
  } catch { return 'cve_review_invalid'; }
  return null;
}
