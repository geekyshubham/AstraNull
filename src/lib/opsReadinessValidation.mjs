/**
 * Control-plane ops readiness probes — no outbound attack traffic; validates governance artifacts.
 */

import { validateSupportReadinessEvidence } from '../../scripts/support-readiness-evidence.mjs';
import { generateNonce, hashNonce } from './crypto.mjs';
import { newId } from './ids.mjs';
import { enrichProbeMetadataWithWafCatalog } from './wafProductCatalog.mjs';
import { getStore } from '../store.mjs';

export const OPS_READINESS_SCENARIOS = Object.freeze(['runbook_contacts', 'kill_switch_readiness']);

const ACCEPTED_EVIDENCE_STATUSES = new Set(['accepted', 'approved']);
const SOC_KILL_SWITCH_ACTIONS = new Set(['soc.kill_switch.activated', 'soc.kill_switch.cleared']);

export function isOpsReadinessProbeKind(check) {
  return check?.probe_profile?.kind === 'ops_readiness';
}

function latestAcceptedEvidence(tenantId, kind) {
  const ledger = getStore().productionReleaseEvidence ?? [];
  const matches = ledger.filter(
    (record) =>
      record.tenant_id === tenantId
      && record.kind === kind
      && ACCEPTED_EVIDENCE_STATUSES.has(String(record.status ?? 'accepted').toLowerCase()),
  );
  if (matches.length === 0) return null;
  return matches.sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)))[0];
}

function validateRunbookContacts(tenantId) {
  const record = latestAcceptedEvidence(tenantId, 'support_readiness');
  if (!record?.evidence) {
    return {
      ok: false,
      external_result: 'error',
      detail: 'No accepted support_readiness evidence recorded for tenant.',
      missing_fields: ['support_readiness_evidence'],
    };
  }
  const validation = validateSupportReadinessEvidence(record.evidence);
  return {
    ok: validation.ok,
    external_result: validation.ok ? 'connected' : 'error',
    detail: validation.ok
      ? 'Support runbook and emergency contact evidence validated.'
      : 'Support readiness evidence incomplete or contains forbidden fields.',
    validation,
    evidence_id: record.id,
  };
}

function validateKillSwitchReadiness(tenantId) {
  const store = getStore();
  const ks = store.socKillSwitch ?? {};
  const ksTenant = ks.tenant_id ?? null;
  const tenantScoped =
    ksTenant === tenantId
    || (ks.tenants && typeof ks.tenants === 'object' && ks.tenants[tenantId]);
  const hasKillSwitchState = tenantScoped && ks.updated_at != null;

  const auditHit = (store.auditLog ?? []).find(
    (entry) =>
      entry.tenant_id === tenantId && SOC_KILL_SWITCH_ACTIONS.has(entry.action),
  );
  const drillRecord = latestAcceptedEvidence(tenantId, 'kill_switch_drill');

  const signals = [];
  if (hasKillSwitchState) signals.push('kill_switch_state');
  if (auditHit) signals.push('kill_switch_audit');
  if (drillRecord) signals.push('kill_switch_drill_evidence');

  const ok = signals.length > 0;
  return {
    ok,
    external_result: ok ? 'connected' : 'error',
    detail: ok
      ? `Kill-switch readiness dry-run passed (${signals.join(', ')}).`
      : 'No kill-switch state, audit trail, or drill evidence recorded for tenant.',
    signals,
    drill_evidence_id: drillRecord?.id ?? null,
    dry_run: true,
    kill_switch_activated: false,
  };
}

function resolveScenario(check) {
  const scenario = check.probe_profile?.scenario;
  if (typeof scenario === 'string' && OPS_READINESS_SCENARIOS.includes(scenario)) {
    return scenario;
  }
  if (check.check_id?.includes('kill_switch')) return 'kill_switch_readiness';
  return 'runbook_contacts';
}

/**
 * @param {{ tenantId: string }} ctx
 * @param {Record<string, unknown>} check
 * @param {Record<string, unknown>} target
 */
export function executeOpsReadinessProbe(ctx, check, target) {
  const nonce = generateNonce();
  const nonce_hash = hashNonce(nonce);
  const scenario = resolveScenario(check);
  const outcome =
    scenario === 'kill_switch_readiness'
      ? validateKillSwitchReadiness(ctx.tenantId)
      : validateRunbookContacts(ctx.tenantId);

  return {
    event_id: newId('event'),
    source: 'ops_readiness_probe',
    signal_type: 'probe_result',
    external_result: outcome.external_result,
    nonce,
    nonce_hash,
    target_id: target.id,
    check_id: check.check_id,
    metadata: enrichProbeMetadataWithWafCatalog(
      {
        probe_kind: 'ops_readiness',
        scenario,
        ops_validation_ok: outcome.ok,
        ops_detail: outcome.detail,
        dry_run: scenario === 'kill_switch_readiness',
        target_value: target.value,
        ...(outcome.validation ? { validation_missing_fields: outcome.validation.missing_fields } : {}),
        ...(outcome.signals ? { readiness_signals: outcome.signals } : {}),
        ...(outcome.evidence_id ? { evidence_id: outcome.evidence_id } : {}),
        ...(outcome.drill_evidence_id ? { drill_evidence_id: outcome.drill_evidence_id } : {}),
      },
      check.check_id,
    ),
  };
}