// Rechecks current execution authorization before a protection-validation finding retest (PV-06).
import { firewallExpectationScopeKey } from '../contracts/protectionValidation.mjs';
import {
  assessProtectionRetestAuthorization,
  isProtectionValidationFinding,
} from '../lib/protectionValidationFindings.mjs';
import { getStore } from '../store.mjs';
import { bindingRecordsFromStore, currentOriginProof } from './originBindings.mjs';
import { PROTECTION_VALIDATION_STORE_KEYS } from './protectionValidation.mjs';

function deny(error, status = 409) {
  return { ok: false, error, status, drift: [], comparable_with_original: false };
}

function findingKind(finding) {
  const pv = finding?.protection_validation ?? {};
  return pv.comparison_kind ?? pv.comparison_context?.comparison_kind ?? null;
}

function sameEntryScope(row, route) {
  return row.anchor_target_id === route.anchor_target_id
    && row.entry_target_id === route.entry_target_id
    && (route.relation_kind == null || row.relation_kind === route.relation_kind)
    && (row.origin_binding_id ?? null) === (route.origin_binding_id ?? null);
}

function activeFirewallExpectation(rows, finding) {
  const context = finding.protection_validation?.comparison_context ?? {};
  const original = rows.find((row) => row.id === context.expectation_id) ?? null;
  if (original?.status === 'active') return original;
  if (!original) return null;
  const scopeKey = original.scope_key ?? firewallExpectationScopeKey(original);
  return rows.find((row) => row.status === 'active' && row.kind === 'firewall_change'
    && (row.scope_key ?? firewallExpectationScopeKey(row)) === scopeKey) ?? null;
}

/** Dev store (synchronous, for startTestRun): current relation/expectation, targets, binding, and ownership. */
export function resolveDevProtectionRetestAuthorization(ctx, finding) {
  if (!isProtectionValidationFinding(finding)) return null;
  const store = getStore();
  const tenantId = ctx?.tenantId;
  const owned = (rows) => (rows ?? []).filter((row) => row.tenant_id === tenantId);
  const targets = owned(store.targets);
  const targetById = (id) => targets.find((row) => row.id === id) ?? null;
  const records = bindingRecordsFromStore(store, tenantId);
  const verified = (id) => Boolean(id) && currentOriginProof(records, tenantId, id).verified === true;
  const kind = findingKind(finding);
  if (kind === 'path_validation') {
    const route = finding.protection_validation?.observed_route ?? {};
    const entryPath = owned(store[PROTECTION_VALIDATION_STORE_KEYS.entryPaths])
      .find((row) => row.status === 'active' && sameEntryScope(row, route)) ?? null;
    if (!entryPath) return deny('entry_path_archived');
    const originBinding = entryPath.origin_binding_id
      ? owned(store.originBindings).find((row) => row.id === entryPath.origin_binding_id) ?? null
      : null;
    return assessProtectionRetestAuthorization({
      finding,
      tenantId,
      entryPath,
      anchorTarget: targetById(entryPath.anchor_target_id),
      entryTarget: targetById(entryPath.entry_target_id),
      originBinding,
      ownershipVerified: verified(entryPath.anchor_target_id) && verified(entryPath.entry_target_id),
    });
  }
  if (kind === 'firewall_change') {
    const expectation = activeFirewallExpectation(owned(store[PROTECTION_VALIDATION_STORE_KEYS.expectations]), finding);
    const destinationTarget = expectation ? targetById(expectation.pre_post_mapping?.post_destination_target_id ?? expectation.destination_target_id) : null;
    return assessProtectionRetestAuthorization({
      finding,
      tenantId,
      expectation,
      destinationTarget,
      ownershipVerified: verified(destinationTarget?.id),
    });
  }
  return deny('comparison_context_missing');
}

/** Store-agnostic (async) variant over a PV-03 service and backend; used by the Postgres run start. */
export function createProtectionRetestAuthorizer({ base, backend }) {
  return async function resolveProtectionRetestAuthorization(ctx, finding) {
    if (!isProtectionValidationFinding(finding)) return null;
    const tenantId = ctx?.tenantId;
    const kind = findingKind(finding);
    if (kind === 'path_validation') {
      const route = finding.protection_validation?.observed_route ?? {};
      const rows = await backend.listEntryPathsByScope(ctx, {
        anchor_target_id: route.anchor_target_id,
        entry_target_id: route.entry_target_id,
        relation_kind: route.relation_kind,
        origin_binding_id: route.origin_binding_id ?? null,
      });
      const entryPath = rows.find((row) => row.tenant_id === tenantId && row.status === 'active') ?? null;
      if (!entryPath) return deny('entry_path_archived');
      const exec = await base.authorizeEntryPathForExecution(ctx, entryPath.id);
      if (!exec?.ok) return deny(exec?.error ?? 'target_not_authorized', exec?.status ?? 409);
      return assessProtectionRetestAuthorization({
        finding,
        tenantId,
        entryPath,
        anchorTarget: exec.anchor_target,
        entryTarget: exec.entry_target,
        originBinding: exec.origin_binding ?? null,
        ownershipVerified: true,
      });
    }
    if (kind === 'firewall_change') {
      const contextId = finding.protection_validation?.comparison_context?.expectation_id ?? null;
      const original = contextId ? await backend.getExpectation(ctx, contextId) : null;
      let expectation = original?.status === 'active' ? original : null;
      if (!expectation && original) {
        const scopeRows = await backend.listExpectationsByScope(ctx, 'firewall_change', original.scope_key ?? firewallExpectationScopeKey(original));
        expectation = scopeRows.find((row) => row.tenant_id === tenantId && row.status === 'active') ?? null;
      }
      const postTargetId = expectation?.pre_post_mapping?.post_destination_target_id ?? expectation?.destination_target_id;
      const loaded = expectation ? await backend.loadTargetContext(ctx, [postTargetId]) : { targets: [] };
      const destinationTarget = (loaded.targets ?? []).find((row) => row.tenant_id === tenantId && row.id === postTargetId) ?? null;
      const ownership = destinationTarget ? await base.verifyBaselineTargets(ctx, [destinationTarget.id], 'target_id') : { error: 'unknown_target' };
      return assessProtectionRetestAuthorization({
        finding,
        tenantId,
        expectation,
        destinationTarget,
        ownershipVerified: ownership === null,
      });
    }
    return deny('comparison_context_missing');
  };
}
