import { randomBytes } from 'node:crypto';
import { normalizeTargetInput, targetDedupeKey } from '../../contracts/targetManagement.mjs';
import { encodeBase32 } from '../../lib/base32.mjs';
import { mapProviderInventory } from '../../lib/connectorInventory.mjs';
import { paginateItems } from '../../lib/cursorPagination.mjs';
import { buildLoaCustodyDigest } from '../../lib/authorizationArtifactLedger.mjs';
import { newId } from '../../lib/ids.mjs';
import { LEAN_GROUP_LOOKUP } from './coreCatalogRepository.mjs';
import { PORTAL_REVAMP_REPOSITORY_METHODS } from './portalRevampRepository.mjs';

/** @type {readonly string[]} */
export const POSTGRES_PORTAL_DNS_SERVICE_METHODS = Object.freeze([
  'listChallenges',
  'issueDnsOwnershipChallenge',
  'verifyDnsOwnership',
]);

/** @type {readonly string[]} */
export const POSTGRES_LOA_SERVICE_METHODS = Object.freeze(['sign', 'revoke', 'getActive']);

/** @type {readonly string[]} */
export const POSTGRES_TARGET_DETAIL_SERVICE_METHODS = Object.freeze(['getTargetDetail']);

/** @type {readonly string[]} */
export const POSTGRES_REMEDIATION_SERVICE_METHODS = Object.freeze([
  'attachToFinding',
  'deliver',
  'updateState',
]);

/** @type {readonly string[]} */
export const POSTGRES_PORTAL_OWNERSHIP_SERVICE_METHODS = Object.freeze([
  'getLadder',
  'confirmTarget',
]);

/** @type {readonly string[]} */
export const POSTGRES_PORTAL_FINDINGS_SERVICE_METHODS = Object.freeze(['getEvidenceBundle']);

/** @type {readonly string[]} */
export const POSTGRES_PORTAL_TARGET_GROUPS_SERVICE_METHODS = Object.freeze([
  'restoreArchived',
  'bulkImportTargets',
]);

/** @type {readonly string[]} */
export const POSTGRES_PORTAL_WAF_SERVICE_METHODS = Object.freeze([
  'getCoverageSummary',
  'getConnectorInventory',
]);

/** @type {readonly string[]} */
export const POSTGRES_PORTAL_SIGNUP_SERVICE_METHODS = Object.freeze(['listEvents']);

function assertPortalRevampRepository(repositories) {
  const repo = repositories?.portalRevamp;
  if (!repo || typeof repo !== 'object') {
    throw new Error('Postgres portal revamp adapter requires repositories.portalRevamp.');
  }
  for (const method of PORTAL_REVAMP_REPOSITORY_METHODS) {
    if (typeof repo[method] !== 'function') {
      throw new Error(`Postgres portal revamp adapter requires portalRevamp.${method}().`);
    }
  }
}

const EMPTY_COUNTS = Object.freeze({
  runs_total: 0,
  findings_open: 0,
  findings_closed: 0,
});

const EMPTY_COVERAGE_SUMMARY = Object.freeze({
  assets_total: 0,
  protected: 0,
  underprotected: 0,
  unknown: 0,
  coverage_pct: 0,
  by_vendor: {},
  connectors_active: 0,
  connectors_degraded: 0,
  connectors_disabled: 0,
  refreshed_at: null,
});

const LADDER_STEP_IDS = Object.freeze([
  'declared',
  'dns_verified',
  'agent_verified',
  'user_confirmed',
]);

const LADDER_LABELS = Object.freeze({
  declared: 'Declared',
  dns_verified: 'DNS verified',
  agent_verified: 'Agent verified',
  user_confirmed: 'User confirmed',
});

const DNS_TIMEOUT_MS = 4000;
const VERIFY_RATE_LIMIT = 6;
const VERIFY_RATE_WINDOW_MS = 60_000;
const LOA_SCOPE_STATES = new Set(['agent_verified', 'user_confirmed']);

/** @type {Map<string, { windowStart: number, count: number }>} */
const verifyRateBuckets = new Map();

function flattenTxtRecords(records) {
  if (!Array.isArray(records)) return [];
  const out = [];
  for (const entry of records) {
    if (Array.isArray(entry)) {
      for (const chunk of entry) out.push(String(chunk));
    } else {
      out.push(String(entry));
    }
  }
  return out;
}

function checkVerifyRateLimit(targetId) {
  const key = `dns_verify:${targetId}`;
  const now = Date.now();
  const bucket = verifyRateBuckets.get(key);
  if (!bucket || now - bucket.windowStart >= VERIFY_RATE_WINDOW_MS) {
    verifyRateBuckets.set(key, { windowStart: now, count: 1 });
    return { allowed: true };
  }
  bucket.count += 1;
  if (bucket.count > VERIFY_RATE_LIMIT) {
    return {
      allowed: false,
      retryAfterSeconds: Math.ceil((VERIFY_RATE_WINDOW_MS - (now - bucket.windowStart)) / 1000),
    };
  }
  return { allowed: true };
}

async function resolveTxtWithTimeout(recordName, resolveTxt) {
  let resolveFn = resolveTxt;
  if (!resolveFn) {
    const dns = await import('node:dns/promises');
    resolveFn = dns.resolveTxt.bind(dns);
  }
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      const err = new Error('DNS lookup timed out');
      err.code = 'ETIMEOUT';
      reject(err);
    }, DNS_TIMEOUT_MS);
  });
  try {
    return await Promise.race([resolveFn(recordName), timeout]);
  } finally {
    clearTimeout(timer);
  }
}

async function loadConnectorInventory(repositories, ctx, connectorId) {
  const connectorRepository = repositories?.wafPosture;
  if (typeof connectorRepository?.getConnector !== 'function' || typeof connectorRepository?.listConnectorSnapshots !== 'function') {
    throw new Error('Postgres connector inventory requires wafPosture connector and snapshot repositories.');
  }
  const connector = await connectorRepository.getConnector(ctx, connectorId);
  if (!connector) return { error: 'connector_not_found', status: 404 };
  if (['disabled', 'revoked'].includes(String(connector.status ?? '').toLowerCase())) {
    return { error: 'connector_disabled', status: 409 };
  }

  const snapshots = await connectorRepository.listConnectorSnapshots(ctx, connectorId);
  const seenResources = new Set();
  const inventory = new Map();
  for (const snapshot of snapshots) {
    const resourceKey = snapshot.resource_ref_hash ?? snapshot.id;
    if (seenResources.has(resourceKey)) continue;
    seenResources.add(resourceKey);

    const mapped = mapProviderInventory(connector.provider, snapshot.summary);
    const direct = snapshot.summary && typeof snapshot.summary === 'object'
      ? snapshot.summary.items ?? snapshot.summary.inventory_items ?? []
      : [];
    const candidates = mapped.length
      ? mapped
      : Array.isArray(direct) && direct.length
        ? direct
        : snapshot.display_ref
          ? [{
              kind: /(?:ip|address)/i.test(snapshot.snapshot_kind) ? 'ip'
                : /url/i.test(snapshot.snapshot_kind) ? 'url' : 'fqdn',
              value: snapshot.display_ref,
              label: snapshot.display_ref,
              importable: true,
            }]
          : [];

    for (const candidate of candidates) {
      if (candidate?.importable === false) continue;
      try {
        const normalized = normalizeTargetInput(candidate);
        const key = targetDedupeKey(normalized);
        if (inventory.has(key)) continue;
        inventory.set(key, {
          kind: normalized.kind,
          value: normalized.value,
          label: String(candidate.label ?? normalized.value).slice(0, 300),
          resource_ref: snapshot.resource_ref_hash ?? null,
          importable: true,
          observed_at: snapshot.observed_at ?? null,
        });
      } catch {
        // Fail closed for malformed provider rows; never return an unvalidated target.
      }
    }
  }

  const items = [...inventory.values()].sort((left, right) => left.value.localeCompare(right.value));
  return {
    connector: { id: connector.id, provider: connector.provider, name: connector.name, status: connector.status },
    discovered_at: snapshots[0]?.observed_at ?? connector.last_success_at ?? null,
    items,
  };
}

/**
 * @param {{ repositories: Record<string, unknown> }} deps
 */
export function createPostgresPortalRevampServices(deps) {
  const repositories = deps?.repositories ?? deps;
  assertPortalRevampRepository(repositories);
  const portalRevamp = repositories.portalRevamp;
  const nowFn = deps?.now ?? (() => new Date());

  const auditRepo = repositories.audit;
  const validationEvidence = repositories.validationEvidence;

  const portalDns = {
    async listChallenges(ctx, groupId) {
      const items = await portalRevamp.listDnsChallengesByGroup(ctx, groupId);
      const count = items.length;
      return {
        items,
        count,
        meta: count
          ? undefined
          : { empty_reason: 'no_dns_challenges_recorded', target_group_id: groupId },
      };
    },
    async issueDnsOwnershipChallenge(ctx, { target_group_id, target_id }) {
      const target = await portalRevamp.resolveFqdnTarget(ctx, target_group_id, target_id ?? null);
      if (!target) return { error: target_id ? 'target_not_found' : 'no_fqdn_target', status: target_id ? 404 : 409 };

      const now = nowFn();
      const pending = (await portalRevamp.listDnsChallengesByGroup(ctx, target_group_id))
        .find(
          (row) =>
            row.target_id === target.id
            && row.state === 'pending'
            && new Date(row.expires_at).getTime() > now.getTime(),
        );
      if (pending) return { error: 'challenge_active', status: 409 };

      const issued_at = now.toISOString();
      const expires_at = new Date(now.getTime() + 15 * 60_000).toISOString();
      const record = {
        id: newId('dns'),
        target_group_id,
        target_id: target.id,
        record_name: `_astranull-challenge.${String(target.value).trim().toLowerCase()}`,
        record_value: encodeBase32(randomBytes(32)),
        ttl_seconds: 60,
        state: 'pending',
        issued_at,
        expires_at,
      };
      const challenge = await portalRevamp.insertDnsChallenge(ctx, record, auditRepo);
      return { challenge, audit_entry_id: challenge.audit_entry_id };
    },
    async verifyDnsOwnership(ctx, { target_group_id, challenge_id }, options = {}) {
      if (!target_group_id) return { error: 'missing_target_group_id', status: 400 };
      let challenge = challenge_id
        ? await portalRevamp.findDnsChallenge(ctx, challenge_id)
        : null;
      if (!challenge && !challenge_id) {
        challenge = (await portalRevamp.listDnsChallengesByGroup(ctx, target_group_id))
          .find((row) => row.state === 'pending');
      }
      if (!challenge || challenge.target_group_id !== target_group_id) {
        return { error: 'challenge_not_found', status: 404 };
      }
      if (!challenge.target_id) return { error: 'challenge_target_not_bound', status: 409 };
      const target = await portalRevamp.getActiveTarget(
        ctx,
        target_group_id,
        challenge.target_id,
      );
      if (!target) return { error: 'target_not_found', status: 404 };
      if (challenge.state !== 'pending') {
        return {
          challenge,
          verified: challenge.state === 'resolved',
          audit_entry_id: challenge.audit_entry_id,
        };
      }

      const lookupStartedAt = nowFn();
      if (new Date(challenge.expires_at).getTime() <= lookupStartedAt.getTime()) {
        return portalRevamp.finalizeDnsOwnershipCheck(ctx, {
          challenge_id: challenge.id,
          target_group_id,
          finalized_at: lookupStartedAt.toISOString(),
          matched: false,
          last_check_result: { matched: false, expired: true },
          transitioned_by: ctx.userId ?? 'system',
        }, auditRepo);
      }

      const rate = checkVerifyRateLimit(challenge.target_id);
      if (!rate.allowed) {
        return { error: 'rate_limited', status: 429, retry_after_seconds: rate.retryAfterSeconds };
      }

      let lookup;
      let timedOut = false;
      try {
        lookup = await resolveTxtWithTimeout(challenge.record_name, options.resolveTxt);
      } catch (err) {
        timedOut = err?.code === 'ETIMEOUT';
        lookup = [];
      }
      const finalizedAt = nowFn();
      const values = flattenTxtRecords(lookup);
      const matched = values.some((value) => value === challenge.record_value);
      const finalized = await portalRevamp.finalizeDnsOwnershipCheck(ctx, {
        challenge_id: challenge.id,
        target_group_id,
        finalized_at: finalizedAt.toISOString(),
        matched,
        last_check_result: {
          resolver: 'system',
          records: values,
          matched,
          timed_out: timedOut,
        },
        verification_id: matched ? newId('tv') : null,
        transitioned_by: ctx.userId ?? 'system',
      }, auditRepo);
      if (finalized?.error) return finalized;

      const response = {
        challenge: finalized.challenge,
        verified: finalized.verified,
        audit_entry_id: finalized.audit_entry_id,
      };
      if (timedOut) response.meta = { timeout: true };
      return response;
    },
  };

  const loa = {
    async sign(ctx, groupId, payload) {
      if (payload?.attested !== true) return { error: 'attestation_required', status: 403 };
      if (!Array.isArray(payload.scope_ack) || payload.scope_ack.length === 0) {
        return { error: 'invalid_scope_ack', status: 400 };
      }
      const acknowledged = payload.scope_ack.map((targetId) => String(targetId ?? '').trim());
      if (acknowledged.some((targetId) => !targetId)) {
        return { error: 'invalid_scope_ack', status: 400 };
      }
      const scopeSource = await portalRevamp.getLoaScopeTargets(ctx, groupId);
      if (!scopeSource) return { error: 'target_group_not_found', status: 404 };
      const targetIds = new Set(scopeSource.targets.map((target) => target.id));
      const ackSet = new Set(acknowledged);
      if ([...ackSet].some((targetId) => !targetIds.has(targetId))) {
        return { error: 'scope_target_not_found', status: 400 };
      }
      const scope_snapshot = { targets: [], excluded: [] };
      for (const target of scopeSource.targets) {
        const eligible = LOA_SCOPE_STATES.has(target.verification_state);
        if (eligible && ackSet.has(target.id)) {
          scope_snapshot.targets.push(target.id);
        } else {
          scope_snapshot.excluded.push({
            target_id: target.id,
            reason: eligible ? 'not_acknowledged' : 'unverified',
          });
        }
      }
      if (scope_snapshot.targets.length === 0) {
        return { error: 'invalid_scope_ack', status: 400 };
      }

      const active = await portalRevamp.getActiveLoaByGroup(ctx, groupId);
      if (active) return { error: 'loa_active', status: 409 };
      const signed_at = nowFn().toISOString();
      const custody_digest_sha256 = buildLoaCustodyDigest({
        tenant_id: ctx.tenantId,
        target_group_id: groupId,
        signer_name: payload.signer_name,
        signer_email: payload.signer_email,
        signed_at,
        scope_snapshot,
      });
      const loaRecord = await portalRevamp.insertLoaSignature(
        ctx,
        {
          id: newId('loa'),
          target_group_id: groupId,
          state: 'signed',
          signer_name: String(payload.signer_name ?? '').trim(),
          signer_title: String(payload.signer_title ?? '').trim(),
          signer_email: String(payload.signer_email ?? '').trim(),
          signed_at,
          expires_at: payload.expires_at ?? null,
          emergency_contact: payload.emergency_contact ?? {},
          attested: true,
          scope_snapshot,
          custody_artifact_id: newId('art'),
          custody_digest_sha256,
        },
        auditRepo,
      );
      if (loaRecord?.error) return loaRecord;
      return {
        loa: loaRecord,
        custody_artifact_id: loaRecord.custody_artifact_id,
        custody_digest_sha256,
        audit_entry_id: loaRecord.audit_entry_id,
      };
    },
    async revoke(ctx, loaId, _reason) {
      const record = await portalRevamp.updateLoaSignature(ctx, loaId, { state: 'revoked' }, auditRepo);
      if (!record) return { error: 'not_found', status: 404 };
      return { loa: record, audit_entry_id: record.audit_entry_id };
    },
    async getActive(ctx, groupId) {
      const active = await portalRevamp.getActiveLoaByGroup(ctx, groupId);
      return {
        loa: active,
        meta: active ? undefined : { empty_reason: 'no_active_loa' },
      };
    },
  };

  const targetDetail = {
    async getTargetDetail(ctx, targetId, _query = {}) {
      const bundle = await portalRevamp.getTargetDetailBundle(ctx, targetId, _query);
      if (bundle) return bundle;
      return { error: 'not_found', status: 404 };
    },
  };

  const remediation = {
    async attachToFinding(ctx, findingId, payload = {}) {
      const existing = await portalRevamp.getFindingRemediationByFinding(ctx, findingId);
      if (existing) return { remediation: existing };

      const steps = Array.isArray(payload.steps)
        ? payload.steps.map((step) => String(step))
        : ['Review finding evidence', 'Apply recommended control change', 'Re-run validation'];
      const record = await portalRevamp.insertFindingRemediation(ctx, {
        id: `rem_${Date.now()}`,
        finding_id: findingId,
        action_slug: String(payload.action_slug ?? 'origin_restrict'),
        owner_group: String(payload.owner_group ?? 'edge-sre'),
        state: 'open',
        description: String(payload.description ?? 'Remediation plan for linked finding.'),
        steps,
        audit_entry_id: `aud_${Date.now()}`,
      });
      return { remediation: record };
    },
    async deliver(_ctx, actionItemId, channel, targetRef) {
      return {
        action_item: { action_item_id: actionItemId },
        delivery_receipt: {
          action_item_id: actionItemId,
          channel,
          target_ref: targetRef ?? null,
          status: 'delegated_to_waf_action_item_deliver',
        },
      };
    },
    async updateState(ctx, remediationId, state) {
      const record = await portalRevamp.updateFindingRemediation(ctx, remediationId, {
        state: String(state ?? '').trim(),
      });
      if (!record) return { error: 'not_found', status: 404 };
      return { remediation: record };
    },
  };

  const portalOwnership = {
    async getLadder(ctx, groupId) {
      const counts = await portalRevamp.getVerificationLadderCounts(ctx, groupId);
      const total = counts?.total ?? 0;
      const steps = LADDER_STEP_IDS.map((id) => ({
        id,
        label: LADDER_LABELS[id] ?? id,
        done: total > 0 && (counts?.[id] ?? 0) >= total,
        count: counts?.[id] ?? 0,
        total,
      }));
      return {
        steps,
        meta: total === 0
          ? { empty_reason: 'No targets declared for this group; the verification ladder cannot be computed yet.' }
          : undefined,
      };
    },
    async confirmTarget(ctx, groupId, targetId, signer) {
      return portalRevamp.confirmTargetWithLoa(ctx, {
        target_group_id: groupId,
        target_id: targetId,
        verification_id: newId('tv'),
        transitioned_at: nowFn().toISOString(),
        note: signer?.note ?? null,
      }, auditRepo);
    },
  };

  const portalFindings = {
    async getEvidenceBundle(ctx, findingId) {
      if (!validationEvidence?.getFinding) {
        return {
          finding: null,
          bundle: null,
          artifacts: [],
          custody_chain: [],
          verify_url: '/v1/custody/verify',
          meta: { empty_reason: 'evidence_service_unavailable', finding_id: findingId },
        };
      }

      const finding = await validationEvidence.getFinding(ctx, findingId);
      if (!finding) {
        return {
          finding: null,
          bundle: null,
          artifacts: [],
          custody_chain: [],
          verify_url: '/v1/custody/verify',
          meta: { empty_reason: 'finding_not_found', finding_id: findingId },
        };
      }

      const vault = finding.test_run_id && validationEvidence.listEvidenceForRun
        ? await validationEvidence.listEvidenceForRun(ctx, finding.test_run_id)
        : validationEvidence.listEvidence
          ? await validationEvidence.listEvidence(ctx, { findingId })
          : [];

      if (!vault.length) {
        return {
          finding: { id: finding.id, title: finding.title ?? null, run_id: finding.test_run_id ?? null },
          bundle: null,
          artifacts: [],
          custody_chain: [],
          verify_url: '/v1/custody/verify',
          meta: { empty_reason: 'no_evidence_bundle_sealed_for_finding', finding_id: findingId },
        };
      }

      const artifacts = vault.map((row) => ({
        id: row.id,
        kind: row.label ?? row.kind ?? 'metadata_evidence',
        run_id: row.test_run_id ?? finding.test_run_id ?? null,
        sha256: row.sha256 ?? row.content_sha256 ?? row.metadata?.sha256 ?? null,
        sealed_at: row.sealed_at ?? row.created_at ?? null,
        size_bytes: row.size_bytes ?? row.metadata?.size_bytes ?? null,
      }));

      const custody_chain = artifacts
        .filter((art) => art.sha256)
        .map((art, index) => ({
          step: index + 1,
          kind: `${art.kind}_sealed`,
          sha256: art.sha256,
          at: art.sealed_at,
        }));

      return {
        finding: { id: finding.id, title: finding.title ?? null, run_id: finding.test_run_id ?? null },
        bundle: null,
        artifacts,
        custody_chain,
        verify_url: '/v1/custody/verify',
      };
    },
  };

  const portalTargetGroups = {
    async restoreArchived(ctx, groupId) {
      if (typeof repositories.coreCatalog?.restoreTargetGroup !== 'function') {
        throw new Error('Postgres target restore requires coreCatalog.restoreTargetGroup().');
      }
      const restored = await repositories.coreCatalog.restoreTargetGroup(ctx, groupId);
      if (restored?.error) return restored.error === 'not_found' ? { error: 'not_archived', status: 404 } : restored;
      const targetGroup = await repositories.coreCatalog.getTargetGroup(ctx, groupId, LEAN_GROUP_LOOKUP);
      return { target_group: targetGroup, audit_entry_id: restored.audit_entry_id };
    },
    async bulkImportTargets(ctx, groupId, body = {}) {
      if (typeof repositories.coreCatalog?.bulkImportTargets !== 'function') {
        throw new Error('Postgres target import requires coreCatalog.bulkImportTargets().');
      }
      let trustedConnector = null;
      let connectorInventoryKeys = new Set();
      if (body.connector_id) {
        const inventory = await loadConnectorInventory(repositories, ctx, String(body.connector_id));
        if (inventory.error) return inventory;
        trustedConnector = inventory.connector;
        connectorInventoryKeys = new Set(inventory.items.map((item) => targetDedupeKey(item)));
      }
      return repositories.coreCatalog.bulkImportTargets(ctx, groupId, body, {
        trustedConnector,
        connectorInventoryKeys,
      });
    },
  };

  const portalWaf = {
    async getCoverageSummary(ctx) {
      const row = await portalRevamp.getWafCoverageSummaryRow(ctx);
      if (row) return row;
      return {
        ...EMPTY_COVERAGE_SUMMARY,
        meta: { empty_reason: 'coverage_summary_not_populated', tenant_id: ctx.tenantId },
      };
    },
    async getConnectorInventory(ctx, connectorId, query = {}) {
      const inventory = await loadConnectorInventory(repositories, ctx, connectorId);
      if (inventory.error) return inventory;
      const paged = paginateItems(inventory.items, {
        limit: Number(query.limit) || 50,
        cursor: query.cursor,
        cursorField: 'value',
      });
      return {
        provider: inventory.connector.provider ?? null,
        account: inventory.connector.name ?? null,
        scope: 'read_only',
        discovered_at: inventory.discovered_at,
        items: paged.items,
        count: paged.count,
        next_cursor: paged.next_cursor ?? undefined,
        meta: paged.items.length
          ? undefined
          : { empty_reason: 'connector_inventory_not_populated', connector_id: connectorId },
      };
    },
  };

  const portalSignup = {
    async listEvents(requestId, options = {}) {
      if (options.rateLimitKey && options.rateLimit?.check) {
        const rate = options.rateLimit.check(options.rateLimitKey);
        if (!rate.allowed) {
          return {
            error: 'rate_limited',
            status: 429,
            retry_after_seconds: rate.retryAfterSeconds,
          };
        }
      }
      const events = await portalRevamp.listSignupQueueEvents(requestId, {
        truncateMessageChars: 500,
      });
      return {
        events,
        count: events.length,
        meta: events.length
          ? undefined
          : { empty_reason: 'no_signup_events_recorded', request_id: requestId },
      };
    },
  };

  return {
    portalDns,
    loa,
    targetDetail,
    remediation,
    portalOwnership,
    portalFindings,
    portalTargetGroups,
    portalWaf,
    portalSignup,
  };
}

/**
 * Merges portal revamp listChallenges into an existing dnsOwnership service adapter.
 *
 * @param {Record<string, unknown>} dnsOwnership
 * @param {{ listChallenges: (...args: unknown[]) => unknown }} portalDns
 */
export function mergePortalDnsOwnershipServices(dnsOwnership, portalDns) {
  return {
    ...dnsOwnership,
    listChallenges: portalDns.listChallenges.bind(portalDns),
    issueDnsOwnershipChallenge: portalDns.issueDnsOwnershipChallenge.bind(portalDns),
    verifyDnsOwnership: portalDns.verifyDnsOwnership.bind(portalDns),
  };
}

/**
 * Merges portal revamp ownership helpers into an existing ownershipVerification adapter.
 *
 * @param {Record<string, unknown>} ownershipVerification
 * @param {{ getLadder: (...args: unknown[]) => unknown, confirmTarget: (...args: unknown[]) => unknown }} portalOwnership
 */
export function mergePortalOwnershipVerificationServices(ownershipVerification, portalOwnership) {
  return {
    ...ownershipVerification,
    getLadder: portalOwnership.getLadder.bind(portalOwnership),
    confirmTarget: portalOwnership.confirmTarget.bind(portalOwnership),
  };
}