/**
 * Finding lifecycle shared by the dev store and the Postgres adapter.
 * Closure records an audited timestamp. It does not claim a fix was proved.
 */
import { createHash } from 'node:crypto';
import { roleHasPermission } from '../contracts/roles.mjs';
import { requirePermission } from '../rbac.mjs';
import { REJECT_ICMP_MIN_ELAPSED_MS } from './networkProbeOutcomes.mjs';

export function computeDenyRulesDigest(declarations) {
  if (!declarations) return null;
  const policy = Array.isArray(declarations.network_policy) ? declarations.network_policy : [];
  const denyRules = policy
    .filter((r) => r && r.action === 'deny' && r.port != null)
    .map((r) => ({
      protocol: String(r.protocol ?? 'tcp').toLowerCase(),
      port: Number(r.port),
      action: 'deny',
      address_family: String(r.address_family ?? 'any').toLowerCase(),
    }))
    .sort((a, b) => a.protocol.localeCompare(b.protocol) || a.port - b.port || a.address_family.localeCompare(b.address_family));
  if (denyRules.length === 0) return null;
  return createHash('sha256').update(JSON.stringify(denyRules)).digest('hex');
}

export const FINDING_LIFECYCLE = Object.freeze([
  'open', 'in_progress', 'accepted_risk', 'resolved', 'closed', 'false_positive', 'accepted', 'fix_verified',
]);
const LIFECYCLE = new Set(FINDING_LIFECYCLE);
const CLOSURE_STATUSES = new Set(['accepted_risk', 'resolved', 'closed', 'false_positive', 'accepted', 'fix_verified']);
const OPEN_STATUSES = new Set(['open', 'in_progress']);
const PASSING_VERDICTS = new Set(['protected', 'pass', 'passed', 'success', 'ok', 'allowed_as_expected', 'edge_protected']);

export const RISK_ACCEPTANCE_REASON_MIN = 20;
export const RISK_ACCEPTANCE_REASON_MAX = 2000;
export const RISK_ACCEPTANCE_MAX_REVIEW_DAYS = 365;
const DAY_MS = 24 * 60 * 60 * 1000;
const ISO_TIMESTAMP = /^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?(?:Z|[+-]\d{2}:\d{2}))?$/;

function riskAcceptanceRequired(message, field) {
  return { error: 'risk_acceptance_required', status: 400, field, message };
}

/** Validate the customer's risk decision; the accepting user and time come from the server. */
export function validateRiskAcceptance(input, now = new Date()) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return riskAcceptanceRequired('Accepting risk needs a reason and a review date.', 'risk_acceptance');
  }
  const reason = typeof input.reason === 'string' ? input.reason.trim() : '';
  if (reason.length < RISK_ACCEPTANCE_REASON_MIN || reason.length > RISK_ACCEPTANCE_REASON_MAX) {
    return riskAcceptanceRequired(
      `The reason must be ${RISK_ACCEPTANCE_REASON_MIN} to ${RISK_ACCEPTANCE_REASON_MAX} characters.`,
      'risk_acceptance.reason',
    );
  }
  const rawReview = typeof input.review_at === 'string' ? input.review_at.trim() : '';
  const reviewMs = ISO_TIMESTAMP.test(rawReview) ? Date.parse(rawReview) : Number.NaN;
  const nowMs = now.getTime();
  if (!Number.isFinite(reviewMs) || reviewMs <= nowMs || reviewMs > nowMs + RISK_ACCEPTANCE_MAX_REVIEW_DAYS * DAY_MS) {
    return riskAcceptanceRequired(
      `The review date must be in the future and within ${RISK_ACCEPTANCE_MAX_REVIEW_DAYS} days.`,
      'risk_acceptance.review_at',
    );
  }
  return { ok: true, reason, review_at: new Date(reviewMs).toISOString() };
}

/**
 * Pure lifecycle plan. Closure sets closed_at; reopen clears it. Accepting risk needs the
 * finding:accept_risk permission and a reasoned, dated decision; any other status clears it.
 * system_summary is server-written verdict text and is never accepted from a client.
 */
export function planFindingPatch(body = {}, ctx = null, { now = new Date(), findingId = null } = {}) {
  if (body && Object.hasOwn(body, 'system_summary')) {
    return { error: 'system_summary_immutable', status: 400, message: 'The recorded explanation cannot be edited.' };
  }
  if (body.status == null || body.status === '') return { patch: {} };
  if (!LIFECYCLE.has(body.status)) return { error: 'invalid_lifecycle', status: 400 };
  const patch = { status: body.status };
  if (body.status === 'accepted_risk') {
    const allowed = authorizeRiskAcceptance(ctx, findingId);
    if (!allowed.ok) return { error: 'forbidden', status: allowed.status ?? 403, permission: 'finding:accept_risk' };
    const decision = validateRiskAcceptance(body.risk_acceptance, now);
    if (decision.error) return decision;
    patch.risk_acceptance = {
      reason: decision.reason,
      review_at: decision.review_at,
      accepted_by: ctx?.userId ?? null,
      accepted_at: now.toISOString(),
    };
  } else {
    patch.risk_acceptance = null;
  }
  if (CLOSURE_STATUSES.has(body.status)) patch.closed_at = now.toISOString();
  else if (body.status === 'open' || body.status === 'in_progress') patch.closed_at = null;
  return { patch };
}

function stampText(...values) {
  for (const value of values) {
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return null;
}

function isViolationOnlyCheck(checkId, probeKind) {
  const id = String(checkId ?? '');
  const kind = String(probeKind ?? '');
  return id.startsWith('nfw.')
    || id.startsWith('reflect.')
    || ['tcp_connect', 'udp_probe', 'port_scan_bounded', 'reflection_service_probe', 'connection_limit_probe', 'host_sni_bypass'].includes(kind);
}

function perspectiveId(value) {
  if (typeof value === 'string' && value.trim()) return value.trim();
  if (value && typeof value === 'object' && typeof value.id === 'string' && value.id.trim()) return value.id.trim();
  return null;
}

function findingPerspective(finding) {
  return perspectiveId(
    finding?.source_perspective
    ?? finding?.metadata?.source_perspective
    ?? finding?.protection_validation?.source_perspective
    ?? finding?.failed_expectation?.source_perspective
  );
}

function retestPerspective(run, verdict) {
  return perspectiveId(
    verdict?.source_perspective
    ?? run?.source_perspective
    ?? verdict?.placement_confidence?.source_perspective
    ?? run?.probe_metadata?.source_perspective
    ?? verdict?.metadata?.source_perspective
    ?? verdict?.metadata_json?.source_perspective
  );
}

function combinedMetadata(verdict, run) {
  const sources = [
    verdict?.metadata,
    verdict?.metadata_json,
    verdict?.placement_confidence,
    run?.probe_metadata,
    run?.probe_external_result?.metadata,
    run?.summary_json,
    run?.summary,
  ].filter((entry) => entry && typeof entry === 'object');
  return Object.assign({}, ...sources);
}

function retestIncomplete(verdict, run) {
  const value = String(verdict?.verdict ?? '').trim().toLowerCase();
  if (!value || value === 'inconclusive' || value === 'unknown' || value === 'error' || value === 'skipped') return true;
  if (!PASSING_VERDICTS.has(value)) return true;
  const sources = [
    verdict?.metadata, verdict?.metadata_json, run?.probe_metadata, run?.summary_json, run?.summary,
    ...(Array.isArray(run?.readiness_result_metadata) ? run.readiness_result_metadata : []),
  ].filter((entry) => entry && typeof entry === 'object');
  return sources.some((entry) => entry.complete === false || entry.comparison_complete === false
    || entry.observation_only === true || entry.planned_legs_complete === false
    || entry.evidence_complete === false || entry.capture_complete === false);
}

function recordedCheckVersion(row) {
  return stampText(
    row?.check_version,
    row?.check_definition_version,
    row?.protection_validation?.check_version,
    row?.provenance_json?.check_version,
  );
}

function recordedGradingVersion(row) {
  return stampText(
    row?.grading_version,
    row?.protection_validation?.grading_version,
    row?.provenance_json?.grading_version,
    row?.metadata?.grading_version,
    row?.metadata_json?.grading_version,
    row?.probe_metadata?.grading_version,
  );
}

function hasEarlierPathProof(finding, perspective, addressFamily) {
  if (finding?.path_proven === true) return true;
  const fam = addressFamily != null ? String(addressFamily) : null;
  const persp = perspective != null ? String(perspective) : null;
  const sources = [
    finding?.proven_paths,
    finding?.protection_validation?.proven_paths,
    finding?.metadata?.proven_paths,
  ].filter(Array.isArray);
  for (const paths of sources) {
    if (paths.some((p) => {
      const matchP = !p?.perspective || !persp || String(p.perspective) === persp;
      const matchF = !p?.address_family || !fam || String(p.address_family) === fam;
      return matchP && matchF;
    })) {
      return true;
    }
  }
  return false;
}

/** Complete passing retest of the same check/target/scope/versions. Partial or inconclusive never closes. */
export function planFixVerifiedFromRetest({ finding, run, verdict, declarations = null, now = new Date() } = {}) {
  const status = String(finding?.status ?? finding?.state ?? '').trim().toLowerCase();
  if (!OPEN_STATUSES.has(status)) return { action: 'none', reason: 'not_open' };
  if (!finding || !run || !verdict) return { action: 'none', reason: 'missing_input' };
  if (finding.check_id !== run.check_id && finding.check_id !== verdict.check_id) {
    return { action: 'none', reason: 'check_mismatch' };
  }
  const targetId = run.target_id ?? verdict.target_id;
  if (finding.target_id && targetId && finding.target_id !== targetId) return { action: 'none', reason: 'target_mismatch' };
  if (finding.target_group_id && run.target_group_id && finding.target_group_id !== run.target_group_id) {
    return { action: 'none', reason: 'scope_mismatch' };
  }

  const checkId = finding.check_id ?? run.check_id ?? verdict.check_id;
  const probeKind = run.probe_profile?.kind ?? verdict.probe_profile?.kind;
  const violationOnly = isViolationOnlyCheck(checkId, probeKind);

  let verificationBasis = 'passing_retest';
  if (violationOnly) {
    // Retest complete check
    const runStatus = String(run.status ?? '').trim().toLowerCase();
    if (['error', 'cancelled', 'canceled'].includes(runStatus)) {
      return { action: 'none', reason: 'retest_incomplete' };
    }
    const verdictValue = String(verdict.verdict ?? '').trim().toLowerCase();
    if (!verdictValue || ['error', 'skipped'].includes(verdictValue)) {
      return { action: 'none', reason: 'retest_incomplete' };
    }
    const sources = [
      verdict.metadata, verdict.metadata_json, run.probe_metadata, run.summary_json, run.summary,
      ...(Array.isArray(run.readiness_result_metadata) ? run.readiness_result_metadata : []),
    ].filter((entry) => entry && typeof entry === 'object');
    if (sources.some((entry) => entry.complete === false || entry.planned_legs_complete === false || entry.evidence_complete === false || entry.capture_complete === false)) {
      return { action: 'none', reason: 'partial_or_inconclusive' };
    }

    // Condition 2: same perspective
    const fp = findingPerspective(finding);
    const rp = retestPerspective(run, verdict);
    if (!fp || !rp || fp !== rp) {
      return { action: 'none', reason: 'perspective_mismatch' };
    }

    // Condition 3: >=2 agreeing samples
    const meta = combinedMetadata(verdict, run);
    const portResults = Array.isArray(meta.port_results) ? meta.port_results : [];
    const portResultsAgree = portResults.length > 0 && portResults.every((p) => (p.sample_agreement === 'agree' || p.sample_agreement === 'agreed') && (Array.isArray(p.samples) ? p.samples.length >= 2 : true));
    const topAgree = (meta.sample_agreement === 'agree' || meta.sample_agreement === 'agreed') && (Array.isArray(meta.samples) ? meta.samples.length >= 2 : Number(meta.samples_count ?? meta.sample_count) >= 2);
    if (!topAgree && !portResultsAgree) {
      return { action: 'none', reason: 'samples_disagree_or_insufficient' };
    }

    // Condition 4: no violation found
    if (['exposed', 'unprotected', 'gap', 'fail', 'failed'].includes(verdictValue)) {
      return { action: 'none', reason: 'violation_observed' };
    }
    if (verdict.createsFinding === true || verdict.creates_finding === true || meta.creates_finding === true) {
      return { action: 'none', reason: 'violation_observed' };
    }
    if (meta.violation === true || portResults.some((p) => p.result === 'violated')) {
      return { action: 'none', reason: 'violation_observed' };
    }

    // Condition 5: unprobed_deny_ports empty
    const unprobed = meta.unprobed_deny_ports ?? meta.unprobed_ports;
    if (Array.isArray(unprobed) && unprobed.length > 0) {
      return { action: 'none', reason: 'unprobed_deny_ports_present' };
    }

    // Condition 6: N12 gate — every sample must be a target-attributed non-violation
    const allSamples = [];
    if (Array.isArray(meta.samples) && meta.samples.length > 0) {
      allSamples.push(...meta.samples);
    }
    for (const p of portResults) {
      if (Array.isArray(p.samples) && p.samples.length > 0) {
        allSamples.push(...p.samples.map((s) => ({ ...p, ...s })));
      } else {
        allSamples.push(p);
      }
    }
    if (allSamples.length === 0) {
      allSamples.push(meta);
    }

    if (allSamples.some((s) => s.local_error === true) || meta.local_error === true || portResults.some((p) => p.local_error === true)) {
      return { action: 'none', reason: 'local_probe_error' };
    }
    if (allSamples.some((s) => s.peer_is_cdn === true) || meta.peer_is_cdn === true || portResults.some((p) => p.peer_is_cdn === true)) {
      return { action: 'none', reason: 'peer_is_cdn' };
    }

    for (const sample of allSamples) {
      const proto = String(sample.protocol ?? meta.protocol ?? (checkId.includes('udp') ? 'udp' : 'tcp')).toLowerCase();
      if (proto === 'udp') {
        const outcome = sample.udp_outcome ?? sample.outcome;
        if (outcome === 'silent') {
          // allowed outcome
        } else if (outcome === 'rejected_icmp') {
          const elapsed = sample.elapsed_ms ?? meta.elapsed_ms;
          const fam = sample.address_family ?? meta.address_family;
          const proven = elapsed != null && elapsed >= REJECT_ICMP_MIN_ELAPSED_MS && hasEarlierPathProof(finding, fp, fam);
          if (!proven) return { action: 'none', reason: 'path_not_proven' };
        } else {
          return { action: 'none', reason: 'path_not_proven' };
        }
      } else {
        const outcome = sample.tcp_outcome ?? sample.outcome;
        if (outcome === 'timeout' || outcome === 'refused_rst') {
          // allowed outcome
        } else if (outcome === 'rejected_icmp') {
          const elapsed = sample.elapsed_ms ?? meta.elapsed_ms;
          const fam = sample.address_family ?? meta.address_family;
          const proven = elapsed != null && elapsed >= REJECT_ICMP_MIN_ELAPSED_MS && hasEarlierPathProof(finding, fp, fam);
          if (!proven) return { action: 'none', reason: 'path_not_proven' };
        } else {
          return { action: 'none', reason: 'path_not_proven' };
        }
      }
    }

    // Condition 7: Declarations deny rules match
    const activeDeclarations = declarations
      ?? verdict?.declarations
      ?? run?.declarations
      ?? run?.probe_metadata?.declarations
      ?? null;
    const recordedDigest = finding?.declaration_digest
      ?? finding?.protection_validation?.declaration_digest
      ?? null;
    if (recordedDigest) {
      if (!activeDeclarations) {
        return { action: 'none', reason: 'declaration_changed' };
      }
      const curDigest = computeDenyRulesDigest(activeDeclarations);
      if (curDigest !== recordedDigest) {
        return { action: 'none', reason: 'declaration_changed' };
      }
      const findingPorts = finding?.declared_deny_ports ?? finding?.ports ?? [];
      if (Array.isArray(findingPorts) && findingPorts.length > 0) {
        const policy = Array.isArray(activeDeclarations.network_policy) ? activeDeclarations.network_policy : [];
        const stillDeniesAll = findingPorts.every((port) =>
          policy.some((r) => r.action === 'deny' && Number(r.port) === Number(port))
        );
        if (!stillDeniesAll) {
          return { action: 'none', reason: 'declaration_changed' };
        }
      }
    } else if (activeDeclarations != null && (checkId.startsWith('nfw.declared_deny_') || checkId.startsWith('l3.'))) {
      const curDigest = computeDenyRulesDigest(activeDeclarations);
      if (!curDigest) {
        return { action: 'none', reason: 'declaration_changed' };
      }
    }

    verificationBasis = 'violation_not_reproduced';
  } else {
    if (retestIncomplete(verdict, run)) return { action: 'none', reason: 'partial_or_inconclusive' };
  }

  const findingCheck = recordedCheckVersion(finding);
  const runCheck = recordedCheckVersion(run) ?? recordedCheckVersion(verdict);
  if (findingCheck && runCheck && findingCheck !== runCheck) return { action: 'none', reason: 'check_definition_version_mismatch' };
  const findingGrading = recordedGradingVersion(finding);
  const runGrading = recordedGradingVersion(verdict) ?? recordedGradingVersion(run);
  if (findingGrading && runGrading && findingGrading !== runGrading) return { action: 'none', reason: 'grading_version_mismatch' };
  const closedAt = now instanceof Date ? now.toISOString() : new Date(now).toISOString();
  return {
    action: 'fix_verified',
    verification_basis: verificationBasis,
    finding_id: finding.id ?? null,
    patch: {
      status: 'fix_verified',
      closed_at: closedAt,
      verifying_run_id: run.id ?? null,
      last_verdict_id: verdict.id ?? finding.last_verdict_id ?? null,
      verification_basis: verificationBasis,
    },
  };
}

function authorizeRiskAcceptance(ctx, findingId) {
  if (!ctx) return { ok: false, status: 403 };
  const scopes = ctx.scopes;
  const scopeOk = !Array.isArray(scopes) || scopes.includes('*') || scopes.includes('finding:accept_risk');
  if (roleHasPermission(ctx.role, 'finding:accept_risk') && scopeOk) return { ok: true };
  return requirePermission(ctx, 'finding:accept_risk', { resource_type: 'finding', resource_id: findingId });
}

/** finding:write, checked before requirePermission so an allowed role does not record a false denial. */
export function authorizeFindingWrite(ctx) {
  const roleOk = roleHasPermission(ctx?.role, 'finding:write');
  const scopes = ctx?.scopes;
  const scopeOk = !Array.isArray(scopes) || scopes.includes('*') || scopes.includes('finding:write');
  if (roleOk && scopeOk) return { ok: true };
  return requirePermission(ctx, 'finding:write', { resource_type: 'finding' });
}
