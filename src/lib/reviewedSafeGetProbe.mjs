import { applyEvasionTransform, buildEvasionRequest } from './vectorProbes/evasionProbes.mjs';
import { markerResponseSnapshot, readSignatureBody, signatureBodyComplete, markerBaselineHealth, isBlockedOrChallenged } from './outsideInWafScanner.mjs';
import { reviewedHash } from './reviewedSafeExecution.mjs';
import { reviewedGrantExact, reviewedGrantJson, reviewedGrantUtc } from '../contracts/reviewedExecutionGrant.mjs';
import { canonicalJsonStringify } from './custody.mjs';

const ROLES = ['permitted','untransformed','transformed'];
function requests(job) {
  const transformed = applyEvasionTransform('base64_wrap','sqli');
  return [buildEvasionRequest(job.target.value,{ sent_value: null }),
    buildEvasionRequest(job.target.value,{ sent_value: transformed.marker }), buildEvasionRequest(job.target.value,transformed)];
}
export function reviewedSafeLegDescriptors(job) {
  return requests(job).map((request,index) => { const url = new URL(request.url); return { role: ROLES[index], order: index + 1,
    method: 'GET', origin: url.origin, path: url.pathname, query_sha256: reviewedHash(url.search),
    request_schema: 'fixed-asn-probe-query.v1', body_bytes: 0 }; });
}
const projected = (snapshot) => Object.fromEntries(['status_code','header_names','block_page_signature_id','denial_signature','connection_dropped'].map((k) => [k,snapshot[k]]));
function grade(legs) {
  const permitted = legs[0];
  const healthy = permitted?.health === 'healthy' && permitted.completion === 'complete';
  const baseline = healthy && legs[1]?.completion === 'complete' ? isBlockedOrChallenged(legs[1].snapshot,permitted.snapshot) : null;
  const transformed = healthy && legs[2]?.completion === 'complete' ? isBlockedOrChallenged(legs[2].snapshot,permitted.snapshot) : null;
  const complete = healthy && legs.length === 3 && legs.every((leg) => leg.completion === 'complete')
    && baseline && transformed && !baseline.inconclusive && !transformed.inconclusive;
  const externalResult = complete && baseline.blocked === true ? transformed.blocked === true ? 'blocked' : transformed.allowed === true ? 'connected' : 'not_run' : 'not_run';
  return { baseline, transformed, complete: Boolean(complete), externalResult };
}
/** Fixed inert three-leg GET producer. Transport is supplied only AFTER the reviewed
 * worker's actual dual verification and shared durable claim; no caller request/profile knobs. */
export async function probeReviewedSafeGet(job, deps, claim) {
  const planned = requests(job), descriptors = reviewedSafeLegDescriptors(job), legs = [];
  for (let index = 0; index < planned.length; index++) {
    if (deps.jobDeadlineSignal?.aborted || deps.remainingJobTimeoutMs() <= 0) break;
    const startedAt = new Date().toISOString(), attemptsBefore = deps.reviewedProbeAttempts(); let snapshot, complete = false;
    try {
      const res = await deps.reviewedRequest(planned[index].url);
      const body = await readSignatureBody(res,'GET',{ timeoutMs: Math.min(1000,deps.remainingJobTimeoutMs()),signal: deps.jobDeadlineSignal });
      snapshot = projected(markerResponseSnapshot(res,body)); complete = signatureBodyComplete(res);
    } catch { snapshot = projected(markerResponseSnapshot(null)); }
    if (deps.reviewedProbeAttempts() === attemptsBefore) break;
    const health = index === 0 ? snapshot.status_code >= 200 && snapshot.status_code < 300
      && markerBaselineHealth(snapshot) === 'healthy' && complete ? 'healthy' : 'unhealthy' : 'not_applicable';
    legs.push({ ...descriptors[index], started_at: startedAt, completed_at: new Date().toISOString(),
      completion: snapshot.connection_dropped ? 'transport_error' : complete ? 'complete' : 'incomplete', health, snapshot });
    if (index === 0 && health !== 'healthy' || !complete || snapshot.connection_dropped) break;
  }
  const graded = grade(legs);
  const variants = legs.slice(1).map((leg,index) => { const classification = index === 0 ? graded.baseline : graded.transformed;
    return { label: index === 0 ? 'baseline' : 'base64_wrap', status_code: leg.snapshot.status_code || null,
      blocked: classification?.blocked ?? false, allowed: classification?.allowed ?? false, inconclusive: classification?.inconclusive ?? true,
      block_suspected: classification?.block_suspected ?? false, reason: classification?.reason ?? 'comparison_incomplete',
      denial_signature: classification?.denial_signature ?? null, sent_length: index === 0 ? applyEvasionTransform('base64_wrap','sqli').marker.length : applyEvasionTransform('base64_wrap','sqli').sent_value.length,
      actual_delivery: planned[index+1].delivery, ...(leg.completion === 'transport_error' ? { transport_error: true } : {}) }; });
  const completed = new Date().toISOString();
  return { external_result: graded.externalResult, metadata: { probe_kind: 'waf_evasion_marker_probe', profile_kind: 'waf_evasion_marker_probe',
    classifier_version: 'marker-comparison-v4', assurance_scope: 'inert_marker_rule_action_only', delivery_supported: true,
    planned_marker_legs: 2, completed_marker_legs: variants.filter((v) => !v.inconclusive && !v.transport_error).length,
    comparison_complete: graded.complete, permitted_baseline_status: legs[0]?.snapshot.status_code ?? null,
    permitted_baseline_health: legs[0]?.health ?? 'not_available', permitted_baseline: { status_code: legs[0]?.snapshot.status_code ?? null,
      health: legs[0]?.health ?? 'not_available', denial_signature: legs[0]?.snapshot.denial_signature ?? null },
    evasion_transform: 'base64_wrap', marker_class: 'sqli', baseline_blocked: graded.baseline?.blocked ?? null,
    blocked_baseline_prerequisite: graded.baseline?.blocked === true ? 'met' : 'not_met',
    evasion_bypass_suspected: graded.externalResult === 'connected', variant_results: variants,
    observation_only: graded.externalResult === 'not_run', readiness_conclusion: graded.externalResult !== 'not_run',
    ...(graded.externalResult === 'not_run' ? { not_run_reason: 'insufficient_evasion_comparison' } : {}),
    reviewed_execution: { version: 'reviewed-safe-get-observations.v1', claim_id: claim.id, grant_digest: claim.grant_digest,
      completed_at: completed, legs }, request_counting_basis: 'logical_operations' }, requests_sent: legs.length, duration_ms: deps.observedJobDurationMs() };
}
export function validateReviewedSafeObservations(value,{ job,claim,now,expected }) {
  const fail = () => ({ ok: false, error: 'reviewed_result_observations_invalid' });
  try {
    if (!reviewedGrantExact(value,['version','claim_id','grant_digest','completed_at','legs']) || !reviewedGrantJson(value)
      || value.version !== 'reviewed-safe-get-observations.v1' || value.claim_id !== claim.id || value.grant_digest !== claim.grant_digest
      || !Array.isArray(value.legs) || value.legs.length > 3 || !Number.isFinite(reviewedGrantUtc(value.completed_at))) return fail();
    let previous = Date.parse(claim.claimed_at);
    for (const [index,leg] of value.legs.entries()) {
      if (!reviewedGrantExact(leg,[...Object.keys(expected[index]),'started_at','completed_at','completion','health','snapshot'])
        || !Object.keys(expected[index]).every((k) => canonicalJsonStringify(leg[k]) === canonicalJsonStringify(expected[index][k]))
        || ![leg.started_at,leg.completed_at].every((v) => Number.isFinite(reviewedGrantUtc(v)))
        || Date.parse(leg.started_at) < previous || Date.parse(leg.completed_at) < Date.parse(leg.started_at)
        || Date.parse(leg.completed_at) >= Date.parse(job.constraints.not_after)
        || !['complete','incomplete','transport_error'].includes(leg.completion)
        || !reviewedGrantExact(leg.snapshot,['status_code','header_names','block_page_signature_id','denial_signature','connection_dropped'])
        || !Number.isInteger(leg.snapshot.status_code) || leg.snapshot.status_code < 0 || leg.snapshot.status_code > 599
        || typeof leg.snapshot.connection_dropped !== 'boolean' || !Array.isArray(leg.snapshot.header_names)
        || leg.snapshot.header_names.length > 64 || !leg.snapshot.header_names.every((v) => typeof v === 'string' && /^[a-z0-9-]{1,128}$/.test(v))
        || leg.snapshot.block_page_signature_id != null && (typeof leg.snapshot.block_page_signature_id !== 'string' || leg.snapshot.block_page_signature_id.length > 128)
        || leg.snapshot.denial_signature != null && (!reviewedGrantExact(leg.snapshot.denial_signature,['kind','id','vendor'])
          || !Object.values(leg.snapshot.denial_signature).every((v) => v === null || typeof v === 'string' && v.length <= 128))) return fail();
      const health = index === 0 ? leg.snapshot.status_code >= 200 && leg.snapshot.status_code < 300 && markerBaselineHealth(leg.snapshot) === 'healthy'
        && leg.completion === 'complete' ? 'healthy' : 'unhealthy' : 'not_applicable';
      if (leg.health !== health || index > 0 && value.legs[0].health !== 'healthy' || index > 0 && value.legs[index-1].completion !== 'complete') return fail();
      previous = Date.parse(leg.completed_at);
    }
    if (Date.parse(value.completed_at) < previous || Date.parse(value.completed_at) > Date.parse(now)
      || Date.parse(value.completed_at) >= Date.parse(job.constraints.not_after)) return fail();
    return { ok: true, legs: value.legs, ...grade(value.legs) };
  } catch { return fail(); }
}
