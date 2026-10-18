import { pinnedFetch, resolvePinnedDestination } from './pinnedHttpRequest.mjs';
import { startProbeIoAttempt } from './probeAttempt.mjs';
import { readSignatureBody, signatureBodyComplete } from './outsideInWafScanner.mjs';
import { CANARY_ECHO_RESPONSE_HEADER, CANARY_NONCE_REQUEST_HEADER, classifyDirectOriginObservation,
  matchControlDenialSignature } from './externalObservationOutcomes.mjs';
import { signedOriginIdentityPair, originIdentityContentSupport, originIdentityBodyIsGeneric } from './originIdentityPair.mjs';

/** One shared nonce/worker, two authorized requests; there is no redirect/retry/asset expansion. */
export async function probeOriginIdentityPair(job, deps = {}) {
  const started = Date.now();
  deps = { ...deps, destinationPolicy: { allowPrivate: false, allowLoopback: false } };
  const pair = signedOriginIdentityPair(job);
  let attempts = 0;
  const finish = (metadata, external = 'error') => ({ external_result: external, requests_sent: attempts,
    duration_ms: Date.now() - started, metadata: { profile_kind: 'origin_identity_pair', probe_kind: 'origin_identity_pair',
      scenario_version: pair?.version ?? job.probe_profile?.scenario_version,
      observation_only: true, readiness_conclusion: false, evidence_tier: 'E2',
      planned_requests: 2, completed_requests: attempts, comparison_complete: false,
      ...metadata } });
  if (!pair || typeof job.nonce !== 'string' || !job.nonce) return finish({ error_class: 'invalid_signed_origin_identity_pair' });
  const remaining = () => Math.max(0, Math.min(5000 - (Date.now() - started), deps.remainingJobTimeoutMs?.() ?? 5000));
  const scope = { host: pair.host, path: pair.path, port: pair.port, method: pair.method,
    scenario_version: pair.version, source_perspective: deps.sourcePerspective ?? 'astranull-signed-public-worker',
    worker_id: deps.workerId ?? job.leased_by ?? job.worker_id ?? null };
  const url = `${pair.scheme}://${pair.host}:${pair.port}${pair.path}`;
  let baselineDestination;
  try {
    // Production worker preflights BOTH endpoints before either request and hands off this exact set.
    const resolverDeps = { ...deps };
    delete resolverDeps.vettedHost;
    delete resolverDeps.vettedAddresses;
    baselineDestination = deps.pairedBaselineDestination ?? await resolvePinnedDestination(pair.host, resolverDeps);
  } catch (error) { return finish({ error_class: error.code ?? 'paired_baseline_destination_failed' }); }
  if (baselineDestination.host !== pair.host || !baselineDestination.addresses?.length) return finish({ error_class: 'invalid_paired_baseline_destination' });

  const request = async (addresses, phase) => {
    let response = null;
    let bodyText = '';
    let bodyComplete = pair.method === 'HEAD';
    let error = null;
    const controller = new AbortController();
    const abort = () => controller.abort();
    const timer = setTimeout(abort, Math.max(1, remaining()));
    deps.jobDeadlineSignal?.addEventListener('abort', abort, { once: true });
    try {
      if (remaining() <= 0 || deps.jobDeadlineSignal?.aborted) throw Object.assign(new Error('Probe stopped'), { code: 'probe_job_deadline_exceeded' });
      response = await startProbeIoAttempt(deps, 'http_request', () => pinnedFetch(url, {
        method: pair.method, redirect: 'manual', signal: controller.signal, timeoutMs: remaining(),
        headers: { Host: pair.port === (pair.scheme === 'https' ? 443 : 80) ? pair.host : `${pair.host}:${pair.port}`,
          [CANARY_NONCE_REQUEST_HEADER]: job.nonce }, activity_phase: phase,
      }, { ...deps, vettedHost: pair.host, vettedAddresses: addresses }), () => { attempts += 1; });
      if (pair.method === 'GET') {
        bodyText = await readSignatureBody(response, 'GET', { timeoutMs: remaining(), signal: controller.signal });
        bodyComplete = signatureBodyComplete(response);
      } else {
        await response.body?.cancel?.();
      }
      if (controller.signal.aborted || deps.jobDeadlineSignal?.aborted) throw Object.assign(new Error('Probe stopped'), { code: 'probe_job_deadline_exceeded' });
    } catch (caught) { error = caught; }
    finally { clearTimeout(timer); deps.jobDeadlineSignal?.removeEventListener('abort', abort); }
    return { response, body_text: bodyText, body_complete: bodyComplete, error, observed_at: new Date().toISOString() };
  };

  const baselineLeg = await request(baselineDestination.addresses, 'protected_baseline');
  const eligible = (leg) => !leg.error && leg.response?.status >= 200 && leg.response.status < 300
    && (pair.method === 'HEAD' || (leg.body_complete && !originIdentityBodyIsGeneric(leg.body_text)));
  const baseline = { status_code: baselineLeg.response?.status ?? null,
    ...(baselineLeg.error ? { error_class: baselineLeg.error.code ?? 'request_failed' } : {}),
    denial_signature: matchControlDenialSignature({ statusCode: baselineLeg.response?.status,
      headers: baselineLeg.response, bodyText: baselineLeg.body_text, bodyComplete: baselineLeg.body_complete }),
    application_identity: { confirmed: eligible(baselineLeg) && baselineLeg.response?.headers?.get(CANARY_ECHO_RESPONSE_HEADER) === job.nonce,
      method: 'nonce_canary' }, canary_echo: eligible(baselineLeg) ? baselineLeg.response?.headers?.get(CANARY_ECHO_RESPONSE_HEADER) : null,
    scope, observed_at: baselineLeg.observed_at };
  const baselineMetadata = { status_code: baseline.status_code, application_identity: baseline.application_identity,
    scope, observed_at: baseline.observed_at, body_complete: baselineLeg.body_complete,
    tls: baselineLeg.response?.tls ?? null, denial_signature: baseline.denial_signature };
  if (baselineLeg.error || remaining() <= 0 || deps.jobDeadlineSignal?.aborted) return finish({
    error_class: baselineLeg.error?.code ?? 'probe_job_deadline_exceeded', permitted_baseline: baselineMetadata,
    incomplete_reason: 'baseline_failed_or_stopped_before_direct' });

  const directLeg = await request([pair.address], 'bound_direct');
  const observation = classifyDirectOriginObservation({ attempted: true, response: directLeg.response,
    error: directLeg.error, bodyText: directLeg.body_text, bodyComplete: directLeg.body_complete,
    baseline, expectedNonce: eligible(directLeg) ? job.nonce : null,
    // Static marker and content/certificate similarity never become nonce proof.
    expectedMarker: null, declaredLockdown: null, directAddress: pair.address,
    scope, observedAt: directLeg.observed_at });
  const support = originIdentityContentSupport(baselineLeg, directLeg);
  if (observation.outcome === 'not_applicable' || !eligible(baselineLeg) || !eligible(directLeg)) {
    support.suspected_application_association = false;
    support.supporting_signals = [];
  }
  const complete = !directLeg.error && attempts === 2 && !deps.jobDeadlineSignal?.aborted;
  // This scenario reports application identity only, never positive denial/readiness.
  observation.readiness_conclusion = false;
  observation.observation_only = true;
  observation.origin_lockdown_confirmed = false;
  return finish({ permitted_baseline: baselineMetadata, origin_observation: observation,
    observation_outcome: observation.outcome, application_bypass_confirmed: observation.application_bypass_confirmed,
    application_bypass_suspected: observation.application_bypass_suspected,
    direct_application_path_confirmed: observation.application_bypass_confirmed,
    content_support: support, direct_tls: directLeg.response?.tls ?? null,
    binding_id: pair.binding_id, comparison_id: pair.comparison_id, scope_digest: pair.scope_digest,
    protected_target_id: pair.protected_target.id, direct_ip: pair.address,
    comparison_complete: complete, observation_complete: complete,
    limitations: ['identity_comparison_not_a_waf_rule_bypass_test', 'no_positive_origin_lockdown_assurance',
      'no_ddos_capacity_assurance', 'single_baseline_stability_not_established'] },
  directLeg.error ? 'error' : observation.response_observed ? 'connected' : 'inconclusive');
}
