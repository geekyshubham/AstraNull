/** Passive qualification of immutable firewall comparisons from accepted execution records. */
import { canonicalJsonStringify } from './custody.mjs';
import {
  assessFreshness, firewallBaselineCaptureDigest, normalizeEvidenceReference, verifyBaselineDigest,
} from '../contracts/protectionValidation.mjs';
import {
  buildFirewallBaselineEntry, evaluateFirewallChange, firewallObservationsDigest,
  firewallSampleFromProbeEvent, FIREWALL_ACCEPTANCE_CLASSIFIER_VERSION,
} from './firewallChangeAcceptance.mjs';
import { probeExecutionReceipt, probeExecutionEvidenceReceipt } from './probeExecution.mjs';
import { validateSafetyAttestation } from './probeResultValidation.mjs';
import { probeSourceResolverFromEnv } from './probeSourcePerspective.mjs';

const list = (value) => Array.isArray(value) ? value : [];
const time = (value) => value == null ? NaN : new Date(value).getTime();
const metadataOf = (event) => event?.metadata ?? event?.metadata_json ?? {};
const sameReferences = (left, right) => canonicalJsonStringify(list(left).map(normalizeEvidenceReference))
  === canonicalJsonStringify(list(right).map(normalizeEvidenceReference));

export function firewallBaselineFor(evaluation, evidenceInputs) {
  return list(evidenceInputs?.baselines).find((row) => row.id === evaluation?.baseline_id
    && row.tenant_id === evaluation?.tenant_id && row.kind === 'firewall_change') ?? null;
}

export function firewallRequiredReferences(item, evaluation, evidenceInputs) {
  const entry = firewallBaselineFor(evaluation, evidenceInputs)?.entries
    ?.find((row) => row.expectation_id === item?.expectation_id);
  return [...list(entry?.references), ...list(item?.evidence_refs)];
}

/** A retained signed-producer label is not an accepted execution receipt. No current signing secret is needed to read history. */
export function firewallExecutionProofGap({ event, run, job, ref, cutoff }) {
  const metadata = metadataOf(event);
  if (!job || job.tenant_id !== run.tenant_id || job.test_run_id !== run.id
    || job.target_id !== run.target_id || job.check_id !== run.check_id
    || metadata.probe_job_id !== job.id || !/^[a-f0-9]{64}$/.test(job.job_signature ?? '')
    || job.status !== 'completed' || job.nonce_hash !== event.nonce_hash
    || !metadata.probe_worker_id || metadata.probe_worker_id !== ref.worker_id
    || job.leased_by !== metadata.probe_worker_id
    || !Number.isFinite(time(job.created_at)) || !Number.isFinite(time(job.completed_at))
    || time(job.created_at) > time(event.timestamp) || time(job.completed_at) < time(event.timestamp)
    || time(job.completed_at) > cutoff || time(job.created_at) > cutoff) return 'accepted_execution_binding_missing';
  if (!Number.isFinite(time(job.leased_at))) return 'accepted_execution_binding_missing';
  // jsonb_agg serializes timestamptz with +00:00, whereas ingestion maps it to ISO Z.
  // Canonicalize this database column only; never rewrite signed JSON authority fields.
  const normalized = { ...job, leased_at: new Date(job.leased_at).toISOString(),
    constraints: job.constraints ?? job.constraints_json,
    worker_metadata: job.worker_metadata ?? job.worker_metadata_json,
    target: job.target ?? job.target_descriptor_json };
  if (normalized.probe_profile?.kind !== metadata.profile_kind
    || metadata.external_result !== run.probe_external_result) return 'accepted_execution_result_mismatch';
  const attestation = metadata.safety_attestation;
  const receipt = metadata.execution_receipt;
  if (receipt?.version !== 'accepted-probe-execution.v1'
    || receipt.digest !== probeExecutionEvidenceReceipt(normalized, metadata.probe_worker_id,
      attestation, metadata.external_result).digest) return 'accepted_execution_receipt_mismatch';
  const reserved = normalized.worker_metadata?.execution_reservation;
  // This projection verifies a previously accepted, completed job against its original lease;
  // it does not reopen that lease, refund its allowance, or authorize another attempt.
  if (!reserved?.id || reserved.state !== 'reserved_unknown' || normalized.constraints?.execution_attempts !== 1
    || time(reserved.reserved_at) < time(job.leased_at) || time(reserved.reserved_at) > time(event.timestamp)
    || probeExecutionReceipt({ ...normalized, status: 'leased' }, metadata.probe_worker_id,
      attestation, metadata.external_result).error) return 'accepted_execution_reservation_missing';
  const validated = validateSafetyAttestation({ external_result: metadata.external_result, safety_attestation: attestation },
    normalized.constraints, { probeKind: normalized.probe_profile?.kind,
      probeProfile: normalized.probe_profile, target: normalized.target });
  if (!validated.ok || !Number.isSafeInteger(attestation?.probe_requests_sent) || attestation.probe_requests_sent <= 0
    || time(reserved.reserved_at) + attestation.duration_ms > time(reserved.not_after)) return 'accepted_execution_accounting_invalid';
  return null;
}

export function firewallComparisonProofGap({ item, evaluation, expectation, proofContext, verifyReference,
  resolveSourcePerspective = probeSourceResolverFromEnv() }) {
  const { tenantId, evidenceInputs, targets, now } = proofContext;
  const baseline = firewallBaselineFor(evaluation, evidenceInputs);
  if (!baseline) return 'actual_firewall_comparison_unverified';
  try {
    if (baseline.immutable !== true || baseline.baseline_digest !== evaluation.baseline_digest
      || firewallBaselineCaptureDigest(baseline) !== baseline.baseline_digest
      || list(baseline.entries).length !== baseline.entry_count
      || !Number.isFinite(time(baseline.created_at)) || time(baseline.created_at) > time(now)
      || !Number.isFinite(time(baseline.captured_at)) || time(baseline.captured_at) > time(evaluation.evaluated_at)
      || !baseline.entries.every(verifyBaselineDigest)) return 'actual_firewall_baseline_unverified';
    const entry = baseline.entries.find((row) => row.expectation_id === item.expectation_id);
    if (!entry || !expectation || expectation.tenant_id !== tenantId
      || expectation.change_id !== baseline.change_id || entry.expectation_digest !== expectation.digest
      || entry.expectation_version !== expectation.expectation_version
      || entry.classifier_version !== FIREWALL_ACCEPTANCE_CLASSIFIER_VERSION) return 'actual_firewall_expectation_mismatch';
    const cutoff = time(now);
    const samplesFor = (refs, side) => {
      const samples = [];
      const eventIds = new Set();
      const runIds = new Set();
      for (const ref of refs) {
        const gap = verifyReference(ref, { ...proofContext, observationPermitted: true });
        if (gap) return { gap };
        const run = evidenceInputs.runs.find((row) => row.id === ref.test_run_id && row.tenant_id === tenantId);
        runIds.add(run.id);
        for (const id of ref.evidence_ids) {
          const vault = list(evidenceInputs.evidenceItems).find((row) => row.id === id
            && row.tenant_id === tenantId && row.test_run_id === run.id);
          const event = evidenceInputs.events.find((row) => row.id === (vault?.related_event_id ?? id)
            && row.tenant_id === tenantId && row.test_run_id === run.id);
          if (!event || eventIds.has(event.id)) return { gap: 'actual_firewall_sample_binding_mismatch' };
          eventIds.add(event.id);
          const metadata = metadataOf(event);
          const finiteObservation = metadata.observation_complete === true
            && ['tcp_connect', 'udp_probe', 'port_scan_bounded', 'host_sni_bypass', 'tls_audit'].includes(metadata.profile_kind);
          if (['complete', 'evidence_complete', 'capture_complete', 'observation_complete']
            .some((key) => metadata[key] === false)
            || (metadata.comparison_complete === false && !finiteObservation)) return { gap: 'actual_firewall_sample_incomplete' };
          const source = resolveSourcePerspective(metadata.probe_worker_id);
          if (!source || source !== ref.source_perspective || source !== expectation.source_perspective) {
            return { gap: 'actual_firewall_source_unverified' };
          }
          const job = list(evidenceInputs.jobs).find((row) => row.id === metadata.probe_job_id);
          const receiptGap = firewallExecutionProofGap({ event, run, job, ref, cutoff });
          if (receiptGap) return { gap: receiptGap };
          if (!assessFreshness(event.timestamp, entry.freshness_window_seconds, now).fresh) return { gap: 'actual_firewall_sample_expired' };
          if ((side === 'pre' && time(event.timestamp) > time(baseline.captured_at))
            || (side === 'post' && time(event.timestamp) <= time(baseline.captured_at))
            || time(event.timestamp) > time(evaluation.evaluated_at)) return { gap: 'actual_firewall_sample_time_mismatch' };
          const target = targets.find((row) => row.id === ref.target_id && row.tenant_id === tenantId);
          samples.push(firewallSampleFromProbeEvent({ event: { ...event, metadata }, run, target,
            verdictId: ref.verdict_id, sourcePerspective: source }));
        }
      }
      if (!samples.length || evidenceInputs.events.some((event) => event.tenant_id === tenantId
        && runIds.has(event.test_run_id) && event.signal_type === 'probe_result' && !eventIds.has(event.id))) {
        return { gap: 'actual_firewall_sample_set_incomplete' };
      }
      return { samples };
    };
    const pre = samplesFor(entry.references, 'pre');
    if (pre.gap) return pre.gap;
    const post = samplesFor(item.evidence_refs, 'post');
    if (post.gap) return post.gap;
    const rebuilt = buildFirewallBaselineEntry({ tenantId, expectationId: expectation.id, expectation,
      samples: pre.samples, freshnessWindowSeconds: entry.freshness_window_seconds });
    if (rebuilt.entry.baseline_digest !== entry.baseline_digest
      || firewallObservationsDigest(rebuilt.observations) !== entry.observations_digest) return 'actual_firewall_baseline_observation_mismatch';
    const actualEntry = { ...entry, observations: rebuilt.observations };
    const actual = evaluateFirewallChange({ tenantId, baseline: { ...baseline, entries: [actualEntry] },
      expectations: { [expectation.id]: expectation }, candidateSamples: post.samples,
      evaluatedAt: evaluation.evaluated_at, now }).evaluation.items[0];
    if (!sameReferences(actual.evidence_refs, item.evidence_refs)
      || ['status', 'gap_kind', 'expectation_met', 'pre_state', 'post_state'].some((key) => actual[key] !== item[key])
      || canonicalJsonStringify(actual.compatibility_reasons) !== canonicalJsonStringify(item.compatibility_reasons)
      || canonicalJsonStringify(actual.reasons) !== canonicalJsonStringify(item.reasons)) return 'actual_firewall_outcome_mismatch';
    return null;
  } catch { return 'actual_firewall_comparison_unverified'; }
}
