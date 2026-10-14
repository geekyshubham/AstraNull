import { externalObservationLabel, originObservationOf } from './externalObservationOutcomes.mjs';

/** Explain an inconclusive attempt without upgrading it to a protection claim. */
export function inconclusiveReason({ probeKind, externalResult, metadata = {} } = {}) {
  const originOutcome = probeKind === 'host_sni_bypass' ? originObservationOf(metadata)?.outcome : null;
  if (originOutcome === 'no_response' || originOutcome === 'transport_error') {
    return {
      reason: originOutcome === 'no_response' ? 'origin_no_response' : 'origin_transport_error',
      label: externalObservationLabel(originOutcome),
      next_step: 'Confirm the declared origin binding, then rerun the current check version. Only an explicit denial or an observed response can support a direct-origin conclusion.',
      explanation: originOutcome === 'no_response'
        ? 'The direct-origin request received no response within its safe time limit. Silence cannot establish origin lockdown or identify the responsible control.'
        : 'The direct-origin request ended in a transport error such as a refusal, unreachable host, or TLS failure. That cannot establish origin lockdown or identify the responsible control.',
    };
  }
  if (['waf_evasion_marker_probe', 'waf_inspection_limit_probe'].includes(probeKind)
    && externalResult === 'not_run') {
    return {
      reason: 'baseline_comparison_unavailable',
      label: 'Blocking comparison unavailable',
      next_step: 'Review the baseline marker evidence and configure a rule that blocks that harmless marker, then rerun the comparison.',
      explanation: metadata.baseline_blocked === false
        ? 'The baseline harmless marker was allowed. Requests were sent, but evasion or inspection-limit resistance cannot be assessed without a blocked baseline.'
        : 'A complete blocked-baseline comparison was not recorded. Evasion or inspection-limit resistance remains unassessed.',
    };
  }
  if (
    metadata.inconclusive_reason === 'required_input_missing'
    || metadata.error_class === 'required_input_missing'
    || metadata.explanation_reason === 'required_input_missing'
  ) {
    return {
      reason: 'required_input_missing',
      label: 'Required input missing',
      next_step: 'Declare the required port, policy rule, or origin binding on the target before rerunning it.',
      explanation: metadata.missing_message || metadata.explanation || 'Required input is missing for this check; no traffic was sent.',
    };
  }
  if (['unsupported_target', 'resolver_not_routable', 'missing_webhook_url'].includes(metadata.error_class)) {
    return {
      reason: 'endpoint_setup_required', label: 'Endpoint details required',
      next_step: 'Declare the service endpoint, port, or resolver required by this check before rerunning it.',
      explanation: 'The declared target lacks the endpoint details required by this probe; no protection conclusion was produced.',
    };
  }
  if (externalResult === 'timeout') {
    return {
      reason: 'probe_timeout', label: 'No response within the safe time limit',
      next_step: 'Review the recorded destination and transport. Rerun only against a declared endpoint that serves this protocol; silence alone does not prove blocking.',
      explanation: 'The probe received no definitive response within its safe time limit. A timeout cannot establish protection or exposure; it cannot distinguish filtering from an unavailable service.',
    };
  }
  return {
    reason: 'probe_incomplete', label: 'Probe could not establish a result',
    next_step: 'Review this check’s recorded evidence and execution error before rerunning it.',
    explanation: 'The probe did not establish sufficient external evidence and cannot establish protection or exposure. Review the recorded execution error or incomplete result.',
  };
}
