import { originObservation, originObservationLabel } from './origin-observation.mjs';
import type { DataItem } from './types';
// @ts-ignore Plain ESM keeps terminology directly testable with node:test.
import { plainVerdictLabel } from './plain-language.mjs';

export type VerdictExplanationField = { label: string; value: string };

function getString(item: DataItem | null | undefined, keys: string[], fallback = '') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function getNestedString(item: DataItem | null | undefined, path: string[], fallback = '') {
  let current: unknown = item;
  for (const key of path) {
    if (!current || typeof current !== 'object' || Array.isArray(current)) return fallback;
    current = (current as DataItem)[key];
  }
  if (current !== undefined && current !== null && current !== '') return String(current);
  return fallback;
}

export function isSignedProbeEvidenceEvent(event: DataItem) {
  return getString(event, ['signal_type']) === 'probe_result'
    && getString(event, ['producer_kind']) === 'signed_probe';
}

const KNOWN_REMEDIATION_TEMPLATE_KEYS = new Set(['waf_posture_remediation']);

function parseFindingReasonCodes(finding: DataItem | null | undefined) {
  const notes = getString(finding, ['notes'], '');
  const match = notes.match(/(?:Reason codes|reason_codes):\s*([^.;]+)/i);
  if (!match) return [];
  return match[1]
    .split(',')
    .map((code) => code.trim())
    .filter((code) => code && code !== 'none');
}

function parseFindingPostureStatus(finding: DataItem | null | undefined) {
  const title = getString(finding, ['title'], '');
  const titleMatch = title.match(/WAF posture\s+(\w+)/i);
  if (titleMatch) return titleMatch[1].toLowerCase();
  const notes = getString(finding, ['notes'], '');
  const notesMatch = notes.match(/Posture status:\s*(\w+)/i);
  if (notesMatch) return notesMatch[1].toLowerCase();
  return '';
}

function probeEventsHaveError(probeEvents: DataItem[]) {
  return probeEvents.some((event) => {
    const meta = (event.metadata as DataItem | undefined) ?? {};
    const externalResult = String(event.external_result ?? meta.external_result ?? '').toLowerCase();
    return externalResult === 'error' || externalResult === 'failed' || externalResult === 'timeout';
  });
}

function resolveWafPostureRemediation(context: {
  finding?: DataItem | null;
  detail?: DataItem | null;
  events?: DataItem[];
}) {
  const reasonCodes = parseFindingReasonCodes(context.finding);
  const postureStatus = parseFindingPostureStatus(context.finding);
  const probeEvents = (context.events ?? []).filter(isSignedProbeEvidenceEvent);
  const steps: string[] = [];

  if (reasonCodes.includes('origin_bypass_confirmed')) {
    steps.push('Restrict origin access to WAF/CDN egress only and enable authenticated origin pull where supported.');
  }
  if (reasonCodes.includes('marker_rule_not_blocking')) {
    steps.push('Review WAF rule mode and ensure marker or managed rules are in blocking mode.');
  }
  if (reasonCodes.includes('monitor_only_behavior')) {
    steps.push('Move affected WAF rules from monitor or log-only to blocking mode after staging validation.');
  }
  if (postureStatus === 'unprotected') {
    steps.push('Enable WAF coverage for the declared asset and validate with a safe marker retest.');
  }
  if (probeEventsHaveError(probeEvents)) {
    steps.push('Verify the declared URL is reachable from external probes.');
  }

  if (steps.length) {
    return `${[...new Set(steps)].join(' ')} Retest with a safe WAF validation after changes.`;
  }
  return 'Review WAF posture findings, apply vendor-aware remediation, and retest with a safe marker validation.';
}

export function resolveRemediationTemplate(
  template: string,
  context: {
    finding?: DataItem | null;
    detail?: DataItem | null;
    events?: DataItem[];
  } = {},
) {
  const trimmed = template.trim();
  if (!trimmed) return '';
  if (!KNOWN_REMEDIATION_TEMPLATE_KEYS.has(trimmed)) return trimmed;
  if (trimmed === 'waf_posture_remediation') return resolveWafPostureRemediation(context);
  return trimmed;
}

export function summarizeExternalProbeEvidence(probeEvents: DataItem[]) {
  const trustedProbeEvents = probeEvents.filter(isSignedProbeEvidenceEvent);
  if (!trustedProbeEvents.length) {
    return 'No signed probe_result events recorded for this run yet; external probe evidence is missing or limited.';
  }
  return trustedProbeEvents
    .map((event) => {
      const parts: string[] = [];
      if (event.timestamp) parts.push(String(event.timestamp));
      if (event.source) parts.push(`source ${String(event.source)}`);
      const meta = (event.metadata as DataItem | undefined) ?? {};
      const externalResult = event.external_result ?? meta.external_result;
      if (externalResult) parts.push(`external_result ${String(externalResult)}`);
      if (meta.probe_profile_kind) parts.push(`profile ${String(meta.probe_profile_kind)}`);
      const observation = originObservation(meta);
      if (observation) parts.push(originObservationLabel(meta));
      const signature = getNestedString(observation, ['denial_signature', 'id']);
      if (signature) parts.push(`denial signature ${signature}`);
      if (meta.simulation) parts.push(String(meta.simulation));
      if (meta.note) parts.push(String(meta.note));
      return parts.length ? parts.join(' · ') : getString(event, ['signal_type'], 'probe_result');
    })
    .join('; ');
}

export function buildVerdictExplanationFields(
  detail: DataItem | null,
  events: DataItem[],
  options: { remediationTemplate?: string; finding?: DataItem | null } = {}
): VerdictExplanationField[] {
  if (!detail?.verdict || typeof detail.verdict !== 'object') return [];

  const probeEvents = events.filter(isSignedProbeEvidenceEvent);

  const verdict = detail.verdict as DataItem;
  const rawRemediation = options.remediationTemplate ?? getString(detail, ['remediation_template'], '');
  const remediationRef = resolveRemediationTemplate(rawRemediation, {
    finding: options.finding,
    detail,
    events,
  });
  const technicalVerdict = getString(verdict, ['verdict'], '—');
  const conclusion = `${plainVerdictLabel(technicalVerdict)} (technical verdict: ${technicalVerdict}) · confidence ${getString(verdict, ['confidence'], '—')}. ${getString(verdict, ['explanation'], '')}`.trim();

  return [
    { label: 'External probe evidence', value: summarizeExternalProbeEvidence(probeEvents) },
    { label: 'Conclusion', value: conclusion },
    {
      label: 'Remediation',
      value: remediationRef || 'No remediation template recorded for this run.',
    },
  ];
}

export function normalizeVerdictKey(verdict: string) {
  return verdict;
}

export function trafficHopState(hop: string, verdict?: string) {
  if (!verdict) return hop === 'probe' ? 'ok' : 'muted';
  if (verdict === 'protected') {
    if (hop === 'probe' || hop === 'edge') return 'ok';
    return 'muted';
  }
  if (verdict === 'bypassable' || verdict === 'penetrated') {
    if (hop === 'probe') return 'ok';
    if (hop === 'origin') return 'danger';
    return 'warn';
  }
  return 'warn';
}

export const TRUTH_TABLE_ROWS: Array<{ key: string; description: string }> = [
  { key: 'protected', description: 'Blocked before origin by external probe evidence.' },
  { key: 'bypassable', description: 'Edge did not stop traffic; the external probe reached the origin.' },
  { key: 'penetrated', description: 'Protection failed; unwanted reach confirmed by external probe evidence.' },
];
