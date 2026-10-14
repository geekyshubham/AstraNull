/** Plain-language view model for one signed WAF/NFW probe result; unrecorded fields stay absent, never inferred. */

export const OUTCOME_META = Object.freeze({
  blocked: Object.freeze({ label: 'Blocked', tone: 'success', help: 'The edge refused the request with a response AstraNull recognises as a block.' }),
  challenged: Object.freeze({ label: 'Challenged', tone: 'warn', help: 'The edge answered with a solvable challenge (CAPTCHA or JavaScript check). A challenge is not a block.' }),
  allowed: Object.freeze({ label: 'Allowed', tone: 'danger', help: 'The request got a normal response, so nothing at the edge stopped it.' }),
  redirected: Object.freeze({ label: 'Redirected', tone: 'warn', help: 'The edge sent the request somewhere other than the baseline did, so it cannot be graded.' }),
  inconclusive: Object.freeze({ label: 'Inconclusive', tone: 'muted', help: 'The response could not be tied to a protection control, for example an error page with no block signature.' }),
  error: Object.freeze({ label: 'Error', tone: 'muted', help: 'The request failed before a response could be graded.' }),
  source_penalized: Object.freeze({ label: 'Source penalized', tone: 'warn', help: 'A harmless follow-up request from the same probe was also refused, so the edge was blocking the probe address rather than the marker. Treated as inconclusive.' }),
});

export const PLACEMENT_LABELS = Object.freeze({
  query: 'Query string',
  path: 'URL path',
  header: 'Request header',
  user_agent: 'User-Agent',
  trailing_control: 'Follow-up control',
});

// Transport facts stay neutral: whether a reachable port is a problem depends on what was declared.
export const TCP_OUTCOME_COPY = Object.freeze({
  handshake: Object.freeze({ label: 'Handshake completed', tone: 'muted', help: 'The port accepted a TCP connection from the probe.' }),
  refused_rst: Object.freeze({ label: 'Refused (TCP reset)', tone: 'muted', help: 'The host answered with a reset: the port is closed, but the host is reachable.' }),
  rejected_icmp: Object.freeze({ label: 'Rejected by firewall (ICMP)', tone: 'muted', help: 'A router or firewall sent back an ICMP rejection for this connection.' }),
  timeout: Object.freeze({ label: 'No reply', tone: 'muted', help: 'Nothing came back before the timeout. Silence can be a firewall drop, packet loss or a down host; it is not proof of a rule.' }),
  error: Object.freeze({ label: 'Probe error', tone: 'muted', help: 'The probe could not complete the attempt.' }),
});

export const UDP_OUTCOME_COPY = Object.freeze({
  validated_reply: Object.freeze({ label: 'Service replied (protocol checked)', tone: 'muted', help: 'A reply came back and matched the expected protocol, so the service is reachable.' }),
  unvalidated_reply: Object.freeze({ label: 'Reply received (not protocol-checked)', tone: 'muted', help: 'Something replied, but it did not match the expected protocol, so it proves little on its own.' }),
  port_unreachable: Object.freeze({ label: 'Port unreachable (ICMP)', tone: 'muted', help: 'The host reported that nothing listens on this port.' }),
  rejected_icmp: Object.freeze({ label: 'Rejected by firewall (ICMP)', tone: 'muted', help: 'A router or firewall sent back an ICMP rejection.' }),
  silent: Object.freeze({ label: 'No reply', tone: 'muted', help: 'Nothing came back. For UDP, silence is normal for both open and filtered ports.' }),
  error: Object.freeze({ label: 'Probe error', tone: 'muted', help: 'The probe could not complete the attempt.' }),
});

export const ICMP_KIND_COPY = Object.freeze({
  admin_prohibited: 'administratively prohibited (typically a firewall rule)',
  port_unreachable: 'port unreachable',
  host_unreachable: 'host unreachable',
  net_unreachable: 'network unreachable',
  unknown: 'unclassified ICMP message',
});

export const PARITY_COPY = Object.freeze({
  match: Object.freeze({ label: 'IPv4 and IPv6 match', tone: 'muted', help: 'Both address families behaved the same way.' }),
  mismatch: Object.freeze({ label: 'IPv4 and IPv6 differ', tone: 'warn', help: 'The two address families behaved differently. Firewall rules are often written for IPv4 only.' }),
  single_family: Object.freeze({ label: 'One address family only', tone: 'muted', help: 'Only one of IPv4 or IPv6 resolved, so parity was not compared.' }),
});

export const ENFORCEMENT_COPY = Object.freeze({
  enforced: 'Enforced: every graded placement was blocked.',
  partial: 'Partly enforced: some placements were blocked and some were not.',
  not_enforced: 'Not enforced: graded placements reached the application.',
  challenged: 'Challenged rather than blocked.',
  unknown: 'Unknown: no placement could be graded cleanly.',
});

export const ASSURANCE_SCOPE_COPY = Object.freeze({
  managed_rule_marker: Object.freeze({ label: 'Managed rule marker', help: 'A harmless string that common managed rule sets (for example SQL injection or cross-site scripting rules) recognise. It shows whether your managed rules act on that pattern.' }),
  custom_canary_rule: Object.freeze({ label: 'Custom canary rule', help: 'An AstraNull-specific token that only a rule you wrote for it will match. It proves your custom rule acts, not that the attack class is covered.' }),
  inert_marker_rule_action_only: Object.freeze({ label: 'Rule action only', help: 'Shows only that a rule acted on an inert marker; it says nothing about the attack class itself.' }),
});

const TRANSFORM_LABELS = Object.freeze({
  double_url: 'double URL encoding',
  mixed_url: 'mixed URL encoding',
  case_fold: 'case folding',
  overlong_utf8: 'overlong UTF-8',
  unicode_normalization: 'Unicode normalization',
  html_entity: 'HTML entities',
  js_escape: 'JavaScript escapes',
});

export const INCONCLUSIVE_REASON_COPY = Object.freeze({
  block_suspected_unverified_signature: 'Block suspected — vendor signature not yet verified',
  local_error: 'Inconclusive — the probe hit a local error before an answer',
  declared_signature_matches_baseline: 'Inconclusive — your declared block signature also appears on normal pages',
});

/** Server version-gap reasons; a gap removes readiness credit until the check is re-run. */
export const VERSION_GAP_COPY = Object.freeze({
  signature_corpus_version_mismatch: 'Grading rules changed — re-run to restore credit',
  grading_version_mismatch: 'Grading rules changed — re-run to restore credit',
  retest_required: 'Grading rules changed — re-run to restore credit',
  missing_signature_corpus_version: 'Grading rules not recorded — re-run to restore credit',
  missing_grading_version: 'Grading rules not recorded — re-run to restore credit',
  check_definition_changed: 'Check definition changed — re-run to restore credit',
});

export function versionGapLabel(reason) {
  const key = typeof reason === 'string' ? reason.trim() : '';
  return VERSION_GAP_COPY[key] ?? '';
}

export const PORT_RESULT_COPY = Object.freeze({
  violated: Object.freeze({ label: 'Violates your deny rule', tone: 'danger', help: 'You declared this port denied, yet it answered from outside your CDN.' }),
  no_violation_observed: Object.freeze({ label: 'No violation seen', tone: 'muted', help: 'Nothing answered in a way that breaks your rule. This is not proof the port is protected.' }),
});

export const PERSPECTIVE_UNAUTHENTICATED = 'Perspective not authenticated — result cannot prove an allowlist gap';

export const TERM_HELP = Object.freeze({
  normalization_gap: 'The plain marker was blocked but the same marker after an encoding trick (for example double URL encoding) got through. The WAF does not decode that form before matching.',
  perspective: 'The probe source location the request came from. Firewalls and allowlists can treat locations differently.',
  cache: 'The CDN cache status on the response. A cached answer may never have reached the WAF.',
  signature: 'The block page fingerprint AstraNull matched, or the header you declared as your block signature.',
  perspective_authentication: 'Only a probe source signed with its own key proves where a request came from. Without it, any probe worker could claim this location, so an allowlist result cannot be attributed to it.',
  request_budget: 'Each check has a fixed, small request limit. Declared ports beyond it are listed but not probed in this run.',
});

function text(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function record(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function list(value) {
  return Array.isArray(value) ? value : [];
}

function intOrNull(value) {
  return Number.isInteger(value) ? value : null;
}

function humanize(value) {
  const raw = text(value).replace(/[_-]+/g, ' ');
  return raw ? `${raw.charAt(0).toUpperCase()}${raw.slice(1)}` : '';
}

export function outcomeMeta(outcome) {
  return OUTCOME_META[text(outcome)] ?? { label: humanize(outcome) || 'Not recorded', tone: 'muted', help: '' };
}

function reasonLabelOf(row) {
  const reason = text(row?.inconclusive_reason);
  if (!reason) return '';
  const vendor = text(row?.matched_vendor ?? row?.suspected_vendor ?? row?.vendor);
  const label = INCONCLUSIVE_REASON_COPY[reason] ?? humanize(reason);
  return vendor && reason === 'block_suspected_unverified_signature' ? `${label} (${vendor})` : label;
}

function placementRows(rows) {
  return list(rows).map((raw) => {
    const row = record(raw) ?? {};
    const outcome = text(row.outcome);
    const meta = outcomeMeta(outcome);
    return {
      placement: text(row.placement),
      placementLabel: PLACEMENT_LABELS[text(row.placement)] ?? humanize(row.placement),
      outcome,
      outcomeLabel: meta.label,
      tone: meta.tone,
      help: meta.help,
      statusCode: intOrNull(row.status_code),
      signature: text(row.signature_id),
      cacheStatus: text(row.cache_status),
      locationChanged: row.location_changed === true,
      reasonLabel: reasonLabelOf(row),
    };
  }).filter((row) => row.placement);
}

function familyOutcome(raw, protocol) {
  const row = record(raw);
  if (!row) return null;
  const tcp = text(row.tcp_outcome);
  const udp = text(row.udp_outcome);
  const copy = protocol === 'udp' || (!tcp && udp) ? UDP_OUTCOME_COPY[udp] : TCP_OUTCOME_COPY[tcp];
  return {
    address: text(row.address),
    outcome: tcp || udp,
    label: copy?.label ?? (humanize(tcp || udp) || 'Not recorded'),
    tone: copy?.tone ?? 'muted',
    help: copy?.help ?? '',
  };
}

function icmpText(raw) {
  const icmp = record(raw);
  if (!icmp) return '';
  const kind = ICMP_KIND_COPY[text(icmp.kind)] ?? humanize(icmp.kind);
  return kind ? `ICMP ${kind}` : '';
}

function perspectiveOf(meta) {
  const perspective = record(meta.source_perspective);
  const claimedId = text(meta.claimed_perspective_id);
  const authenticated = typeof meta.perspective_authenticated === 'boolean' ? meta.perspective_authenticated : null;
  const id = text(perspective?.id) || claimedId;
  const label = text(perspective?.label) || id;
  if (!id && !label) return null;
  return { id, label, claimedId, authenticated };
}

function portList(value) {
  return [...new Set(list(value).map((port) => Number(port)).filter((port) => Number.isInteger(port) && port > 0 && port <= 65535))];
}

/** Per-port rows from probe metadata (transport outcome) merged with verdict rows (result); missing facts stay empty. */
export function portResultRows(probeRows, verdictRows = []) {
  const verdictByPort = new Map(list(verdictRows).map((raw) => record(raw)).filter(Boolean).map((row) => [`${text(row.protocol).toLowerCase() || 'tcp'}:${Number(row.port)}`, row]));
  const source = list(probeRows).length ? list(probeRows) : list(verdictRows);
  return source.map((raw) => {
    const row = record(raw) ?? {};
    const protocol = text(row.protocol).toLowerCase() || (text(row.udp_outcome) ? 'udp' : 'tcp');
    const port = Number(row.port);
    const verdictRow = verdictByPort.get(`${protocol}:${port}`) ?? (text(row.result) ? row : null);
    const outcomeKey = text(row.tcp_outcome) || text(row.udp_outcome) || text(row.outcome) || text(verdictRow?.outcome);
    const copy = protocol === 'udp' ? UDP_OUTCOME_COPY[outcomeKey] : TCP_OUTCOME_COPY[outcomeKey];
    const resultKey = text(verdictRow?.result);
    const result = PORT_RESULT_COPY[resultKey] ?? null;
    const parity = text(row.parity);
    return {
      protocol: protocol.toUpperCase(),
      port: Number.isInteger(port) ? port : null,
      outcome: outcomeKey,
      outcomeLabel: copy?.label ?? (humanize(outcomeKey) || 'Not recorded'),
      help: copy?.help ?? '',
      result: resultKey,
      resultLabel: result?.label ?? '',
      resultTone: result?.tone ?? 'muted',
      resultHelp: result?.help ?? '',
      severity: text(verdictRow?.severity),
      parity: parity ? { id: parity, ...(PARITY_COPY[parity] ?? { label: humanize(parity), tone: 'muted', help: '' }) } : null,
      icmp: icmpText(row.icmp),
    };
  }).filter((row) => row.port !== null);
}

function networkModel(meta, verdictPortResults = []) {
  const protocol = text(meta.protocol).toLowerCase() || (text(meta.udp_outcome) ? 'udp' : text(meta.tcp_outcome) ? 'tcp' : '');
  const outcomeKey = protocol === 'udp' ? text(meta.udp_outcome) : text(meta.tcp_outcome);
  const localError = meta.local_error === true;
  const copy = localError
    ? { label: 'Inconclusive — local probe error', tone: 'muted', help: 'The probe failed on its own side before any answer, so nothing is known about the target.' }
    : protocol === 'udp' ? UDP_OUTCOME_COPY[outcomeKey] : TCP_OUTCOME_COPY[outcomeKey];
  const familiesRecord = record(meta.families) ?? {};
  const families = ['ipv4', 'ipv6']
    .map((key) => ({ key, label: key === 'ipv4' ? 'IPv4' : 'IPv6', result: familyOutcome(familiesRecord[key], protocol) }))
    .filter((entry) => entry.result);
  const parity = text(meta.parity);
  const family = meta.address_family === 4 || meta.address_family === 6 ? `IPv${meta.address_family}` : '';
  return {
    protocol: protocol.toUpperCase(),
    port: intOrNull(meta.port),
    address: text(meta.address),
    family,
    outcome: outcomeKey,
    outcomeLabel: copy?.label ?? (humanize(outcomeKey) || 'Not recorded'),
    tone: copy?.tone ?? 'muted',
    help: copy?.help ?? '',
    icmp: icmpText(meta.icmp),
    serviceValidated: typeof meta.service_validated === 'boolean' ? meta.service_validated : null,
    peerIsCdn: typeof meta.peer_is_cdn === 'boolean' ? meta.peer_is_cdn : null,
    families,
    parity: parity ? { id: parity, ...(PARITY_COPY[parity] ?? { label: humanize(parity), tone: 'muted', help: '' }) } : null,
    sampleAgreement: text(meta.sample_agreement),
    sampleCount: list(meta.samples).length,
    localError,
    reflectorReachable: text(meta.exposure_basis) === 'validated_reflector_reply',
    portResults: list(meta.port_results).length > 1 || portList(meta.declared_deny_ports).length > 1 ? portResultRows(meta.port_results, verdictPortResults) : [],
    declaredDenyPorts: portList(meta.declared_deny_ports),
    unprobedDenyPorts: portList(meta.unprobed_deny_ports),
  };
}

function hasNetworkFields(meta) {
  return Boolean(text(meta.tcp_outcome) || text(meta.udp_outcome) || record(meta.families) || text(meta.parity) || meta.local_error === true || text(meta.exposure_basis) || list(meta.port_results).length);
}

/** View model for one probe result, or null when nothing WAF/NFW-specific was recorded. */
export function probeEvidenceModel(input, { verdictPortResults = [] } = {}) {
  const meta = record(input);
  if (!meta) return null;
  const placements = placementRows(meta.placements);
  const trailing = record(meta.trailing_control);
  const hasEvasion = 'normalization_gap' in meta || text(meta.reference_outcome) || text(meta.transform_outcome);
  const hasConnectionLimit = Number.isInteger(meta.attempted) && 'accepted_count' in meta;
  const hasRateLimit = 'threshold' in meta && 'window_seconds' in meta && ('first_limited_at' in meta || 'limited_outcome' in meta);
  const methodResults = list(meta.method_results).map((raw) => {
    const row = record(raw) ?? {};
    const outcome = outcomeMeta(row.outcome);
    return { method: text(row.method).toUpperCase(), outcome: text(row.outcome), outcomeLabel: outcome.label, tone: outcome.tone, statusCode: intOrNull(row.status_code) };
  }).filter((row) => row.method);
  const network = hasNetworkFields(meta) ? networkModel(meta, verdictPortResults) : null;
  const scope = text(meta.assurance_scope);
  const enforcement = text(meta.enforcement);
  const inconclusiveReason = reasonLabelOf(meta);
  const perspective = perspectiveOf(meta);
  if (!placements.length && !hasEvasion && !network && !hasConnectionLimit && !hasRateLimit && !methodResults.length && !scope && !inconclusiveReason) return null;

  const outcomes = new Set(placements.map((row) => row.outcome).filter(Boolean));
  for (const row of methodResults) if (row.outcome) outcomes.add(row.outcome);
  if (hasEvasion) for (const key of ['reference_outcome', 'transform_outcome']) if (text(meta[key])) outcomes.add(text(meta[key]));
  const chips = [...outcomes].filter((key) => OUTCOME_META[key]).map((key) => ({ id: key, ...OUTCOME_META[key] }));
  if (meta.source_penalized === true) chips.push({ id: 'source_penalized', ...OUTCOME_META.source_penalized });
  if (meta.local_error === true && !chips.some((chip) => chip.id === 'inconclusive')) chips.push({ id: 'inconclusive', ...OUTCOME_META.inconclusive });

  const metaRows = [
    text(meta.grading_version) ? { label: 'Grading', value: text(meta.grading_version) } : null,
    text(meta.signature_corpus_version) ? { label: 'Signatures', value: text(meta.signature_corpus_version) } : null,
    list(meta.leg_order).length ? { label: 'Request order', value: list(meta.leg_order).map((leg) => PLACEMENT_LABELS[text(leg)] ?? humanize(leg)).join(' → ') } : null,
    meta.cache_buster === true ? { label: 'Cache bypass', value: 'Every request carried a unique query value' } : null,
    Number.isInteger(meta.paths_skipped) && meta.paths_skipped > 0 ? { label: 'Paths skipped', value: String(meta.paths_skipped) } : null,
  ].filter(Boolean);

  return {
    chips,
    scope: scope ? { id: scope, ...(ASSURANCE_SCOPE_COPY[scope] ?? { label: humanize(scope), help: '' }) } : null,
    enforcement: enforcement ? { id: enforcement, text: ENFORCEMENT_COPY[enforcement] ?? humanize(enforcement) } : null,
    sourcePenalized: meta.source_penalized === true,
    inconclusiveReason,
    trailing: trailing ? { outcome: text(trailing.outcome), outcomeLabel: outcomeMeta(trailing.outcome).label, tone: outcomeMeta(trailing.outcome).tone, statusCode: intOrNull(trailing.status_code) } : null,
    placements,
    paths: list(meta.paths).map((raw) => text(record(raw)?.path)).filter(Boolean),
    evasion: hasEvasion ? {
      transform: TRANSFORM_LABELS[text(meta.transform ?? meta.evasion_transform)] ?? humanize(meta.transform ?? meta.evasion_transform),
      reference: text(meta.reference_outcome),
      referenceLabel: outcomeMeta(meta.reference_outcome).label,
      referenceTone: outcomeMeta(meta.reference_outcome).tone,
      transformed: text(meta.transform_outcome),
      transformedLabel: outcomeMeta(meta.transform_outcome).label,
      transformedTone: outcomeMeta(meta.transform_outcome).tone,
      normalizationGap: meta.normalization_gap === true,
      referenceNotEnforced: meta.reference_not_enforced === true,
    } : null,
    network,
    connectionLimit: hasConnectionLimit ? {
      port: intOrNull(meta.port),
      attempted: meta.attempted,
      accepted: intOrNull(meta.accepted_count),
      refusedAfter: intOrNull(meta.refused_after),
      declaredLimit: intOrNull(meta.declared_limit),
    } : null,
    rateLimit: hasRateLimit ? {
      threshold: intOrNull(meta.threshold),
      windowSeconds: intOrNull(meta.window_seconds),
      requestsSent: intOrNull(meta.requests_sent),
      firstLimitedAt: intOrNull(meta.first_limited_at),
      limitedOutcome: text(meta.limited_outcome),
      limitedLabel: text(meta.limited_outcome) ? outcomeMeta(meta.limited_outcome).label : '',
    } : null,
    methodResults,
    perspective,
    metaRows,
  };
}

/** Signed probe results inside a run's event list, newest last. */
export function probeResultEvents(events) {
  return list(events)
    .filter((event) => text(record(event)?.signal_type) === 'probe_result' && ['signed_probe', 'internal_simulation'].includes(text(record(event)?.producer_kind)))
    .sort((left, right) => text(left.timestamp).localeCompare(text(right.timestamp)));
}

/** One sentence for a network outcome, e.g. "TCP 22 over IPv4: Handshake completed". */
export function networkOutcomeSentence(network) {
  if (!network) return '';
  const where = [network.protocol, network.port !== null ? String(network.port) : ''].filter(Boolean).join(' ');
  const family = network.family ? ` over ${network.family}` : '';
  return `${where || 'Connection'}${family}: ${network.outcomeLabel}${network.icmp ? ` (${network.icmp})` : ''}`;
}

const EXPOSED_VERDICTS = new Set(['exposed', 'edge_exposed']);

/** Check-aware wording for an exposed verdict, so a WAF or firewall result never reads as "direct server access". */
export function exposedVerdictLabel(checkId, outcome) {
  if (!EXPOSED_VERDICTS.has(text(outcome).toLowerCase())) return '';
  const id = text(checkId);
  if (id === 'nfw.origin_lockdown.safe') return 'Your origin answered directly, outside the CDN';
  if (id.startsWith('reflect.') || id.includes('amplification')) return 'An open reflector is reachable from the internet';
  if (id.startsWith('nfw.') || id.startsWith('l3.')) return 'A declared firewall rule was not enforced';
  if (id.startsWith('waf.')) return 'The WAF did not stop the test traffic';
  return '';
}
