// Family copy only; every proof fact comes from the recorded model passed in.

const PASS = new Set(['pass', 'passed', 'protected', 'blocked', 'block_at_edge', 'allowed_as_expected', 'edge_protected']);
const GAP = new Set(['fail', 'failed', 'gap', 'allowed', 'exposed', 'bypassable', 'penetrated', 'unprotected', 'edge_exposed']);
const NOT_RUN = new Set(['', 'not_run', 'not_recorded', 'not_checked', 'pending', 'planned']);

const FAMILY_BY_KEY = Object.freeze({
  origin: 'origin',
  waf: 'waf',
  dns: 'dns',
  l3: 'network',
  l4: 'network',
  l3_l4: 'network',
  network: 'network',
  nfw: 'network',
  tls: 'tls',
  protocol: 'tls',
  l7: 'l7',
  path: 'l7',
  pattern: 'l7',
  exploit: 'l7',
  reflection: 'reflection',
  amplification: 'reflection',
  ops: 'operations',
  operations: 'operations',
});

const FAMILY_COPY = Object.freeze({
  origin: {
    tested: 'Whether the servers behind this host answer requests sent straight to them, skipping your CDN or WAF.',
    gap: 'Your origin server answered requests that skipped your CDN or WAF.',
    pass: 'Your origin server did not answer requests that skipped your CDN or WAF.',
    why: 'Anyone who finds the origin address can send attack traffic straight to it and bypass your DDoS protection.',
    fix: ['Allow inbound web traffic only from your CDN or WAF provider’s address ranges.', 'If the origin address has been public, move the origin to a new address.'],
  },
  waf: {
    tested: 'Whether your web application firewall blocks a harmless request shaped like an attack.',
    gap: 'A request your WAF should have blocked reached the application.',
    pass: 'Your WAF blocked the test request before it reached the application.',
    why: 'Attack traffic that passes the WAF lands on your application, where it can exhaust or exploit it.',
    fix: ['Turn on blocking mode for the matching WAF rule group.', 'Re-test after the rule change to confirm it blocks.'],
  },
  dns: {
    tested: 'How your DNS servers answer queries an attacker could abuse.',
    gap: 'Your DNS answered in a way attackers can abuse.',
    pass: 'Your DNS handled the test queries safely.',
    why: 'Weak DNS can be flooded or used to amplify attacks, taking every service on the domain offline.',
    fix: ['Use at least two DNS providers or anycast nameservers.', 'Disable open recursion and public zone transfers.'],
  },
  network: {
    tested: 'Which network ports and protocols answer from the internet.',
    gap: 'A network port or protocol that should be closed answered from the internet.',
    pass: 'The network paths that should be closed did not answer.',
    why: 'Every open port is another way in for floods that bypass your web protections.',
    fix: ['Close or firewall ports that do not need public access.', 'Restrict management services to known source addresses.'],
  },
  tls: {
    tested: 'How your servers negotiate TLS and HTTP protocol features.',
    gap: 'Your servers accept a protocol setting that makes them easier to overload.',
    pass: 'Your servers negotiated protocols safely.',
    why: 'Expensive handshakes and protocol features let small attacks consume large server resources.',
    fix: ['Disable outdated TLS versions and costly protocol options.', 'Let your CDN terminate TLS where possible.'],
  },
  l7: {
    tested: 'How your application responds to request patterns used in application-layer floods.',
    gap: 'Your application accepted a request pattern used in application-layer floods.',
    pass: 'Your application limited or rejected the test request pattern.',
    why: 'Application-layer floods look like real users and can exhaust servers with little traffic.',
    fix: ['Add rate limits on the affected paths.', 'Enable bot or challenge protection at your edge.'],
  },
  reflection: {
    tested: 'Whether your services can be abused to reflect or amplify traffic toward others.',
    gap: 'A service on this host answered with more data than it received.',
    pass: 'No reflection or amplification response was observed.',
    why: 'Amplifying services are used to flood victims and can get your addresses blocked.',
    fix: ['Disable or firewall the responding UDP service.', 'Apply response rate limiting where the service must stay public.'],
  },
  operations: {
    tested: 'Whether your alerts, runbooks and stop controls are ready for an attack.',
    gap: 'A step your team needs to respond to an attack is missing or failed.',
    pass: 'The response readiness step was confirmed.',
    why: 'Without tested alerts and runbooks, an attack lasts longer and costs more.',
    fix: ['Complete the missing runbook or alert step.', 'Run a drill and record the result.'],
  },
});

const KICKER = Object.freeze({
  gap: 'Gap confirmed',
  pass: 'Passed',
  review: 'Needs review',
  not_tested: 'Not tested',
});

/** @param {unknown} value */
function text(value) {
  return typeof value === 'string' ? value.trim() : '';
}

/**
 * Story family for a check, from its catalog vector family or its check id prefix.
 * @param {string} checkId
 * @param {string} [vectorFamily]
 */
export function storyFamily(checkId, vectorFamily = '') {
  const family = FAMILY_BY_KEY[text(vectorFamily).toLowerCase()];
  if (family) return family;
  const prefix = text(checkId).toLowerCase().split('.')[0] ?? '';
  return FAMILY_BY_KEY[prefix] ?? '';
}

/**
 * Tone of a recorded outcome: gap, pass, review or not_tested.
 * @param {string} outcome
 * @param {boolean} [notTested]
 */
export function storyTone(outcome, notTested = false) {
  if (notTested) return 'not_tested';
  const key = text(outcome).toLowerCase();
  if (NOT_RUN.has(key)) return 'not_tested';
  if (PASS.has(key)) return 'pass';
  if (GAP.has(key)) return 'gap';
  return 'review';
}

/**
 * @param {{ checkId?: string, vectorFamily?: string, outcome?: string, notTested?: boolean,
 *   observationOnly?: boolean, remediation?: string, explanation?: string }} input
 */
export function evidenceStory(input = {}) {
  const family = storyFamily(input.checkId ?? '', input.vectorFamily ?? '');
  const copy = family ? FAMILY_COPY[family] : null;
  const tone = storyTone(input.outcome ?? '', input.notTested === true);
  const observationOnly = input.observationOnly === true && (tone === 'gap' || tone === 'pass');
  const explanation = text(input.explanation);
  const remediation = text(input.remediation);
  let headline;
  if (tone === 'not_tested') headline = 'This check did not produce a result for this target.';
  else if (tone === 'review') headline = 'The result was not conclusive, so it needs a human review.';
  else if (copy) headline = copy[tone];
  else headline = tone === 'gap' ? 'The check recorded a gap on this target.' : 'The check passed on this target.';
  if (observationOnly) headline = `${headline} This is an observation, not a confirmed verdict.`;
  const fix = copy && tone !== 'pass' ? [...copy.fix] : remediation && tone !== 'pass' ? [remediation] : [];
  return {
    family,
    tone,
    observationOnly,
    kicker: observationOnly ? 'Observation' : KICKER[tone],
    headline,
    tested: copy?.tested ?? '',
    why: copy && tone !== 'pass' ? copy.why : tone === 'pass' ? '' : explanation,
    fix,
  };
}

/** @param {string} value */
function humanize(value) {
  const label = text(value).replace(/_/g, ' ');
  return label ? label.charAt(0).toUpperCase() + label.slice(1) : '';
}

/**
 * @param {Array<{ key: string, value: string }>} fields
 * @param {string} key
 */
function field(fields, key) {
  return text((Array.isArray(fields) ? fields : []).find((item) => item?.key === key)?.value);
}

/**
 * Up to four proof rows built only from recorded values. A row is omitted when its value is absent.
 * @param {{ tone: string, observed?: string, expected?: string,
 *   request?: Array<{ key: string, value: string }>, response?: Array<{ key: string, value: string }>,
 *   proof?: { addresses?: string[], matched_signals?: string[], fingerprints?: string[], cnames?: string[] } | null }} input
 * @returns {Array<{ key: string, tone: 'fail' | 'pass' | 'neutral', title: string, detail: string }>}
 */
export function proofRows(input) {
  const rows = [];
  const resultTone = input.tone === 'gap' ? 'fail' : input.tone === 'pass' ? 'pass' : 'neutral';
  const status = field(input.response ?? [], 'status_code') || field(input.response ?? [], 'response_status');
  const external = field(input.response ?? [], 'external_result');
  const responseDetail = [status ? `Response status ${status}` : '', external ? humanize(external) : ''].filter(Boolean).join(' · ');
  const observed = text(input.observed);
  if (observed) rows.push({ key: 'observed', tone: resultTone, title: `Observed: ${observed}`, detail: responseDetail });
  else if (responseDetail) rows.push({ key: 'response', tone: resultTone, title: responseDetail, detail: '' });
  const maxRequests = field(input.request ?? [], 'max_requests');
  const timeout = field(input.request ?? [], 'timeout_ms');
  const sent = field(input.request ?? [], 'requests_sent');
  const bounds = [
    sent && sent !== 'Not recorded' ? `${sent} ${sent === '1' ? 'request' : 'requests'} sent` : '',
    maxRequests ? `at most ${maxRequests}` : '',
    timeout ? `${timeout} ms timeout` : '',
  ].filter(Boolean).join(', ');
  const expected = text(input.expected);
  if (expected) rows.push({ key: 'expected', tone: 'neutral', title: `Expected: ${expected}`, detail: bounds });
  else if (bounds) rows.push({ key: 'bounds', tone: 'neutral', title: 'Bounded probe', detail: bounds });
  const proof = input.proof ?? null;
  const addresses = Array.isArray(proof?.addresses) ? proof.addresses.filter(Boolean) : [];
  if (addresses.length) rows.push({ key: 'addresses', tone: 'neutral', title: `${addresses.length === 1 ? 'Address' : 'Addresses'} observed`, detail: addresses.slice(0, 4).join(', ') });
  const signals = [...(proof?.matched_signals ?? []), ...(proof?.fingerprints ?? [])].filter(Boolean);
  if (signals.length) rows.push({ key: 'signals', tone: 'neutral', title: 'Signals matched', detail: signals.slice(0, 4).join(', ') });
  return rows.slice(0, 4);
}
