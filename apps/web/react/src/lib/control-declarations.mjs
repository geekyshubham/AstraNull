/** Control declarations (`/v1/targets/:id/control-declarations`): draft mapping, client validation and check prerequisites. */
import { checkExclusionReason } from './check-picker.mjs';

export const MAX_NETWORK_RULES = 64;
export const MAX_MARKER_PATHS = 5;
export const MAX_CONNECTION_LIMITS = 64;
export const MAX_NOTE = 200;
export const MAX_HEADER_NAME = 64;
export const MAX_HEADER_VALUE = 256;
export const MAX_PATH = 256;

const HEADER_TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const PRINTABLE_ASCII = /^[\x20-\x7E]+$/;
const ABSOLUTE_PATH = /^\/(?!\/)[^\s?#]*$/;

/** Declaration keys a check can require, with the copy used for chips, CTAs and empty states. */
export const DECLARATION_KEYS = Object.freeze({
  network_policy: Object.freeze({
    label: 'Network policy',
    cta: 'Set blocked ports',
    section: 'network',
    unlocks: 'Declare which ports should be closed so AstraNull can report a firewall exposure when one answers.',
  }),
  'waf.rate_limit_canary': Object.freeze({
    label: 'Rate-limit canary route',
    cta: 'Declare a rate-limit canary route',
    section: 'rate_limit',
    unlocks: 'Name a low-threshold route so AstraNull can check that your rate limit actually triggers.',
  }),
  canary_sink: Object.freeze({
    label: 'Canary sink URL',
    cta: 'Declare a canary sink',
    section: 'canary_sink',
    unlocks: 'A harmless endpoint you deploy, so AstraNull SOC can test request-body and response inspection without touching real data.',
  }),
  connection_limits: Object.freeze({
    label: 'Connection limits',
    cta: 'Declare a connection limit',
    section: 'connection_limits',
    unlocks: 'State how many connections one source may open so AstraNull can check the limit is enforced (at most 12 test connections).',
  }),
  'origin.lockdown_expected': Object.freeze({
    label: 'Origin lockdown',
    cta: 'Declare origin lockdown',
    section: 'origin',
    unlocks: 'Say your origin should only accept traffic from your CDN so a direct answer is reported as an exposure. The origin-lockdown check also needs an origin relation that names the origin address.',
  }),
  perspectives: Object.freeze({
    label: 'Probe perspectives',
    cta: 'Declare allowed or denied perspectives',
    section: 'perspectives',
    unlocks: 'Tell AstraNull which probe source locations your firewall allows or denies so allowlists can be tested.',
  }),
});

export const EXPECTED_WAF_ACTIONS = Object.freeze([
  Object.freeze({ value: 'block', label: 'Block', hint: 'A challenge does not count as a block.' }),
  Object.freeze({ value: 'challenge', label: 'Challenge', hint: 'A CAPTCHA or JavaScript challenge is the expected response.' }),
  Object.freeze({ value: 'block_or_challenge', label: 'Block or challenge', hint: 'Either a block or a challenge satisfies the expectation.' }),
]);

/** What the WAF should do once the canary route's limit is reached (`waf.rate_limit_canary.expected_action`, server default `block`). */
export const RATE_LIMIT_EXPECTED_ACTIONS = Object.freeze([
  Object.freeze({ value: 'block', label: 'Block', hint: 'A block or HTTP 429 counts. A challenge leaves the result inconclusive.' }),
  Object.freeze({ value: 'block_or_challenge', label: 'Block or challenge', hint: 'A CAPTCHA or JavaScript challenge also counts as the limit being enforced.' }),
]);

const RATE_LIMIT_ACTION_VALUES = new Set(RATE_LIMIT_EXPECTED_ACTIONS.map((option) => option.value));

function text(value) {
  return typeof value === 'string' ? value.trim() : value === null || value === undefined ? '' : String(value).trim();
}

function record(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function list(value) {
  return Array.isArray(value) ? value : [];
}

let rowSequence = 0;
function rowKey(prefix) {
  rowSequence += 1;
  return `${prefix}-${rowSequence}`;
}

export function emptyNetworkRule() {
  return { key: rowKey('np'), protocol: 'tcp', port: '', action: 'deny', address_family: 'any', note: '' };
}

export function emptyConnectionLimit() {
  return { key: rowKey('cl'), port: '', max: '' };
}

/** Editable string draft from a stored declarations document. */
export function draftFromDeclarations(input) {
  const doc = record(input) ?? {};
  const waf = record(doc.waf) ?? {};
  const signature = record(waf.block_signature) ?? {};
  const canary = record(waf.rate_limit_canary);
  const perspectives = record(doc.perspectives) ?? {};
  const origin = record(doc.origin);
  return {
    network_policy: list(doc.network_policy).map((rule) => ({
      key: rowKey('np'),
      protocol: text(rule?.protocol) || 'tcp',
      port: rule?.port === undefined || rule?.port === null ? '' : String(rule.port),
      action: text(rule?.action) || 'deny',
      address_family: text(rule?.address_family) || 'any',
      note: text(rule?.note),
    })),
    block_header_name: text(signature.header_name),
    block_header_value: text(signature.header_value),
    block_status_codes: list(signature.status_codes).map(String).join(', '),
    expected_action: text(waf.expected_action),
    rate_limit_enabled: Boolean(canary),
    rate_path: text(canary?.path),
    rate_method: text(canary?.method) || 'GET',
    rate_threshold: canary?.threshold === undefined ? '' : String(canary.threshold),
    rate_window: canary?.window_seconds === undefined ? '' : String(canary.window_seconds),
    rate_expected_action: text(canary?.expected_action) || 'block',
    marker_paths: list(waf.marker_paths).map(text),
    origin_lockdown: origin ? (origin.lockdown_expected === true ? 'expected' : 'not_expected') : '',
    allowlisted_perspective_ids: list(perspectives.allowlisted_perspective_ids).map(text).filter(Boolean),
    denied_perspective_ids: list(perspectives.denied_perspective_ids).map(text).filter(Boolean),
    canary_sink_url: text(record(doc.canary_sink)?.url),
    connection_limits: list(doc.connection_limits).map((row) => ({
      key: rowKey('cl'),
      port: row?.port === undefined || row?.port === null ? '' : String(row.port),
      max: row?.max_connections_per_source === undefined ? '' : String(row.max_connections_per_source),
    })),
  };
}

function integerOrRaw(value) {
  const trimmed = text(value);
  if (/^\d+$/.test(trimmed)) return Number(trimmed);
  return trimmed;
}

function statusCodeList(value) {
  return text(value).split(/[\s,]+/).filter(Boolean).map(integerOrRaw);
}

/** Full-replace PUT body. Empty sections are omitted, never sent as blank objects. */
export function declarationsFromDraft(draft) {
  const body = { version: 1 };
  const rules = list(draft?.network_policy);
  if (rules.length) {
    body.network_policy = rules.map((rule) => {
      const out = { protocol: text(rule.protocol), port: integerOrRaw(rule.port), action: text(rule.action), address_family: text(rule.address_family) };
      if (text(rule.note)) out.note = text(rule.note);
      return out;
    });
  }
  const waf = {};
  if (text(draft?.block_header_name) || text(draft?.block_header_value) || text(draft?.block_status_codes)) {
    waf.block_signature = { header_name: text(draft.block_header_name), header_value: text(draft.block_header_value) };
    if (text(draft.block_status_codes)) waf.block_signature.status_codes = statusCodeList(draft.block_status_codes);
  }
  if (text(draft?.expected_action)) waf.expected_action = text(draft.expected_action);
  if (draft?.rate_limit_enabled) {
    waf.rate_limit_canary = {
      path: text(draft.rate_path),
      method: text(draft.rate_method) || 'GET',
      threshold: integerOrRaw(draft.rate_threshold),
      window_seconds: integerOrRaw(draft.rate_window),
      expected_action: text(draft.rate_expected_action) || 'block',
    };
  }
  const markerPaths = list(draft?.marker_paths).map(text).filter(Boolean);
  if (markerPaths.length) waf.marker_paths = markerPaths;
  if (Object.keys(waf).length) body.waf = waf;
  if (draft?.origin_lockdown === 'expected' || draft?.origin_lockdown === 'not_expected') {
    body.origin = { lockdown_expected: draft.origin_lockdown === 'expected' };
  }
  const allow = list(draft?.allowlisted_perspective_ids).map(text).filter(Boolean);
  const deny = list(draft?.denied_perspective_ids).map(text).filter(Boolean);
  if (allow.length || deny.length) body.perspectives = { allowlisted_perspective_ids: allow, denied_perspective_ids: deny };
  if (text(draft?.canary_sink_url)) body.canary_sink = { url: text(draft.canary_sink_url) };
  const limits = list(draft?.connection_limits);
  if (limits.length) {
    body.connection_limits = limits.map((row) => ({ protocol: 'tcp', port: integerOrRaw(row.port), max_connections_per_source: integerOrRaw(row.max) }));
  }
  return body;
}

/** Stable comparison key for the unsaved-changes guard; row keys are ignored. */
export function declarationsDraftSignature(draft) {
  return JSON.stringify(declarationsFromDraft(draft));
}

function intInRange(value, min, max) {
  const trimmed = text(value);
  if (!/^\d+$/.test(trimmed)) return false;
  const number = Number(trimmed);
  return number >= min && number <= max;
}

function hostOf(target) {
  const value = text(target?.value ?? target?.normalized_value);
  if (!value) return '';
  if (/^https?:\/\//i.test(value)) {
    try { return new URL(value).hostname.replace(/^\[|\]$/g, '').toLowerCase(); } catch { return ''; }
  }
  return value.replace(/:\d+$/, '').replace(/^\[|\]$/g, '').replace(/\.+$/, '').toLowerCase();
}

function sameHostOrSubdomain(candidate, base) {
  if (!candidate || !base) return false;
  if (candidate === base) return true;
  if (/^[\d.]+$/.test(base) || base.includes(':')) return false;
  return candidate.endsWith(`.${base}`);
}

/** Field errors keyed by server field paths (e.g. `network_policy[2].port`) so client and server errors share an input. */
export function validateDeclarationsDraft(draft, { target = null, perspectiveIds = null } = {}) {
  const errors = {};
  const rules = list(draft?.network_policy);
  if (rules.length > MAX_NETWORK_RULES) errors.network_policy = `At most ${MAX_NETWORK_RULES} network rules are allowed.`;
  const seen = new Map();
  rules.forEach((rule, index) => {
    const field = `network_policy[${index}]`;
    if (!intInRange(rule.port, 1, 65535)) errors[`${field}.port`] = 'Enter a port from 1 to 65535.';
    if (text(rule.note).length > MAX_NOTE) errors[`${field}.note`] = `Keep the note under ${MAX_NOTE} characters.`;
    const key = `${text(rule.protocol)}:${text(rule.port)}:${text(rule.address_family)}`;
    if (intInRange(rule.port, 1, 65535)) {
      if (seen.has(key)) errors[`${field}.port`] = `Duplicates rule ${seen.get(key) + 1} (same protocol, port and address family).`;
      else seen.set(key, index);
    }
  });
  const anySignature = text(draft?.block_header_name) || text(draft?.block_header_value) || text(draft?.block_status_codes);
  if (anySignature) {
    const name = text(draft.block_header_name);
    const value = text(draft.block_header_value);
    if (!name) errors['waf.block_signature.header_name'] = 'Enter the response header name your block page sets.';
    else if (name.length > MAX_HEADER_NAME || !HEADER_TOKEN.test(name)) errors['waf.block_signature.header_name'] = 'Use a plain header name such as x-blocked-by (letters, digits and - only).';
    if (!value) errors['waf.block_signature.header_value'] = 'Enter the header value that marks a block.';
    else if (value.length > MAX_HEADER_VALUE || !PRINTABLE_ASCII.test(value)) errors['waf.block_signature.header_value'] = `Use printable ASCII, at most ${MAX_HEADER_VALUE} characters.`;
    const codes = statusCodeList(draft.block_status_codes);
    if (codes.some((code) => typeof code !== 'number' || code < 400 || code > 599)) errors['waf.block_signature.status_codes'] = 'List status codes from 400 to 599, separated by commas.';
    else if (codes.length > 16) errors['waf.block_signature.status_codes'] = 'List at most 16 status codes.';
  }
  if (draft?.rate_limit_enabled) {
    const path = text(draft.rate_path);
    if (!path || path.length > MAX_PATH || !ABSOLUTE_PATH.test(path) || path.includes('\\')) errors['waf.rate_limit_canary.path'] = 'Enter a path starting with / and no query string, for example /rl-canary.';
    if (!intInRange(draft.rate_threshold, 1, 10)) errors['waf.rate_limit_canary.threshold'] = 'Enter a threshold from 1 to 10 requests.';
    if (!intInRange(draft.rate_window, 1, 60)) errors['waf.rate_limit_canary.window_seconds'] = 'Enter a window from 1 to 60 seconds.';
    if (text(draft.rate_expected_action) && !RATE_LIMIT_ACTION_VALUES.has(text(draft.rate_expected_action))) errors['waf.rate_limit_canary.expected_action'] = 'Choose Block or Block or challenge.';
  }
  const markerPaths = list(draft?.marker_paths);
  if (markerPaths.length > MAX_MARKER_PATHS) errors['waf.marker_paths'] = `At most ${MAX_MARKER_PATHS} extra paths are allowed.`;
  const seenPaths = new Set();
  markerPaths.forEach((raw, index) => {
    const path = text(raw);
    const field = `waf.marker_paths[${index}]`;
    if (!path || path.length > MAX_PATH || !ABSOLUTE_PATH.test(path) || path.includes('\\') || path.includes('://')) errors[field] = 'Enter a path on this host starting with /, for example /api/search.';
    else if (seenPaths.has(path)) errors[field] = 'This path is already listed.';
    seenPaths.add(path);
  });
  const sink = text(draft?.canary_sink_url);
  if (sink) {
    let parsed = null;
    try { parsed = new URL(sink); } catch { parsed = null; }
    const base = hostOf(target);
    if (!parsed || parsed.protocol !== 'https:' || parsed.username || parsed.password) errors['canary_sink.url'] = 'Enter an https:// URL with no user name or password.';
    else if (base && !sameHostOrSubdomain(parsed.hostname.toLowerCase(), base)) errors['canary_sink.url'] = `Use ${base} or one of its subdomains.`;
  }
  const limits = list(draft?.connection_limits);
  if (limits.length > MAX_CONNECTION_LIMITS) errors.connection_limits = `At most ${MAX_CONNECTION_LIMITS} connection limits are allowed.`;
  const seenPorts = new Map();
  limits.forEach((row, index) => {
    const field = `connection_limits[${index}]`;
    if (!intInRange(row.port, 1, 65535)) errors[`${field}.port`] = 'Enter a port from 1 to 65535.';
    else if (seenPorts.has(text(row.port))) errors[`${field}.port`] = `Duplicates limit ${seenPorts.get(text(row.port)) + 1} for the same port.`;
    else seenPorts.set(text(row.port), index);
    if (!intInRange(row.max, 1, 10)) errors[`${field}.max_connections_per_source`] = 'Enter 1 to 10 connections per source.';
  });
  if (Array.isArray(perspectiveIds)) {
    const known = new Set(perspectiveIds);
    const allow = list(draft?.allowlisted_perspective_ids);
    const deny = list(draft?.denied_perspective_ids);
    if (allow.some((id) => !known.has(id))) errors['perspectives.allowlisted_perspective_ids'] = 'A selected perspective is no longer registered. Clear it and save again.';
    if (deny.some((id) => !known.has(id))) errors['perspectives.denied_perspective_ids'] = 'A selected perspective is no longer registered. Clear it and save again.';
    if (allow.some((id) => deny.includes(id))) errors['perspectives.denied_perspective_ids'] = 'A perspective cannot be both allowed and denied.';
  }
  return errors;
}

/** Inline field error from a `400 invalid_control_declarations` response, in plain language. */
export function serverFieldErrors(payload) {
  const body = record(payload);
  if (!body || text(body.error) !== 'invalid_control_declarations') return {};
  const entries = list(body.errors).length ? list(body.errors) : [{ field: body.field, message: body.message }];
  const out = {};
  for (const entry of entries) {
    const field = text(record(entry)?.field) || text(body.field) || 'control_declarations';
    const raw = text(record(entry)?.message) || text(body.message) || 'This value was rejected.';
    const trimmed = raw.startsWith(field) ? raw.slice(field.length).trim() : raw;
    const sentence = trimmed ? `${trimmed.charAt(0).toUpperCase()}${trimmed.slice(1)}` : 'This value was rejected.';
    if (!out[field]) out[field] = sentence;
  }
  return out;
}

/** True when the stored document declares the given key (mirrors the server's rule-coverage test). */
export function declarationPresent(declarations, key) {
  const doc = record(declarations);
  if (!doc) return false;
  if (key === 'network_policy') return list(doc.network_policy).length > 0;
  if (key === 'canary_sink') return Boolean(text(record(doc.canary_sink)?.url));
  if (key === 'waf.rate_limit_canary') return Boolean(text(record(record(doc.waf)?.rate_limit_canary)?.path));
  if (key === 'origin.lockdown_expected') return record(doc.origin)?.lockdown_expected === true;
  if (key === 'connection_limits') return list(doc.connection_limits).length > 0;
  if (key === 'perspectives') {
    const row = record(doc.perspectives);
    return list(row?.allowlisted_perspective_ids).length + list(row?.denied_perspective_ids).length > 0;
  }
  return false;
}

/** Which declaration sections hold anything, for the summary and empty state. */
export function declarationSummary(declarations) {
  const doc = record(declarations) ?? {};
  const waf = record(doc.waf) ?? {};
  const rules = list(doc.network_policy);
  return {
    networkRules: rules.length,
    deniedRules: rules.filter((rule) => rule?.action === 'deny').length,
    blockSignature: Boolean(record(waf.block_signature)),
    expectedAction: text(waf.expected_action),
    rateLimitCanary: Boolean(record(waf.rate_limit_canary)),
    markerPaths: list(waf.marker_paths).length,
    originLockdown: record(doc.origin) ? record(doc.origin).lockdown_expected === true : null,
    perspectives: list(record(doc.perspectives)?.allowlisted_perspective_ids).length + list(record(doc.perspectives)?.denied_perspective_ids).length,
    canarySink: Boolean(text(record(doc.canary_sink)?.url)),
    connectionLimits: list(doc.connection_limits).length,
    updatedAt: text(doc.updated_at),
    updatedBy: text(doc.updated_by),
    empty: !rules.length && !Object.keys(waf).length && !record(doc.origin) && !record(doc.perspectives) && !record(doc.canary_sink) && !list(doc.connection_limits).length,
  };
}

/** Plain copy for each `additional_input_reason` the server returns per check and target, and for matching scan exclusions and run refusals. */
export const ADDITIONAL_INPUT_REASON_COPY = Object.freeze({
  port_required: Object.freeze({
    state: 'needs_port',
    label: 'Needs a port',
    cta: 'Declare the port',
    section: 'network',
    declaration: 'network_policy',
    detail: 'This check sends nothing until a service port is known. Declare a rule with the port in Network policy, or add a host:port target.',
  }),
  port_or_declared_deny_required: Object.freeze({
    state: 'needs_deny_or_port',
    label: 'Needs a declared deny rule or a host:port target',
    cta: 'Declare a denied TCP port',
    section: 'network',
    declaration: 'network_policy',
    detail: 'This check only tests a port you said should be closed. Declare a TCP deny rule in Network policy, or add this host as a host:port target.',
  }),
  declared_tcp_deny_required: Object.freeze({
    state: 'needs_declaration',
    label: 'Needs a declared TCP deny rule',
    cta: 'Declare a denied TCP port',
    section: 'network',
    declaration: 'network_policy',
    detail: 'This check only tests TCP ports you said should be closed. Declare a TCP deny rule with a port in Network policy.',
  }),
  declared_udp_deny_required: Object.freeze({
    state: 'needs_declaration',
    label: 'Needs a declared UDP deny rule',
    cta: 'Declare a denied UDP port',
    section: 'network',
    declaration: 'network_policy',
    detail: 'This check only tests UDP ports you said should be closed. Declare a UDP deny rule with a port in Network policy.',
  }),
  declared_connection_limit_required: Object.freeze({
    state: 'needs_declaration',
    label: 'Needs a declared connection limit',
    cta: 'Declare a connection limit',
    section: 'connection_limits',
    declaration: 'connection_limits',
    detail: 'Declare how many connections one source may open on a TCP port, so AstraNull can check the limit is enforced.',
  }),
  declared_rate_limit_canary_required: Object.freeze({
    state: 'needs_declaration',
    label: 'Needs a declared rate-limit canary route',
    cta: 'Declare a rate-limit canary route',
    section: 'rate_limit',
    declaration: 'waf.rate_limit_canary',
    detail: 'Name a low-threshold route in Rate-limit canary route, so AstraNull can check that your rate limit actually triggers.',
  }),
  declared_origin_lockdown_required: Object.freeze({
    state: 'needs_declaration',
    label: 'Needs origin lockdown declared',
    cta: 'Declare origin lockdown',
    section: 'origin',
    declaration: 'origin.lockdown_expected',
    detail: 'Declare that your origin accepts only CDN traffic. The check also needs an active origin relation on the Overview tab that names the origin address.',
  }),
  origin_binding_required: Object.freeze({
    state: 'needs_setup',
    label: 'Needs one verified origin binding',
    cta: 'Open Origin relations',
    section: 'origin_relations',
    declaration: '',
    detail: 'Origin lockdown is declared, but the check also needs exactly one verified origin relation that names your origin address. Add or verify it under Origin relations on the Overview tab.',
  }),
  declared_perspectives_required: Object.freeze({
    state: 'needs_declaration',
    label: 'Needs a denied perspective declared',
    cta: 'Declare a denied perspective',
    section: 'perspectives',
    declaration: 'perspectives',
    detail: 'Mark at least one probe perspective your firewall denies, so an answer from it can show an allowlist gap.',
  }),
  two_perspectives_required: Object.freeze({
    state: 'needs_perspectives',
    label: 'Needs two perspectives',
    cta: '',
    section: '',
    declaration: '',
    detail: 'Needs at least two registered probe source locations. One source cannot tell "allowed only from X" apart from "denied for everyone".',
  }),
  reviewed_origin_identity_comparison_required: Object.freeze({
    state: 'needs_setup',
    label: 'Needs a reviewed paired identity plan',
    cta: '',
    section: '',
    declaration: '',
    detail: 'Use Entry-path comparisons on the protected target’s Overview tab. Select one verified origin relation, review both destinations and limits, then explicitly start the paired HEAD or bounded GET check.',
  }),
  target_bound_direct_address_required: Object.freeze({
    state: 'needs_setup',
    label: 'Needs an origin relation',
    cta: '',
    section: '',
    declaration: '',
    detail: 'Runs only from an origin relation. Bind the origin address under Origin relations on the Overview tab and start it there.',
  }),
  declared_probe_path_required: Object.freeze({
    state: 'needs_setup',
    label: 'Needs a declared probe path',
    cta: '',
    section: '',
    declaration: '',
    detail: 'Runs only through its dedicated workflow with a declared application probe path.',
  }),
  alert_webhook_required: Object.freeze({
    state: 'needs_setup',
    label: 'Needs an approved alert webhook',
    cta: '',
    section: '',
    declaration: '',
    detail: 'Runs only through the signed alert-webhook workflow after its scope is approved.',
  }),
  t7_probe_module_pending: Object.freeze({
    state: 'unavailable',
    label: 'Not available yet',
    cta: '',
    section: '',
    declaration: '',
    detail: 'The probe for this check has not shipped yet, so it cannot run on any target.',
  }),
  invalid_check_definition: Object.freeze({
    state: 'unavailable',
    label: 'Unavailable',
    cta: '',
    section: '',
    declaration: '',
    detail: 'This check definition is incomplete, so it cannot run. AstraNull support can see why.',
  }),
});

const UNKNOWN_REASON_COPY = Object.freeze({
  state: 'needs_setup',
  label: 'Needs setup',
  cta: '',
  section: '',
  declaration: '',
  detail: 'This target is missing something this check needs before it can run.',
});

/** Copy for every key the server can list in rule-coverage `required_declarations` or `missing_declarations`. */
export const REQUIRED_DECLARATION_COPY = Object.freeze({
  ...DECLARATION_KEYS,
  origin_binding: Object.freeze({
    label: 'One verified origin binding',
    cta: ADDITIONAL_INPUT_REASON_COPY.origin_binding_required.cta,
    section: ADDITIONAL_INPUT_REASON_COPY.origin_binding_required.section,
    unlocks: 'Bind your origin address to this target and verify it under Origin relations on the Overview tab, so the origin-lockdown check knows which address to try directly.',
  }),
});

export const UNKNOWN_DECLARATION_COPY = Object.freeze({
  label: 'An additional target setting',
  cta: '',
  section: '',
  unlocks: 'AstraNull needs one more setting on this target before this can be checked.',
});

/** Copy for a required-declaration key; an unknown key gets generic copy and is never shown raw. */
export function requiredDeclarationCopy(key) {
  const id = text(key);
  return id && Object.hasOwn(REQUIRED_DECLARATION_COPY, id) ? REQUIRED_DECLARATION_COPY[id] : UNKNOWN_DECLARATION_COPY;
}

/** A label for use mid-sentence; acronyms such as URL keep their case. */
export function inlineDeclarationLabel(label) {
  const value = text(label);
  return /^[A-Z][a-z]/.test(value) ? `${value.charAt(0).toLowerCase()}${value.slice(1)}` : value;
}

/** Plain, de-duplicated labels for a list of required-declaration keys, joined as "a, b and c". */
export function requiredDeclarationSentence(keys) {
  const labels = [...new Set(list(keys).map((key) => inlineDeclarationLabel(requiredDeclarationCopy(key).label)))];
  if (labels.length < 2) return labels[0] ?? '';
  return `${labels.slice(0, -1).join(', ')} and ${labels[labels.length - 1]}`;
}

/** Copy for a server reason code (check-list reason, scan exclusion or run refusal); null when the code is not a setup requirement. */
export function additionalInputReasonCopy(reason) {
  return ADDITIONAL_INPUT_REASON_COPY[text(reason)] ?? null;
}

/** Scan exclusion reasons that a target or a declaration can satisfy, in the same words as the picker. */
export function targetRequirementForReason(reason) {
  const copy = additionalInputReasonCopy(reason);
  return copy && copy.section ? copy : null;
}

/** Runnable-requirement kinds the server evaluates per target (mirrors TARGET_DEPENDENT_REQUIREMENTS in src/contracts/checks.mjs). */
const TARGET_ANSWERED_REQUIREMENTS = Object.freeze([
  'port',
  'port_or_declared_tcp_deny',
  'port_or_declared_udp_deny',
  'declared_tcp_deny',
  'declared_udp_deny',
  'declared_connection_limit',
  'declared_rate_limit_canary',
  'declared_origin_lockdown',
  'declared_perspectives',
]);

/** True when only the server's per-target answer can say whether this check runs; the client never guesses it. */
export function needsTargetAnswer(check) {
  return list(check?.runnable_requires).map(text).some((value) => TARGET_ANSWERED_REQUIREMENTS.includes(value));
}

function answerFrom(value) {
  if (typeof value === 'boolean') return { runnable: value, reason: '' };
  const row = record(value);
  if (row && typeof row.runnable === 'boolean') return { runnable: row.runnable, reason: text(row.reason) };
  return null;
}

/** Per-check server answer from a target-scoped catalog (`GET /v1/checks?scope=all&target_id=`). */
export function targetRunnableIndex(items) {
  const index = new Map();
  for (const item of list(items)) {
    const id = text(record(item)?.check_id);
    if (id && typeof item.requires_additional_input === 'boolean') {
      index.set(id, { runnable: item.requires_additional_input === false, reason: item.requires_additional_input ? text(item.additional_input_reason) : '' });
    }
  }
  return index;
}

/** Server reason codes a target can fix, so the check is worth listing with a CTA instead of hiding it. */
export function targetFixableReason(reason) {
  return Boolean(targetRequirementForReason(reason));
}

function fromCopy(copy, reason) {
  return { state: copy.state, label: copy.label, missing: copy.declaration ? [copy.declaration] : [], detail: copy.detail, reason, cta: copy.cta, section: copy.section };
}

const READY = Object.freeze({ state: 'ready', label: '', missing: [], detail: '', reason: '', cta: '', section: '' });

/**
 * Whether a check can run now. The server's per-target answer (`serverRunnable` or `serverRunnableIndex`) decides,
 * with its `additional_input_reason` naming what is missing. Without it, target-answered checks wait.
 */
export function checkPrerequisite(check, { declarations, perspectiveCount = 1, serverRunnable, serverRunnableIndex = null, serverSuppliesInput = false } = {}) {
  const exclusion = checkExclusionReason(check);
  const answer = answerFrom(serverRunnable) ?? (serverRunnableIndex instanceof Map ? answerFrom(serverRunnableIndex.get(text(check?.check_id))) : null);
  if ((exclusion === 'soc_gated' || exclusion === 'not_customer_runnable') && !(serverSuppliesInput && answer?.runnable)) {
    return { state: 'soc_only', label: 'SOC only', missing: [], detail: 'Run only by AstraNull SOC under an approved authorization. Request it through SOC; it cannot be started here.', reason: '', cta: '', section: '' };
  }
  if (answer) {
    if (answer.runnable) return { ...READY, missing: [] };
    return fromCopy(additionalInputReasonCopy(answer.reason) ?? UNKNOWN_REASON_COPY, answer.reason);
  }
  if (needsTargetAnswer(check)) {
    return { state: 'checking', label: 'Checking this target', missing: [], detail: 'Waiting for AstraNull to confirm what this target has declared. Until then it stays out of run-all.', reason: '', cta: '', section: '' };
  }
  const missing = list(check?.required_customer_setup).map(text)
    .filter((key) => Object.hasOwn(DECLARATION_KEYS, key))
    .filter((key) => !declarationPresent(declarations, key));
  if (missing.length) {
    const first = DECLARATION_KEYS[missing[0]];
    return {
      state: 'needs_declaration',
      label: 'Needs declaration',
      missing,
      detail: `Declare ${missing.map((key) => inlineDeclarationLabel(DECLARATION_KEYS[key].label)).join(' and ')} on this target first. Until then it is left out of run-all.`,
      reason: '',
      cta: first.cta,
      section: first.section,
    };
  }
  if (list(check?.runnable_requires).map(text).includes('two_perspectives') && perspectiveCount < 2) {
    return fromCopy(ADDITIONAL_INPUT_REASON_COPY.two_perspectives_required, '');
  }
  return { ...READY, missing: [] };
}

/** CTA copy for a prerequisite that a declaration can satisfy. */
export function prerequisiteCta(prerequisite) {
  if (text(prerequisite?.cta)) return text(prerequisite.cta);
  const key = list(prerequisite?.missing)[0];
  return key && DECLARATION_KEYS[key] ? DECLARATION_KEYS[key].cta : '';
}

/** Chip tone: a setup gap the customer can close is a warning; SOC-only, unavailable and still-loading answers are neutral. */
export function prerequisiteTone(prerequisite) {
  return ['soc_only', 'checking', 'unavailable'].includes(text(prerequisite?.state)) ? 'muted' : 'warn';
}

/** Controls section a prerequisite links to, or '' when no declaration can satisfy it. */
export function prerequisiteSection(prerequisite) {
  if (text(prerequisite?.section)) return text(prerequisite.section);
  const key = list(prerequisite?.missing)[0];
  return key && DECLARATION_KEYS[key] ? DECLARATION_KEYS[key].section : '';
}

/** If-Match value for a stored declarations document; the server's ETag is `"decl-r<revision>"`. */
export function declarationsEtag(doc) {
  const revision = Number(record(doc)?.revision);
  return `"decl-r${Number.isSafeInteger(revision) && revision >= 0 ? revision : 0}"`;
}

/** Classifies a failed save: a concurrent edit (412), a missing precondition (428), or neither. */
export function declarationsSaveConflict(error) {
  const status = Number(record(error)?.status);
  const payload = record(record(error)?.payload) ?? {};
  if (status === 412 || text(payload.error) === 'declarations_conflict') {
    const revision = Number(payload.revision);
    return { kind: 'conflict', revision: Number.isSafeInteger(revision) ? revision : null, etag: text(payload.etag) };
  }
  if (status === 428 || text(payload.error) === 'precondition_required') return { kind: 'precondition', revision: null, etag: '' };
  return null;
}

function listText(items, limit = 4) {
  if (!items.length) return 'None';
  const shown = items.slice(0, limit).join(', ');
  return items.length > limit ? `${shown} and ${items.length - limit} more` : shown;
}

const ORIGIN_COPY = Object.freeze({ expected: 'Origin accepts only CDN traffic', not_expected: 'Origin reachable directly by design', '': 'Not declared' });

const ruleText = (rule) => `${text(rule.protocol).toUpperCase()} ${text(rule.port) || '?'} ${text(rule.action)}${rule.address_family && rule.address_family !== 'any' ? ` (${rule.address_family === 'ipv4' ? 'IPv4' : 'IPv6'})` : ''}`;

/** Each section reads as a single value or as a list of items, so list differences can name the items. */
const DIFF_SECTIONS = Object.freeze([
  ['network', 'Network policy', (draft) => draft.network_policy.map(ruleText), ['rule', 'rules']],
  ['waf_signature', 'WAF block signature', (draft) => (text(draft.block_header_name) ? `Header ${text(draft.block_header_name)}${text(draft.block_status_codes) ? `, status ${text(draft.block_status_codes)}` : ''}` : 'Not declared')],
  ['waf_action', 'Expected WAF action', (draft) => EXPECTED_WAF_ACTIONS.find((option) => option.value === draft.expected_action)?.label ?? 'Not declared'],
  ['rate_limit', 'Rate-limit canary route', (draft) => (draft.rate_limit_enabled ? `${text(draft.rate_method) || 'GET'} ${text(draft.rate_path) || '?'}, ${text(draft.rate_threshold) || '?'} per ${text(draft.rate_window) || '?'} s, then ${(RATE_LIMIT_EXPECTED_ACTIONS.find((option) => option.value === (text(draft.rate_expected_action) || 'block'))?.label ?? text(draft.rate_expected_action)).toLowerCase()}` : 'Not declared')],
  ['marker_paths', 'Extra marker paths', (draft) => draft.marker_paths.map(text).filter(Boolean), ['path', 'paths']],
  ['origin', 'Origin lockdown', (draft) => ORIGIN_COPY[draft.origin_lockdown] ?? ORIGIN_COPY['']],
  ['perspectives', 'Probe perspectives', (draft) => [...draft.allowlisted_perspective_ids.map((id) => `${id} allowed`), ...draft.denied_perspective_ids.map((id) => `${id} denied`)], ['perspective', 'perspectives']],
  ['canary_sink', 'Canary sink URL', (draft) => text(draft.canary_sink_url) || 'Not declared'],
  ['connection_limits', 'Connection limits', (draft) => draft.connection_limits.map((row) => `TCP ${text(row.port) || '?'}: ${text(row.max) || '?'} per source`), ['limit', 'limits']],
]);

function listSide(items, other, nouns, elsewhere) {
  const only = items.filter((item) => !other.includes(item));
  const count = `${items.length} ${items.length === 1 ? nouns[0] : nouns[1]}`;
  if (!only.length) return items.length === other.length ? `${count}, in a different order` : `${count}, nothing extra`;
  return `${count}; not in ${elsewhere}: ${listText(only)}`;
}

/** Sections where the latest saved document and the user's draft differ, described in plain words. */
export function declarationsDraftDiff(latestDoc, draft) {
  const theirs = draftFromDeclarations(latestDoc);
  const mine = draft ?? draftFromDeclarations(null);
  return DIFF_SECTIONS.flatMap(([section, label, describe, nouns]) => {
    const left = describe(theirs);
    const right = describe(mine);
    if (JSON.stringify(left) === JSON.stringify(right)) return [];
    if (Array.isArray(left) && Array.isArray(right)) {
      return [{ section, label, theirs: listSide(left, right, nouns, 'your draft'), yours: listSide(right, left, nouns, 'their version') }];
    }
    return [{ section, label, theirs: String(left), yours: String(right) }];
  });
}

/** Target sections a prerequisite can point at outside the Controls tab. */
export const TARGET_LINK_SECTIONS = Object.freeze({
  origin_relations: Object.freeze({ tab: 'overview', section: 'origin-relations' }),
});

/** Hash link to one section of the target's control declarations, or to a target section listed in TARGET_LINK_SECTIONS. */
export function controlsHref(targetId, section = '') {
  const elsewhere = TARGET_LINK_SECTIONS[text(section)];
  const params = new URLSearchParams({ id: text(targetId), tab: elsewhere ? elsewhere.tab : 'controls' });
  if (elsewhere) params.set('section', elsewhere.section);
  else if (section) params.set('section', section);
  return `#target-detail?${params.toString()}`;
}

/** Editor sections in display order, grouped for the overview and form. */
export const DECLARATION_SECTION_GROUPS = Object.freeze([
  Object.freeze({ id: 'network', label: 'Network and firewall', sections: Object.freeze(['network', 'connection_limits', 'perspectives']) }),
  Object.freeze({ id: 'waf', label: 'WAF behaviour', sections: Object.freeze(['waf_signature', 'waf_action', 'rate_limit', 'marker_paths']) }),
  Object.freeze({ id: 'origin', label: 'Origin and SOC inputs', sections: Object.freeze(['origin', 'canary_sink']) }),
]);

const plural = (count, one, many) => `${count} ${count === 1 ? one : many}`;

const SECTION_STATUS = Object.freeze([
  ['network', 'Network policy', (body) => body.network_policy, (doc) => {
    const rules = list(doc.network_policy);
    const denied = rules.filter((rule) => rule?.action === 'deny').length;
    return rules.length ? `${plural(rules.length, 'rule', 'rules')}, ${denied} denied` : 'No rules';
  }],
  ['connection_limits', 'Connection limits', (body) => body.connection_limits, (doc) => {
    const count = list(doc.connection_limits).length;
    return count ? plural(count, 'limit', 'limits') : 'No limits';
  }],
  ['perspectives', 'Probe perspectives', (body) => body.perspectives, (doc) => {
    const row = record(doc.perspectives);
    const allowed = list(row?.allowlisted_perspective_ids).length;
    const denied = list(row?.denied_perspective_ids).length;
    return allowed + denied ? `${allowed} allowed, ${denied} denied` : 'None marked';
  }],
  ['waf_signature', 'WAF block signature', (body) => body.waf?.block_signature, (doc) => {
    const name = text(record(record(doc.waf)?.block_signature)?.header_name);
    return name ? `Header ${name}` : 'Not declared';
  }],
  ['waf_action', 'Expected WAF action', (body) => body.waf?.expected_action, (doc) => {
    const value = text(record(doc.waf)?.expected_action);
    return EXPECTED_WAF_ACTIONS.find((option) => option.value === value)?.label ?? 'Catalog default';
  }],
  ['rate_limit', 'Rate-limit canary route', (body) => body.waf?.rate_limit_canary, (doc) => {
    const canary = record(record(doc.waf)?.rate_limit_canary);
    return canary ? `${text(canary.method) || 'GET'} ${text(canary.path) || '?'}` : 'Not declared';
  }],
  ['marker_paths', 'Extra marker paths', (body) => body.waf?.marker_paths, (doc) => {
    const count = list(record(doc.waf)?.marker_paths).length;
    return count ? plural(count, 'extra path', 'extra paths') : 'Root path only';
  }],
  ['origin', 'Origin lockdown', (body) => body.origin, (doc) => {
    const origin = record(doc.origin);
    if (!origin) return 'Not declared';
    return origin.lockdown_expected === true ? 'CDN traffic only' : 'Direct access by design';
  }],
  ['canary_sink', 'Canary sink URL', (body) => body.canary_sink, (doc) => (text(record(doc.canary_sink)?.url) ? 'URL declared' : 'Not declared')],
]);

/** Per-section saved state for the overview: whether the stored document declares it, a short detail, and whether the draft changes it. */
export function declarationSectionStates(stored, draft) {
  const doc = record(stored) ?? {};
  const savedBody = declarationsFromDraft(draftFromDeclarations(doc));
  const draftBody = draft ? declarationsFromDraft(draft) : savedBody;
  return SECTION_STATUS.map(([id, label, slice, detail]) => {
    const saved = slice(savedBody);
    return {
      id,
      label,
      declared: saved !== undefined,
      detail: detail(doc),
      edited: JSON.stringify(saved ?? null) !== JSON.stringify(slice(draftBody) ?? null),
    };
  });
}
