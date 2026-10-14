/**
 * SOC-only canary-sink body planner and grader. Pure functions, no network I/O.
 * Bodies go only to the declared canary sink URL. Worker runtime must not import this as a probe kind.
 */

import { BENIGN_CLASS_MARKERS } from '../inertWafMarkers.mjs';

export const CANARY_SINK_BODY_PLAN_KIND = 'canary_sink_body_plan';
export const CANARY_SINK_BODY_MAX_REQUESTS = 12;
export const INSPECTION_LIMIT_PADDING_KB = Object.freeze([8, 16, 64, 128]);
export const SYNTHETIC_PAN = '4111 1111 1111 1111';
export const DLP_PATH_SUFFIX = 'astranull-dlp-canary';

const MANAGED_MARKERS = Object.freeze({
  sqli: BENIGN_CLASS_MARKERS.sqli,
  xss: BENIGN_CLASS_MARKERS.xss,
  path_traversal: BENIGN_CLASS_MARKERS.path_traversal,
});

function planError(code, message) {
  return Object.assign(new Error(message), { code });
}

function assertHttpsSink(raw) {
  const value = String(raw ?? '').trim();
  if (!value) throw planError('missing_canary_sink', 'canarySinkUrl is required');
  let url;
  try {
    url = new URL(value);
  } catch {
    throw planError('invalid_canary_sink', 'canarySinkUrl is not a valid URL');
  }
  if (url.protocol !== 'https:' || url.username || url.password) {
    throw planError('invalid_canary_sink', 'canary sink must be https without credentials');
  }
  return url;
}

function assertSameSink(requestUrl, sinkUrl) {
  let parsed;
  try {
    parsed = new URL(requestUrl);
  } catch {
    throw planError('sink_url_mismatch', 'request URL is not the declared canary sink');
  }
  if (parsed.origin !== sinkUrl.origin || parsed.username || parsed.password) {
    throw planError('sink_url_mismatch', 'request URL is not the declared canary sink');
  }
}

function dlpUrl(sinkUrl) {
  const next = new URL(sinkUrl.href);
  const base = next.pathname.replace(/\/$/, '') || '';
  next.pathname = `${base}/${DLP_PATH_SUFFIX}`;
  next.search = '';
  next.hash = '';
  return next.href;
}

function jsonBody(marker, paddingBytes = 0) {
  const pad = paddingBytes > 0 ? 'a'.repeat(paddingBytes) : '';
  return JSON.stringify({ pad, astranull_probe: marker });
}

function formBody(marker, paddingBytes = 0) {
  const params = new URLSearchParams();
  if (paddingBytes > 0) params.set('pad', 'a'.repeat(paddingBytes));
  params.set('astranull_probe', marker);
  return params.toString();
}

function multipartBody(marker) {
  const boundary = 'astranull-inert-boundary';
  const filename = 'astranull-probe.txt';
  const parts = [
    `--${boundary}`,
    'Content-Disposition: form-data; name="astranull_probe"; filename="astranull-probe.txt"',
    'Content-Type: text/plain',
    '',
    marker,
    `--${boundary}--`,
    '',
  ];
  return { body: parts.join('\r\n'), boundary, filename };
}

function requestRow({ id, variant, method, url, contentType, body, markerClass, paddingKb = 0, extra = {} }) {
  const bytes = Buffer.byteLength(body ?? '', 'utf8');
  return Object.freeze({
    id,
    variant,
    method,
    url,
    content_type: contentType,
    content_length: bytes,
    body: body ?? '',
    marker_class: markerClass ?? null,
    padding_kb: paddingKb,
    ...extra,
  });
}

const DEFAULT_VARIANTS = Object.freeze([
  'json',
  'form',
  'multipart',
  ...INSPECTION_LIMIT_PADDING_KB.map((kb) => `inspection_limit_${kb}kb`),
  'response_dlp',
]);

export function planCanarySinkBodyTests({ canarySinkUrl, declaredCanarySinkUrl, variants } = {}) {
  const sinkUrl = assertHttpsSink(canarySinkUrl);
  if (declaredCanarySinkUrl != null) {
    const declared = assertHttpsSink(declaredCanarySinkUrl);
    if (declared.href !== sinkUrl.href) {
      throw planError('sink_url_mismatch', 'request URL is not the declared canary sink');
    }
  }
  const requested = Array.isArray(variants) && variants.length > 0 ? variants : [...DEFAULT_VARIANTS];
  if (requested.length > CANARY_SINK_BODY_MAX_REQUESTS) {
    throw planError('plan_cap_exceeded', `at most ${CANARY_SINK_BODY_MAX_REQUESTS} body tests`);
  }

  const requests = [];
  const sinkHref = sinkUrl.href;
  for (const raw of requested) {
    if (requests.length >= CANARY_SINK_BODY_MAX_REQUESTS) {
      throw planError('plan_cap_exceeded', `at most ${CANARY_SINK_BODY_MAX_REQUESTS} body tests`);
    }
    const variant = String(raw ?? '').trim();
    if (variant === 'json') {
      const body = jsonBody(MANAGED_MARKERS.sqli);
      const row = requestRow({
        id: 'json_marker', variant: 'json', method: 'POST', url: sinkHref,
        contentType: 'application/json', body, markerClass: 'sqli',
      });
      assertSameSink(row.url, sinkUrl);
      requests.push(row);
      continue;
    }
    if (variant === 'form') {
      const body = formBody(MANAGED_MARKERS.xss);
      const row = requestRow({
        id: 'form_marker', variant: 'form', method: 'POST', url: sinkHref,
        contentType: 'application/x-www-form-urlencoded', body, markerClass: 'xss',
      });
      assertSameSink(row.url, sinkUrl);
      requests.push(row);
      continue;
    }
    if (variant === 'multipart') {
      const { body, boundary, filename } = multipartBody(MANAGED_MARKERS.path_traversal);
      const row = requestRow({
        id: 'multipart_marker', variant: 'multipart', method: 'POST', url: sinkHref,
        contentType: `multipart/form-data; boundary=${boundary}`, body,
        markerClass: 'path_traversal', extra: { filename, part_name: 'astranull_probe' },
      });
      assertSameSink(row.url, sinkUrl);
      requests.push(row);
      continue;
    }
    const limitMatch = variant.match(/^inspection_limit_(\d+)kb$/);
    if (limitMatch) {
      const paddingKb = Number(limitMatch[1]);
      if (!INSPECTION_LIMIT_PADDING_KB.includes(paddingKb)) {
        throw planError('unknown_variant', `unknown inspection-limit size: ${paddingKb}`);
      }
      const body = jsonBody(MANAGED_MARKERS.sqli, paddingKb * 1024);
      const row = requestRow({
        id: `inspection_limit_${paddingKb}kb`, variant: 'inspection_limit', method: 'POST', url: sinkHref,
        contentType: 'application/json', body, markerClass: 'sqli', paddingKb,
      });
      assertSameSink(row.url, sinkUrl);
      requests.push(row);
      continue;
    }
    if (variant === 'response_dlp') {
      const url = dlpUrl(sinkUrl);
      assertSameSink(url, sinkUrl);
      requests.push(Object.freeze({
        id: 'response_dlp_pan',
        variant: 'response_dlp',
        method: 'GET',
        url,
        content_type: null,
        content_length: 0,
        body: '',
        marker_class: null,
        padding_kb: 0,
        instruction: 'Canary sink returns the synthetic test card number on this dedicated path.',
        synthetic_pan: SYNTHETIC_PAN,
      }));
      continue;
    }
    throw planError('unknown_variant', `unknown canary-sink body variant: ${variant}`);
  }

  if (requests.length > CANARY_SINK_BODY_MAX_REQUESTS) {
    throw planError('plan_cap_exceeded', `at most ${CANARY_SINK_BODY_MAX_REQUESTS} body tests`);
  }
  return Object.freeze({
    kind: CANARY_SINK_BODY_PLAN_KIND,
    canary_sink_url: sinkHref,
    max_requests: CANARY_SINK_BODY_MAX_REQUESTS,
    requests,
  });
}

function observationFor(id, observations) {
  const rows = Array.isArray(observations) ? observations : [];
  return rows.find((row) => row && (row.id === id || row.variant_id === id)) ?? null;
}

function outcomeFromObservation(obs) {
  if (!obs) return 'inconclusive';
  if (obs.outcome) return String(obs.outcome);
  if (obs.blocked === true) return 'blocked';
  if (obs.challenged === true) return 'challenged';
  if (obs.allowed === true) return 'allowed';
  if (obs.redirected === true) return 'redirected';
  const status = Number(obs.status_code);
  if (status === 429 || status === 403) return 'blocked';
  if (status >= 200 && status < 300) return 'allowed';
  return 'inconclusive';
}

export function gradeCanarySinkBodyResults(plan, observations) {
  const requests = Array.isArray(plan?.requests) ? plan.requests : [];
  const variants = [];
  let failOpenAt = null;
  let dlp = null;
  for (const request of requests) {
    const obs = observationFor(request.id, observations);
    const outcome = outcomeFromObservation(obs);
    const row = {
      id: request.id,
      variant: request.variant,
      padding_kb: request.padding_kb ?? 0,
      outcome,
      status_code: Number.isInteger(obs?.status_code) ? obs.status_code : null,
    };
    if (request.variant === 'inspection_limit') {
      if (failOpenAt == null && outcome === 'allowed') failOpenAt = request.padding_kb;
    }
    if (request.variant === 'response_dlp') {
      const panVisible = obs?.pan_visible === true;
      const panMasked = obs?.pan_masked === true || outcome === 'blocked' || obs?.blocked === true;
      dlp = {
        pan_visible: panVisible,
        pan_masked: panMasked,
        outcome: panMasked && !panVisible ? 'blocked' : panVisible ? 'allowed' : outcome,
      };
      row.outcome = dlp.outcome;
      row.pan_visible = panVisible;
      row.pan_masked = panMasked;
    }
    variants.push(row);
  }
  return Object.freeze({
    kind: CANARY_SINK_BODY_PLAN_KIND,
    variant_results: variants,
    inspection_limit_fail_open_at_kb: failOpenAt,
    response_dlp: dlp,
  });
}
