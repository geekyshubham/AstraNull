/** Console projection of recorded activity. Never manufactures requests, timings, or results. */
const STAGES = {
  job_started: ['init', 'START', 'Worker started'],
  attempt_started: ['probe', 'PROBE', 'Attempt started'],
  request_started: ['probe', 'PROBE', 'Request started'],
  response_received: ['recv', 'RECV', 'Response received'],
  attempt_failed: ['error', 'ERROR', 'Request failed'],
  request_not_sent: ['warn', 'WARN', 'Not sent'],
  phase_completed: ['recv', 'RECV', 'Phase finished'],
  probe_completed: ['verdict', 'VERDICT', 'Probe finished'],
  response_payload: ['recv', 'PAYLOAD', 'Response payload captured'],
  response_body_completed: ['recv', 'RECV', 'Response body read'],
};

const safeText = (value) => typeof value === 'string' ? value : '';

function time(at) {
  const value = new Date(at);
  return Number.isNaN(value.getTime())
    ? 'Not recorded'
    : value.toLocaleTimeString(undefined, {
        hour12: false,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        fractionalSecondDigits: 3,
      });
}

function entry(id, at, level, tag, message, extra = {}) {
  return { id, timestamp: safeText(at), timeDisplay: time(at), level, tag, message, ...extra };
}

function activityLog(id, at, data, row) {
  if (!data || !STAGES[data.stage]) return null;
  const [level, tag, label] = STAGES[data.stage];
  const message = [
    label,
    safeText(data.method) || safeText(data.operation).replaceAll('_', ' '),
    safeText(data.url),
    Number.isInteger(data.status_code) ? `HTTP ${data.status_code}` : '',
    safeText(data.error_class) || safeText(data.reason),
    Number.isInteger(data.duration_ms) ? `${data.duration_ms}ms` : '',
    data.phase ? `phase ${data.phase}` : '',
    data.vector_family ? `vector ${data.vector_family}` : '',
    data.response_content_type ? `format ${data.response_content_type}` : '',
  ].filter(Boolean).join(' · ');

  const detail = Object.fromEntries(
    [
      'stage', 'operation', 'method', 'url', 'protocol', 'status_code', 'duration_ms', 'requests_sent',
      'error_class', 'reason', 'body_bytes', 'header_names', 'phase', 'vector_family', 'marker_class',
      'request_content_type', 'response_content_type', 'request_payload_preview', 'request_query_preview',
      'response_payload_preview', 'request_payload_encoding', 'response_payload_encoding',
      'request_payload_truncated', 'response_payload_truncated', 'response_payload_available',
      'response_bytes_observed', 'response_bytes_captured',
    ]
      .filter((key) => data[key] != null)
      .map((key) => [key, data[key]])
  );

  return entry(id, at, level, tag, message, {
    checkId: row?.checkId,
    checkName: row?.name,
    detail: JSON.stringify(detail, null, 2),
    ...(Number.isInteger(data.status_code) ? { statusCode: data.status_code } : {}),
    ...(Number.isInteger(data.duration_ms) ? { latencyMs: data.duration_ms } : {}),
  });
}

function formatProbeResultEntry(eventId, at, metadata, producerKind, row) {
  const simulated = producerKind === 'internal_simulation';
  const extResult = safeText(metadata?.external_result);
  const statusCode = Number.isInteger(metadata?.status_code) ? metadata.status_code : null;
  const statusStr = statusCode !== null ? ` · HTTP ${statusCode}` : '';
  const count = metadata?.safety_attestation?.requests_sent;
  // Transport results do not establish an origin bypass or enforcement location.
  // Only the separately published verdict supplies a protection outcome.
  const summary = simulated ? 'Simulation result; no target traffic' : 'Worker result recorded';
  return entry(safeText(eventId), at, 'recv', simulated ? 'SIMULATION' : 'RECV',
    `${summary}${extResult ? `: ${extResult}` : ''}${statusStr}`, {
      checkId: row?.checkId,
      tone: 'info',
      ...(statusCode !== null ? { statusCode } : {}),
      ...(Number.isInteger(count) ? { requestsSent: count } : {}),
    });
}

function formatVerdictEntry(id, at, row) {
  const status = safeText(row.status);
  const verdict = safeText(row.verdict);
  const explanation = safeText(row.explanation);

  let tag = 'STATE';
  let tone = 'default';

  if (status === 'failed') {
    tag = 'GAP';
    tone = 'danger';
  } else if (status === 'passed') {
    tag = 'PASS';
    tone = 'success';
  } else if (status === 'observed') {
    tag = 'OBSERVED';
    tone = 'muted';
  } else if (status === 'inconclusive') {
    tag = 'WARN';
    tone = 'warn';
  } else if (status === 'blocked') {
    tag = 'BLOCKED';
    tone = 'warn';
  }

  const label =
    status === 'failed'
      ? 'Gap found'
      : status === 'passed'
      ? 'Passed'
      : status === 'observed'
      ? 'Observed'
      : status === 'inconclusive'
      ? 'Inconclusive'
      : status === 'blocked'
      ? 'Blocked by safety gate'
      : status || 'Completed';

  const parts = [
    `Check outcome: ${label}`,
    verdict && verdict !== status ? verdict : '',
  ].filter(Boolean).join(' · ');

  const fullMessage = explanation ? `${parts} — ${explanation}` : parts;

  return entry(id, at, 'verdict', tag, fullMessage, {
    checkId: row.checkId,
    tone,
  });
}

export function generateCheckProbeLogs(row, _targetValue = 'target', runEvents = []) {
  if (!row) return [];
  const result = [];
  if (row.startedAt) {
    result.push(
      entry(
        `run:${row.runId || row.checkId}:started`,
        row.startedAt,
        'init',
        'STATE',
        `Run recorded: ${row.name || row.checkId}`,
        { checkId: row.checkId }
      )
    );
  }

  let hasProbeResult = false;
  for (const event of Array.isArray(runEvents) ? runEvents : []) {
    if (!row.runId || event.test_run_id !== row.runId || event.check_id !== row.checkId) continue;
    const at = safeText(event.timestamp);
    if (event.signal_type === 'probe_activity' && event.producer_kind === 'signed_probe') {
      const log = activityLog(
        safeText(event.id),
        at,
        {
          ...event.metadata?.activity,
          vector_family: event.metadata?.vector_family,
          marker_class: event.metadata?.marker_class,
        },
        row
      );
      if (log) result.push(log);
    } else if (
      event.signal_type === 'probe_result' &&
      ['signed_probe', 'internal_simulation'].includes(event.producer_kind)
    ) {
      hasProbeResult = true;
      result.push(
        formatProbeResultEntry(
          event.id,
          at,
          event.metadata || {},
          event.producer_kind,
          row
        )
      );
    }
  }

  // Show the recorded result snapshot when no trusted result event was included.
  if (!hasProbeResult && row.response && (row.response.external_result || row.response.status_code)) {
    const probeAt =
      safeText(row.response.received_at) ||
      row.finishedAt ||
      row.startedAt ||
      '';
    result.push(
      formatProbeResultEntry(
        `row:${row.runId || row.checkId}:response`,
        probeAt,
        row.response,
        row.requestsSimulated ? 'internal_simulation' : 'signed_probe',
        row
      )
    );
  }

  if (row.finishedAt) {
    result.push(
      formatVerdictEntry(
        `run:${row.runId || row.checkId}:finished`,
        row.finishedAt,
        row
      )
    );
  }

  return result.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
}

export function buildScanLiveLogs(_scan, rows = [], activityItems = [], _targetValue = 'target') {
  const result = [];
  const seen = new Set();
  for (const item of Array.isArray(activityItems) ? activityItems : []) {
    if (!item.id || seen.has(item.id)) continue;
    seen.add(item.id);
    const row = rows.find((record) => record.checkId === item.check_id);
    if (item.action === 'probe_activity') {
      if (item.metadata?.producer_kind !== 'signed_probe') continue;
      const log = activityLog(
        item.id,
        item.at,
        {
          ...item.metadata?.activity,
          vector_family: item.metadata?.vector_family,
          marker_class: item.metadata?.marker_class,
        },
        row
      );
      if (log) result.push(log);
      continue;
    }

    const hasError =
      Boolean(item.metadata?.error_code) ||
      item.metadata?.verdict === 'edge_exposed' ||
      (row?.status === 'failed' && item.metadata?.verdict === 'edge_exposed');
    const level = hasError ? 'error' : 'info';
    const tag = item.kind === 'scan' ? 'SCAN' : hasError ? 'GAP' : 'INFO';
    const tone = hasError ? 'danger' : undefined;

    result.push(
      entry(
        item.id,
        item.at,
        level,
        tag,
        safeText(item.summary) || safeText(item.action).replaceAll('_', ' '),
        {
          checkId: item.check_id,
          checkName: row?.name,
          ...(tone ? { tone } : {}),
        }
      )
    );
  }
  return result.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
}
