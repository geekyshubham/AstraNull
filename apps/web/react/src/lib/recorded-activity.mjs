/** Passive, shared REST reader. Event identity is immutable; paging is not capture completeness. */
export const ACTIVITY_POLL_MS = 2500;
export const ACTIVITY_MAX_BACKOFF_MS = 15000;
const ACTIVE = new Set(['planned', 'queued', 'dispatching', 'starting', 'running', 'collecting', 'paused', 'gate_paused', 'stopping', 'scheduled']);
const STOP_PENDING = new Set(['requested']);
const text = (value) => typeof value === 'string' ? value : '';

/** Page-local opaque credential epochs: raw credentials never become a reader key or URL. */
export function createActivityReaderKey() {
  const epochs = new Map();
  let nextEpoch = 0;
  return ({ identity, authMode, session, kind = 'run', id }) => {
    if (!id) return '';
    const credentials = JSON.stringify([session?.mode ?? '', session?.access_token ?? '', session?.expires_at ?? null]);
    let byCredentials = epochs.get(identity);
    if (!byCredentials) { byCredentials = new Map(); epochs.set(identity, byCredentials); }
    if (!byCredentials.has(credentials)) byCredentials.set(credentials, ++nextEpoch);
    return JSON.stringify([identity, authMode, byCredentials.get(credentials), kind, id]);
  };
}

export function activityIsLive(snapshot) {
  return ACTIVE.has(text(snapshot?.status)) || STOP_PENDING.has(text(snapshot?.stop?.state));
}

export function activityPath(kind, id, cursor = '') {
  const params = new URLSearchParams({ limit: '256' });
  if (cursor) params.set(kind === 'scan' ? 'after' : 'cursor', cursor);
  return `/v1/${kind === 'scan' ? 'validation-scans' : 'test-runs'}/${encodeURIComponent(id)}/activity?${params}`;
}

export function mergeActivityItems(previous = [], incoming = []) {
  const byId = new Map(previous.filter((item) => text(item?.id)).map((item) => [item.id, item]));
  for (const item of incoming) if (text(item?.id) && !byId.has(item.id)) byId.set(item.id, item);
  return [...byId.values()].sort((left, right) => text(left.at).localeCompare(text(right.at)) || (Number(left.sequence) || 0) - (Number(right.sequence) || 0) || left.id.localeCompare(right.id));
}

export function captureWarnings(snapshot) {
  const capture = snapshot?.capture;
  const warnings = [];
  if (!capture || !capture.status || capture.status === 'unknown') warnings.push('Capture completeness is unknown. Successful refreshes do not prove complete capture.');
  else if (capture.status === 'recording') warnings.push('Capture is still recording; final completeness is not yet known.');
  else if (capture.status === 'incomplete') warnings.push('Capture is incomplete. Some execution activity was not recorded.');
  if (Number(capture?.dropped_count) > 0) warnings.push(`${capture.dropped_count} activity events omitted by the reporter.`);
  if (Number(capture?.delivery_failures) > 0) warnings.push(`${capture.delivery_failures} activity delivery failures recorded.`);
  if (Array.isArray(capture?.sequence_gaps) && capture.sequence_gaps.length) warnings.push(`Recorded sequence gaps: ${capture.sequence_gaps.map((gap) => `${gap.from}–${gap.to}`).join(', ')}.`);
  if (snapshot?.pagination?.has_more ?? snapshot?.has_more) warnings.push('More recorded pages remain; catching up without discarding earlier events.');
  else if (snapshot?.truncated && snapshot?.pagination?.next_cursor === undefined && snapshot?.next_cursor === undefined) warnings.push('This server returned a sliced activity feed; earlier unavailable records are not reconstructed.');
  return warnings;
}

export function stopStateLabel(stop) {
  switch (stop?.state) {
    case 'requested': return 'Stop requested · worker acknowledgment pending';
    case 'acknowledged': return 'Worker acknowledged Stop';
    case 'unreachable': return 'Worker unreachable · Stop is not confirmed';
    case 'deadline_elapsed': return 'Authorization deadline elapsed · worker Stop is not confirmed';
    default: return '';
  }
}

export function activityItemsToEvents(snapshot) {
  return (snapshot?.items ?? []).filter((item) => item.source === 'signed_worker' || item.source === 'simulation').map((item) => ({
    id: item.id, timestamp: item.at, test_run_id: snapshot.run_id, check_id: snapshot.check_id,
    producer_kind: item.source === 'simulation' ? 'internal_simulation' : 'signed_probe',
    signal_type: item.stage === 'result_received' ? 'probe_result' : 'probe_activity',
    metadata: item.stage === 'result_received' ? { ...item, external_result: item.outcome, safety_attestation: { requests_sent: item.requests_sent } }
      : { activity: item, vector_family: item.vector_family, marker_class: item.marker_class },
  }));
}

export const EMPTY_ACTIVITY_STATE = Object.freeze({ snapshot: null, record: null, error: null, lastUpdated: '', updating: false, revision: 0 });

/** Injectable clock/reader are test seams only. No request here can authorize or dispatch work. */
export function createRecordedActivityReader({ kind = 'run', id, read, now = () => new Date().toISOString(), schedule = setTimeout, unschedule = clearTimeout }) {
  let state = { ...EMPTY_ACTIVITY_STATE };
  let cursor = '';
  let failures = 0;
  let finalSweeps = 0;
  let timer;
  let controller;
  let generation = 0;
  let stopped = false;
  let inFlight = false;
  const subscribers = new Set();
  const enabled = () => [...subscribers].some((subscriber) => subscriber.active);
  const publish = (patch) => {
    state = { ...state, ...patch };
    const accessRevoked = [401, 403, 404].includes(Number(patch.error?.status));
    for (const subscriber of subscribers) if (subscriber.active || accessRevoked) subscriber.listener(state);
  };
  const clearTimer = () => { if (timer !== undefined) unschedule(timer); timer = undefined; };
  const invalidate = () => { generation += 1; controller?.abort(); controller = undefined; inFlight = false; clearTimer(); };

  async function poll() {
    if (stopped || !enabled() || inFlight) return;
    inFlight = true;
    const token = ++generation;
    controller = new AbortController();
    const operationController = controller;
    const signal = operationController.signal;
    const timeout = schedule(() => operationController.abort(), 15000);
    const current = () => !stopped && enabled() && generation === token;
    publish({ updating: true });
    let more = false;
    try {
      if (kind === 'scan') {
        const record = await read(`/v1/validation-scans/${encodeURIComponent(id)}?advance=false`, { signal });
        if (!current()) return;
        if (record?.id !== id) throw new Error('Execution identity did not match the selected assessment.');
        publish({ record });
      }
      // Bound each cycle, not the retained transcript. A long assessment resumes at this cursor.
      for (let page = 0; page < 8; page += 1) {
        const incoming = await read(activityPath(kind, id, cursor), { signal });
        if (!current()) return;
        if (text(incoming?.[kind === 'scan' ? 'scan_id' : 'run_id']) !== id) throw new Error('Activity identity did not match the selected execution.');
        const items = mergeActivityItems(state.snapshot?.items, incoming.items);
        const pagination = incoming.pagination ?? incoming;
        more = pagination.has_more === true;
        const nextCursor = text(pagination.next_cursor);
        if (more && (!nextCursor || nextCursor === cursor)) throw new Error('The activity cursor did not advance. Previous recorded events are retained.');
        if (nextCursor) cursor = nextCursor;
        failures = 0;
        publish({ snapshot: { ...incoming, items, retained_count: items.length }, error: null, lastUpdated: now(), revision: state.revision + 1 });
        if (!more) break;
      }
      const live = activityIsLive(kind === 'scan' ? state.record : state.snapshot) || activityIsLive(state.snapshot);
      if (live || more) finalSweeps = 0;
      else finalSweeps += 1;
      // Even an already-finished run gets a second exact read for late/final activity.
      if (live || more || finalSweeps < 2) timer = schedule(poll, ACTIVITY_POLL_MS);
    } catch (error) {
      if (!current()) return;
      failures += 1;
      const status = Number(error?.status);
      const denied = [401, 403, 404].includes(status);
      publish({ error, ...(denied ? { snapshot: null, record: null } : {}) });
      if (![400, 401, 403, 404].includes(status)) timer = schedule(poll, Math.min(ACTIVITY_MAX_BACKOFF_MS, ACTIVITY_POLL_MS * 2 ** failures));
    } finally {
      unschedule(timeout);
      if (generation === token) { inFlight = false; controller = undefined; if (current()) publish({ updating: false }); }
    }
  }

  return {
    getState: () => state,
    subscribe(listener, active = true) {
      const subscriber = { listener, active };
      subscribers.add(subscriber);
      if (active) { listener(state); if (!inFlight && timer === undefined) void poll(); }
      return {
        setActive(value) {
          if (subscriber.active === value) return;
          subscriber.active = value;
          if (value) { listener(state); clearTimer(); if (!inFlight) void poll(); }
          else if (!enabled()) invalidate();
        },
        unsubscribe() { subscribers.delete(subscriber); if (!enabled()) invalidate(); },
      };
    },
    refresh() { finalSweeps = 0; clearTimer(); if (!inFlight) void poll(); },
    dispose() { stopped = true; invalidate(); subscribers.clear(); },
  };
}
