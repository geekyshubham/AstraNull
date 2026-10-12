import { MAX_PROBE_ACTIVITY_ITEMS, MAX_PROBE_ACTIVITY_BATCH, normalizeProbeActivityItem } from '../src/lib/probeActivity.mjs';

/** Metadata capture is bounded. Lost control-plane authority stops work, not just display. */
export function createProbeActivityReporter(job, sendBatch, { onStop, heartbeatMs = 1500, partitionGraceMs = 2500 } = {}) {
  let sequence = 0;
  let closed = false;
  let sending = false;
  let stopped = false;
  let retries = 0;
  let dropped = 0;
  let failures = 0;
  let lastAcknowledgment = Date.now();
  let finalizedAt = null;
  const pending = [];
  let inFlight = Promise.resolve();
  let retryTimer;
  const snapshot = () => ({ version: 'probe-capture.v1', recorded_count: sequence, last_sequence: sequence,
    dropped_count: dropped, delivery_failures: failures, finalized_at: finalizedAt });
  const stop = (reason) => {
    if (stopped || closed) return;
    stopped = true;
    dropped += pending.length;
    pending.length = 0;
    onStop?.({ reason });
  };
  const flush = () => {
    if (closed || stopped || sending) return inFlight;
    sending = true;
    const items = [];
    while (pending.length && items.length < MAX_PROBE_ACTIVITY_BATCH) {
      const candidate = [...items, pending[0]];
      if (Buffer.byteLength(JSON.stringify({ leased_at: job.leased_at, items: candidate, capture: snapshot() })) > 28 * 1024) break;
      items.push(pending.shift());
    }
    const failed = () => {
      failures += 1;
      retries += 1;
      if (retries > 2 || Date.now() - lastAcknowledgment >= partitionGraceMs) {
        dropped += items.length;
        stop('control_plane_unavailable');
      } else pending.unshift(...items);
    };
    inFlight = Promise.resolve().then(() => sendBatch({ leased_at: job.leased_at, items, capture: snapshot() }))
      .then((response) => {
        if ([401, 403, 409].includes(response?.status) || response?.json?.continue === false) {
          failures += 1; dropped += items.length; stop('job_revoked');
        } else if (response?.status >= 200 && response?.status < 300) {
          retries = 0; lastAcknowledgment = Date.now();
        } else failed();
      }).catch(failed)
      .finally(() => {
        sending = false;
        if (pending.length && !closed && !stopped) {
          retryTimer = setTimeout(flush, retries ? Math.min(250, 50 * retries) : 0);
          retryTimer.unref?.();
        }
      });
    return inFlight;
  };
  const heartbeat = setInterval(flush, heartbeatMs);
  heartbeat.unref?.();
  const authorityWatch = setInterval(() => {
    if (!closed && !stopped && Date.now() - lastAcknowledgment >= partitionGraceMs) stop('control_plane_unavailable');
  }, Math.min(500, heartbeatMs));
  authorityWatch.unref?.();
  return {
    snapshot,
    flush,
    record(item) {
      if (closed || stopped) { dropped += 1; return; }
      if (sequence >= MAX_PROBE_ACTIVITY_ITEMS) { dropped += 1; return; }
      const entry = normalizeProbeActivityItem({ ...item, sequence: sequence + 1, at: new Date().toISOString() });
      if (!entry) { dropped += 1; return; }
      sequence += 1; pending.push(entry); flush();
    },
    async close() {
      clearInterval(heartbeat);
      finalizedAt ??= new Date().toISOString();
      let timer;
      const deadline = new Promise((resolve) => {
        timer = setTimeout(() => { stop('control_plane_unavailable'); resolve(); }, partitionGraceMs);
      });
      try {
        await Promise.race([(async () => {
          while ((pending.length || sending) && !stopped) {
            await flush();
            if (retries && !stopped) await new Promise((resolve) => setTimeout(resolve, 50));
          }
          // An empty final batch attests capture closure, not additional probe traffic.
          if (!stopped) await flush();
        })(), deadline]);
      } finally {
        closed = true;
        clearTimeout(timer); clearTimeout(retryTimer); clearInterval(authorityWatch);
      }
      return snapshot();
    },
  };
}
