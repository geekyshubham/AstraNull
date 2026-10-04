import { MAX_PROBE_ACTIVITY_ITEMS, MAX_PROBE_ACTIVITY_BATCH, normalizeProbeActivityItem } from '../src/lib/probeActivity.mjs';

/** Bounded, batched metadata reporting; heartbeat acknowledgments also observe Stop. */
export function createProbeActivityReporter(job, sendBatch, { onStop, heartbeatMs = 1500 } = {}) {
  let sequence = 0;
  let closed = false;
  let sending = false;
  let stopped = false;
  let retries = 0;
  const pending = [];
  let inFlight = Promise.resolve();
  const flush = () => {
    if (closed || stopped || sending) return inFlight;
    sending = true;
    const items = [];
    while (pending.length && items.length < MAX_PROBE_ACTIVITY_BATCH) {
      const candidate = [...items, pending[0]];
      if (Buffer.byteLength(JSON.stringify({ leased_at: job.leased_at, items: candidate })) > 28 * 1024) break;
      items.push(pending.shift());
    }
    inFlight = Promise.resolve().then(() => sendBatch({ leased_at: job.leased_at, items }))
      .then((response) => {
        if ([401, 403, 409].includes(response?.status)) { stopped = true; onStop?.(); }
        else if ((response?.status >= 500 || response?.status === 429) && retries < 2) { retries += 1; pending.unshift(...items); }
        else retries = 0;
      })
      .catch(() => { if (retries < 2) { retries += 1; pending.unshift(...items); } })
      .finally(() => {
        sending = false;
        if (pending.length && !closed && !stopped) flush();
      });
    return inFlight;
  };
  const heartbeat = setInterval(flush, heartbeatMs);
  heartbeat.unref?.();
  return {
    record(item) {
      if (closed || stopped || sequence >= MAX_PROBE_ACTIVITY_ITEMS) return;
      const entry = normalizeProbeActivityItem({ ...item, sequence: sequence + 1, at: new Date().toISOString() });
      if (!entry) return;
      sequence += 1; pending.push(entry); flush();
    },
    async close() {
      clearInterval(heartbeat);
      const deadline = new Promise((resolve) => { const timer = setTimeout(resolve, 2500); timer.unref?.(); });
      await Promise.race([(async () => {
        while ((pending.length || sending) && !stopped) { await flush(); }
      })(), deadline]);
      closed = true;
    },
  };
}
