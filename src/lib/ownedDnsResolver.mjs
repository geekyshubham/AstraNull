import dns from 'node:dns/promises';

function deadlineError() {
  return Object.assign(new Error('Signed probe job deadline elapsed.'), {
    name: 'AbortError', code: 'probe_job_deadline_exceeded',
  });
}

/**
 * One logical DNS operation owns one Resolver, never the process-global resolver.
 * Injected adapters receive a final { signal } argument and must close their own
 * underlying I/O on abort. Legacy immediate-value/promise adapters remain valid;
 * a promise race alone does not establish cancellation of an adapter's resources.
 * The local timer covers direct calls and delayed/missing upstream deadline delivery.
 */
export async function resolveOwnedDns({ method, name, server, resolveFn, timeoutMs, signals = [] }) {
  const controller = new AbortController();
  let resolver; let timer; let rejectAbort;
  const aborted = new Promise((_, reject) => { rejectAbort = reject; });
  // An adapter can abort synchronously and then throw before the race is attached.
  void aborted.catch(() => {});
  const cancel = () => {
    if (controller.signal.aborted) return;
    const error = deadlineError();
    // Settle the boundary with the deadline classification, not native ECANCELLED.
    rejectAbort(error);
    controller.abort(error);
    resolver?.cancel();
  };
  const upstream = [...new Set(signals.filter(Boolean))];
  try {
    if (timeoutMs <= 0 || upstream.some((signal) => signal.aborted)) {
      throw deadlineError();
    }
    for (const signal of upstream) signal.addEventListener('abort', cancel, { once: true });
    timer = setTimeout(cancel, timeoutMs);
    let operation;
    if (resolveFn) {
      operation = server === undefined
        ? resolveFn(name, { signal: controller.signal })
        : resolveFn(server, name, { signal: controller.signal });
    } else {
      resolver = new dns.Resolver();
      if (server !== undefined) resolver.setServers([server]);
      operation = resolver[method](name);
    }
    return await Promise.race([operation, aborted]);
  } finally {
    clearTimeout(timer);
    for (const signal of upstream) signal.removeEventListener('abort', cancel);
  }
}
