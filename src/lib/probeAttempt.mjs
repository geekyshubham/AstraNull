import { emitProbeActivity } from './probeActivity.mjs';

/**
 * Build the worker's injected pre-I/O reservation callback.
 *
 * The callback is intentionally synchronous: the deadline/cap assertion and logical-attempt
 * reservation both complete before the transport initializer can run. If either throws, the
 * caller must not create a socket or invoke fetch.
 */
export function createProbePreAttempt({ recordProbeLogicalAttempt, assertCanAttempt } = {}) {
  if (typeof recordProbeLogicalAttempt !== 'function') {
    throw new TypeError('recordProbeLogicalAttempt must be a function');
  }
  return (operation) => {
    assertCanAttempt?.();
    recordProbeLogicalAttempt(operation);
  };
}

/**
 * Reserve one logical attempt and immediately initiate its I/O.
 *
 * Production execution injects `beforeProbeIoAttempt`; direct adapter tests may inject the
 * legacy `recordProbeLogicalAttempt` callback. A supplied pre-attempt callback owns recording
 * and MUST synchronously call `recordProbeLogicalAttempt` itself.
 */
export function startProbeIoAttempt(deps, operation, initiate, onReserved) {
  if (typeof initiate !== 'function') throw new TypeError('probe I/O initializer must be a function');
  const beforeAttempt = deps?.beforeProbeIoAttempt ?? deps?.recordProbeLogicalAttempt;
  try {
    beforeAttempt?.(operation);
    onReserved?.();
    const result = initiate();
    return result;
  } catch (error) {
    emitProbeActivity(deps, { stage: 'request_not_sent', operation: String(operation), reason: String(error?.code ?? 'attempt_refused') });
    throw error;
  }
}
