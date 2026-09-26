import { incMetric } from '../lib/metrics.mjs';

const hooks = new Set();

export function registerRunTerminalHook(hook) {
  if (typeof hook !== 'function') throw new TypeError('registerRunTerminalHook requires a function.');
  hooks.add(hook);
  return () => hooks.delete(hook);
}

export function clearRunTerminalHooks() {
  hooks.clear();
}

export function notifyRunTerminal(run, context = {}) {
  if (!run) return;
  for (const hook of hooks) {
    try {
      hook(run, context);
    } catch {
      incMetric('run_terminal_hook_failed');
    }
  }
}
