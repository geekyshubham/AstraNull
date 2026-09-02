function normalizedRouteKey(value) {
  return String(value ?? '').trim();
}

/**
 * Track the active route and latest payload generation. Route activation invalidates in-flight
 * work immediately, before React has to render the newly selected route.
 */
export function createPayloadCommitGate(initialRouteKey = '') {
  let activeRouteKey = normalizedRouteKey(initialRouteKey);
  let generation = 0;

  return {
    activate(routeKey) {
      const nextRouteKey = normalizedRouteKey(routeKey);
      if (nextRouteKey !== activeRouteKey) {
        activeRouteKey = nextRouteKey;
        generation += 1;
      }
      return generation;
    },
    begin(routeKey) {
      const nextRouteKey = normalizedRouteKey(routeKey);
      if (nextRouteKey !== activeRouteKey) {
        activeRouteKey = nextRouteKey;
        generation += 1;
      }
      generation += 1;
      return Object.freeze({ generation, routeKey: nextRouteKey });
    },
    isCurrent(ticket) {
      return Boolean(
        ticket
        && ticket.generation === generation
        && ticket.routeKey === activeRouteKey,
      );
    },
  };
}

/**
 * Commit only the newest request for the active route. The same ticket guards successful data,
 * load errors, and final settlement so no stale cross-route response can mutate portal state.
 */
export async function runGenerationKeyedPayload({
  gate,
  routeKey,
  load,
  onCommit,
  onError,
  onSettled,
}) {
  const ticket = gate.begin(routeKey);
  const isCurrent = () => gate.isCurrent(ticket);
  try {
    const payload = await load(isCurrent);
    if (!isCurrent()) return false;
    onCommit(payload);
    return true;
  } catch (error) {
    if (!isCurrent()) return false;
    onError(error);
    return true;
  } finally {
    if (isCurrent()) onSettled?.();
  }
}
