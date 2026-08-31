export const EVENT_PRODUCER_KINDS = Object.freeze({
  LEGACY_UNTRUSTED: 'legacy_untrusted',
  PUBLIC_API: 'public_api',
  SIGNED_PROBE: 'signed_probe',
  AUTHENTICATED_AGENT: 'authenticated_agent',
  INTERNAL_SIMULATION: 'internal_simulation',
  INTERNAL_CONTROL_PLANE: 'internal_control_plane',
});

const TRUSTED_PRODUCERS_BY_SIGNAL = new Map([
  ['probe_result', new Set([
    EVENT_PRODUCER_KINDS.SIGNED_PROBE,
    EVENT_PRODUCER_KINDS.INTERNAL_SIMULATION,
  ])],
  ['agent_observation', new Set([
    EVENT_PRODUCER_KINDS.AUTHENTICATED_AGENT,
  ])],
  ['ownership_observation', new Set([
    EVENT_PRODUCER_KINDS.SIGNED_PROBE,
    EVENT_PRODUCER_KINDS.AUTHENTICATED_AGENT,
  ])],
  ['agent_no_observation', new Set([
    EVENT_PRODUCER_KINDS.INTERNAL_CONTROL_PLANE,
  ])],
]);

/**
 * Reserved producer events are authoritative only when their immutable ingestion path says so.
 * Undefined provenance is accepted solely for narrow repository doubles used by unit tests;
 * every persisted runtime row is stamped, and migrations mark historical rows untrusted.
 */
export function isTrustedProducerEvent(event) {
  const allowed = TRUSTED_PRODUCERS_BY_SIGNAL.get(String(event?.signal_type ?? ''));
  if (!allowed) return true;
  if (event?.producer_kind == null) return true;
  return allowed.has(String(event.producer_kind));
}
