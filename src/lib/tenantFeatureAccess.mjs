/**
 * Feature surfaces are always on: no tenant is gated behind a flag or allow-list.
 * The runtime-config arguments are kept so callers do not change.
 */
export function wafPostureEnabledFor() {
  return true;
}

export function connectorsEnabledFor() {
  return true;
}

export function externalDiscoveryEnabledFor() {
  return true;
}

export function protectionValidationEnabledFor() {
  return true;
}
