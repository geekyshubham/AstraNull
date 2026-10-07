// Mirrors the plan's expectation_conflicts shape from src/lib/entryPathComparison.mjs: one entry per conflicting path.

const LAYER_NAMES = Object.freeze({ waf: 'WAF', cdn_edge: 'CDN / edge', network_firewall: 'Network firewall', ddos: 'DDoS' });

function text(value) {
  return typeof value === 'string' ? value.trim() : '';
}

export function parseExpectationConflicts(value) {
  if (!Array.isArray(value)) return [];
  const out = [];
  for (const entry of value) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
    const entryPathId = text(entry.entry_path_id);
    const conflicts = Array.isArray(entry.conflicts) ? entry.conflicts.map(text).filter(Boolean) : [];
    if (entryPathId && conflicts.length) out.push({ entry_path_id: entryPathId, conflicts });
  }
  return out;
}

export function expectationConflictLabel(code) {
  const value = text(code);
  const [kind, layer] = value.split(':');
  const layerName = LAYER_NAMES[layer] ?? layer ?? '';
  if (kind === 'required_layer_not_enforced') return `Declared required layer ${layerName} is not expected to enforce`;
  if (kind === 'unreachable_path_allows') return `Path declared not reachable, but ${layerName} is expected to allow`;
  if (kind === 'anchor_mismatch') return 'Expectation belongs to a different application';
  return value.replace(/_/g, ' ');
}
