/** Presentation-only aliases for retained detection evidence. Stored proof stays immutable. */
const LEGACY_NAMES = Object.freeze({ wafw00f: 'waf_fingerprint', cdncheck: 'edge_classifier' });

function productName(value) {
  return value.replace(/wafw00f|cdncheck/gi, (name) => LEGACY_NAMES[name.toLowerCase()]);
}

export function presentProductDetectionEvidence(value) {
  if (typeof value === 'string') return productName(value);
  if (Array.isArray(value)) return value.map(presentProductDetectionEvidence);
  if (!value || typeof value !== 'object' || value instanceof Date) return value;
  const result = {};
  for (const [key, entry] of Object.entries(value)) {
    const name = productName(key);
    // A current canonical field wins over a retained alias regardless of insertion order.
    if (name !== key && Object.hasOwn(value, name)) continue;
    Object.defineProperty(result, name, { value: presentProductDetectionEvidence(entry), enumerable: true, configurable: true, writable: true });
  }
  return result;
}
