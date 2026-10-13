export const CUSTODY_SCHEMA_VERSION = 'astranull.custody.v1';
export const CUSTODY_CONTENT_CANONICALIZATION = 'json-key-sorted-v1';

function normalizeForCustody(value: unknown): unknown {
  if (value === null || value === undefined) return null;
  if (Array.isArray(value)) return value.map((item) => normalizeForCustody(item));
  if (typeof value !== 'object') return value;
  const record = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(record).sort()) {
    if (record[key] === undefined) continue;
    out[key] = normalizeForCustody(record[key]);
  }
  return out;
}

function stringifyCanonical(value: unknown): string {
  if (value === null) return 'null';
  const kind = typeof value;
  if (kind === 'string' || kind === 'boolean' || kind === 'number') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stringifyCanonical(item)).join(',')}]`;
  }
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stringifyCanonical(record[key])}`).join(',')}}`;
}

export function canonicalJsonStringifyForCustody(value: unknown) {
  return stringifyCanonical(normalizeForCustody(value));
}

export const CUSTODY_DIGEST_UNAVAILABLE_MESSAGE =
  'SHA-256 fingerprinting is unavailable: this browser does not expose Web Crypto (crypto.subtle). Open the portal over HTTPS in a current browser and try again.';

export async function sha256HexBytes(bytes: ArrayBuffer | Uint8Array) {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error(CUSTODY_DIGEST_UNAVAILABLE_MESSAGE);
  const input = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const digest = await subtle.digest('SHA-256', input as Uint8Array<ArrayBuffer>);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

export async function sha256Hex(text: string) {
  return sha256HexBytes(new TextEncoder().encode(text));
}

export async function sha256CanonicalJsonForCustody(value: unknown) {
  return sha256Hex(canonicalJsonStringifyForCustody(value));
}

export async function buildEvidenceCustodyManifest(payload: Record<string, unknown>, tenantId?: string) {
  const digest = await sha256CanonicalJsonForCustody(payload);
  return {
    schema_version: CUSTODY_SCHEMA_VERSION,
    artifact_type: 'evidence_chain_export',
    format: 'json',
    content_sha256: digest,
    content_canonicalization: CUSTODY_CONTENT_CANONICALIZATION,
    created_at: String(payload.exported_at ?? new Date().toISOString()),
    created_by: 'react_portal_export',
    tenant_id: tenantId ?? null,
    subject_ids: [...new Set((Array.isArray(payload.evidence_ids) ? payload.evidence_ids as string[] : []).filter(Boolean))].sort()
  };
}