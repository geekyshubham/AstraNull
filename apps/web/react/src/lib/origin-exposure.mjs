export const ORIGIN_IMPORT_MAX_BYTES = 128 * 1024;
export const ORIGIN_IMPORT_MAX_RECORDS = 200;

export const ORIGIN_CLUE_SOURCE_LABELS = Object.freeze({
  current_dns: 'Current DNS',
  dns_a: 'DNS A',
  dns_aaaa: 'DNS AAAA',
  dns_cname: 'DNS CNAME',
  dns_mx: 'DNS MX association',
  dns_spf: 'DNS SPF association',
  dns_txt: 'DNS TXT association',
  historical_dns: 'Historical DNS import',
  certificate_host: 'Certificate host-index import',
  trickest_csv: 'Trickest certificate-index import',
});

export function originClueSourceLabel(value) {
  return Object.hasOwn(ORIGIN_CLUE_SOURCE_LABELS, value) ? ORIGIN_CLUE_SOURCE_LABELS[value] : 'Imported association';
}

export function originCluesErrorState(error) {
  const code = error?.payload?.error;
  if (code === 'origin_clues_feature_disabled') return 'disabled';
  if (error?.status === 403 || code === 'forbidden') return 'forbidden';
  if (error?.status === 404 && code === 'not_found') return 'unsupported';
  return 'error';
}

export function originClueImportBody({ sourceKind, sourceRef, content }) {
  if (!['historical_dns', 'certificate_host', 'trickest_csv'].includes(sourceKind)) throw new Error('Choose a supported record source.');
  if (typeof sourceRef !== 'string' || !sourceRef.trim() || sourceRef.trim().length > 512) throw new Error('Add a source reference of up to 512 characters. It is recorded, never fetched.');
  if (typeof content !== 'string' || !content.trim()) throw new Error('Choose a non-empty records file.');
  if (new TextEncoder().encode(content).byteLength > ORIGIN_IMPORT_MAX_BYTES) throw new Error('The file exceeds the 128 KiB import limit.');
  const body = { source_kind: sourceKind, source_ref: sourceRef.trim() };
  const bounded = (payload) => {
    if (new TextEncoder().encode(JSON.stringify(payload)).byteLength > ORIGIN_IMPORT_MAX_BYTES) throw new Error('The complete import request exceeds 128 KiB. Use a smaller records file.');
    return payload;
  };
  if (sourceKind === 'trickest_csv') return bounded({ ...body, csv: content });
  let records;
  try { records = JSON.parse(content); } catch { throw new Error('The file must contain a JSON array of records.'); }
  if (!Array.isArray(records) || records.length < 1 || records.length > ORIGIN_IMPORT_MAX_RECORDS) throw new Error('Import between 1 and 200 records in a JSON array.');
  if (records.some((row) => !row || typeof row !== 'object' || Array.isArray(row))) throw new Error('Each imported record must be an object.');
  return bounded({ ...body, records });
}

export function originCluesPage(payload, targetId) {
  if (!payload || payload.target_id !== targetId || payload.enabled !== true || !Array.isArray(payload.items)) throw new Error('Origin associations did not match this target. No other target’s data was substituted.');
  if (payload.items.some((row) => !row || typeof row !== 'object' || row.target_id !== targetId || typeof row.id !== 'string')) throw new Error('Origin associations returned an invalid or out-of-scope record.');
  return payload;
}
