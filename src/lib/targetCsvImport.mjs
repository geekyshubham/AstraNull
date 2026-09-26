import { isIP } from 'node:net';
import { normalizeTargetInput, targetDedupeKey, TargetValidationError } from '../contracts/targetManagement.mjs';

export const TARGET_CSV_MAX_BYTES = 256 * 1024;
export const TARGET_CSV_MAX_ROWS = 1000;
export const TARGET_CSV_FORM_FIELD = 'file';
export const TARGET_CSV_MULTIPART_OVERHEAD_BYTES = 16 * 1024;
export const TARGET_CSV_COLUMNS = Object.freeze(['kind', 'value', 'expected_behavior']);
const MAX_EXPECTED_BEHAVIOR_LENGTH = 200;
const HEADER_ALIASES = new Map([
  ['kind', 'kind'],
  ['type', 'kind'],
  ['value', 'value'],
  ['target', 'value'],
  ['fqdn', 'value'],
  ['hostname', 'value'],
  ['domain', 'value'],
  ['url', 'value'],
  ['ip', 'value'],
  ['expected_behavior', 'expected_behavior'],
  ['label', null],
  ['name', null],
  ['notes', null],
]);
const VALUE_COLUMN_KIND = new Map([['fqdn', 'fqdn'], ['hostname', 'fqdn'], ['domain', 'fqdn'], ['url', 'url'], ['ip', 'ip']]);
const HEADERLESS_LAYOUTS = new Map([
  [1, ['value']],
  [2, ['kind', 'value']],
  [3, ['kind', 'value', 'expected_behavior']],
]);

function inferTargetKind(value) {
  if (isIP(value)) return 'ip';
  if (/^https?:\/\//i.test(value)) return 'url';
  return 'fqdn';
}

function csvRejection(message, errors = []) {
  return { error: 'invalid_csv', status: 400, message, created: [], errors };
}

function splitCsvRecords(text) {
  const records = [];
  let field = '';
  let record = [];
  let quoted = false;
  let line = 1;
  let recordLine = 1;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (quoted) {
      if (char === '"' && text[index + 1] === '"') {
        field += '"';
        index += 1;
      } else if (char === '"') {
        quoted = false;
      } else {
        if (char === '\n') line += 1;
        field += char;
      }
      continue;
    }
    if (char === '"' && field === '') {
      quoted = true;
    } else if (char === ',') {
      record.push(field);
      field = '';
    } else if (char === '\n' || char === '\r') {
      if (char === '\r' && text[index + 1] === '\n') index += 1;
      record.push(field);
      records.push({ line: recordLine, fields: record });
      record = [];
      field = '';
      line += 1;
      recordLine = line;
    } else {
      field += char;
    }
  }
  if (quoted) return { error: `Unterminated quoted field starting on line ${recordLine}.` };
  if (field !== '' || record.length > 0) {
    record.push(field);
    records.push({ line: recordLine, fields: record });
  }
  return { records: records.filter((entry) => entry.fields.some((value) => value.trim() !== '')) };
}

export function parseTargetCsv(input) {
  if (typeof input !== 'string' || input.trim() === '') {
    return csvRejection('CSV body is empty. Provide at least one target row.');
  }
  if (Buffer.byteLength(input, 'utf8') > TARGET_CSV_MAX_BYTES) {
    return { ...csvRejection(`CSV exceeds ${TARGET_CSV_MAX_BYTES} bytes.`), error: 'csv_too_large', status: 413 };
  }
  const split = splitCsvRecords(input.replace(/^\uFEFF/, ''));
  if (split.error) return csvRejection(split.error);
  const [first] = split.records;
  if (!first) return csvRejection('CSV body is empty. Provide at least one target row.');
  const firstCells = first.fields.map((name) => name.trim().toLowerCase());
  const hasHeader = firstCells.some((name) => HEADER_ALIASES.has(name) || name === 'port');
  let columns;
  let defaultKind = null;
  let dataRecords;
  if (hasHeader) {
    const unknown = firstCells.filter((name) => !HEADER_ALIASES.has(name));
    if (unknown.includes('port')) {
      return csvRejection('A separate port column is not supported. Use kind "tcp" with value "host:port".');
    }
    if (unknown.length) {
      return csvRejection(`Unsupported CSV columns: ${unknown.join(', ')}. Allowed: ${[...HEADER_ALIASES.keys()].join(', ')}.`);
    }
    columns = firstCells.map((name) => HEADER_ALIASES.get(name));
    const mapped = columns.filter(Boolean);
    if (new Set(mapped).size !== mapped.length) return csvRejection('CSV header maps more than one column to the same field.');
    if (!mapped.includes('value')) return csvRejection('CSV header must include a value column.');
    defaultKind = VALUE_COLUMN_KIND.get(firstCells[columns.indexOf('value')]) ?? null;
    dataRecords = split.records.slice(1);
  } else {
    columns = HEADERLESS_LAYOUTS.get(first.fields.length);
    if (!columns) {
      return csvRejection('Without a header row, use one column (value), two (kind,value), or three (kind,value,expected_behavior).');
    }
    dataRecords = split.records;
  }
  if (dataRecords.length === 0) return csvRejection('CSV has a header but no target rows.');
  if (dataRecords.length > TARGET_CSV_MAX_ROWS) {
    return { ...csvRejection(`CSV has ${dataRecords.length} rows; the limit is ${TARGET_CSV_MAX_ROWS}.`), error: 'csv_too_many_rows', status: 413 };
  }
  const rows = [];
  const errors = [];
  for (const record of dataRecords) {
    if (record.fields.length !== columns.length) {
      errors.push({ row: record.line, error: 'invalid_csv_row', message: `Expected ${columns.length} columns, found ${record.fields.length}.` });
      continue;
    }
    const entry = {};
    columns.forEach((name, index) => {
      if (name) entry[name] = record.fields[index].trim();
    });
    rows.push({
      row: record.line,
      kind: entry.kind || defaultKind || inferTargetKind(entry.value ?? ''),
      value: entry.value ?? '',
      expected_behavior: entry.expected_behavior ? entry.expected_behavior : null,
    });
  }
  return { rows, errors };
}

/** Validates parsed rows with the single-target rules; existingKeys are targetDedupeKey values already in the group. */
export function validateTargetImportRows(rows, existingKeys = new Set()) {
  const accepted = [];
  const errors = [];
  const seen = new Map();
  for (const row of rows) {
    let normalized;
    try {
      normalized = normalizeTargetInput({ kind: row.kind, value: row.value });
    } catch (error) {
      if (!(error instanceof TargetValidationError)) throw error;
      errors.push({ row: row.row, error: error.code, field: error.field, message: error.message });
      continue;
    }
    if (row.expected_behavior && row.expected_behavior.length > MAX_EXPECTED_BEHAVIOR_LENGTH) {
      errors.push({ row: row.row, error: 'invalid_target', field: 'expected_behavior', message: `expected_behavior must be at most ${MAX_EXPECTED_BEHAVIOR_LENGTH} characters.` });
      continue;
    }
    const key = targetDedupeKey(normalized);
    if (existingKeys.has(key)) {
      errors.push({ row: row.row, error: 'target_exists', field: 'value', message: `${normalized.value} is already declared in this target group.` });
      continue;
    }
    if (seen.has(key)) {
      errors.push({ row: row.row, error: 'duplicate_row', field: 'value', message: `${normalized.value} duplicates row ${seen.get(key)}.` });
      continue;
    }
    seen.set(key, row.row);
    accepted.push({ row: row.row, normalized, expected_behavior: row.expected_behavior });
  }
  return { accepted, errors };
}

export function csvImportRejected(errors) {
  return {
    error: 'csv_import_rejected',
    status: 422,
    message: 'No targets were imported. Fix the listed rows and resubmit the whole file.',
    created: [],
    errors,
  };
}

function multipartBoundary(contentType) {
  const match = /boundary=(?:"([^"]+)"|([^;\s]+))/i.exec(String(contentType ?? ''));
  return match ? match[1] ?? match[2] : null;
}

/** Extracts one text field from a multipart/form-data body; returns null when absent. */
export function extractMultipartField(rawBody, contentType, fieldName = TARGET_CSV_FORM_FIELD) {
  const boundary = multipartBoundary(contentType);
  if (!boundary) return { error: 'invalid_multipart', status: 400, message: 'multipart/form-data body is missing its boundary.' };
  const delimiter = `--${boundary}`;
  for (const part of String(rawBody).split(delimiter).slice(1)) {
    if (part.startsWith('--')) break;
    const headerEnd = part.indexOf('\r\n\r\n');
    if (headerEnd < 0) continue;
    const headers = part.slice(0, headerEnd);
    const disposition = /content-disposition:[^\r\n]*/i.exec(headers)?.[0] ?? '';
    const name = /\bname="([^"]*)"/i.exec(disposition)?.[1];
    if (name !== fieldName) continue;
    return { value: part.slice(headerEnd + 4).replace(/\r\n$/, '') };
  }
  return { error: 'invalid_csv', status: 400, message: `multipart/form-data body must include a "${fieldName}" file field.` };
}
