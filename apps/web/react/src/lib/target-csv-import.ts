import { buildApiHeaders } from './portal-auth-policy.mjs';
import type { DataItem, PortalConfig, Session } from './types';

export const TARGET_CSV_MAX_BYTES = 256 * 1024;
export const TARGET_CSV_MAX_ROWS = 1000;
export const TARGET_CSV_FORM_FIELD = 'file';

// Mirrors src/lib/targetCsvImport.mjs HEADER_ALIASES (+ port). Kept in sync by
// tests/unit/target-csv-import.test.mjs, which compares both classifiers.
const HEADER_CELLS = new Set(['kind', 'type', 'value', 'target', 'fqdn', 'hostname', 'domain', 'url', 'ip', 'expected_behavior', 'label', 'name', 'notes', 'port']);
// Header aliases that are also valid target kinds; a first cell like `fqdn` alone is ambiguous.
const KIND_ALIAS_CELLS = new Set(['fqdn', 'hostname', 'domain', 'url', 'ip']);

/**
 * Same rule as the server: a header when the first cell is a header-only alias, or every cell is a
 * known alias. `fqdn,api.example.com` is therefore a headerless kind,value data row.
 */
export function csvFirstRowIsHeader(cells: string[]): boolean {
  if (cells.length === 0) return false;
  const firstIsHeaderOnly = HEADER_CELLS.has(cells[0]) && !KIND_ALIAS_CELLS.has(cells[0]);
  return firstIsHeaderOnly || cells.every((cell) => HEADER_CELLS.has(cell));
}

export type TargetCsvSummary = {
  rowCount: number;
  hasHeader: boolean;
  columns: string[];
};

export type TargetCsvRowError = { row: number | null; error: string };

export type TargetCsvImportResult = {
  created: DataItem[];
  errors: TargetCsvRowError[];
};

function splitCsvCells(line: string) {
  return line.split(',').map((cell) => cell.trim().replace(/^"(.*)"$/, '$1').trim());
}

export function summarizeTargetCsv(text: string): TargetCsvSummary {
  const lines = text.replace(/^﻿/, '').split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (lines.length === 0) return { rowCount: 0, hasHeader: false, columns: [] };
  const firstCells = splitCsvCells(lines[0]).map((cell) => cell.toLowerCase());
  const hasHeader = csvFirstRowIsHeader(firstCells);
  return {
    rowCount: hasHeader ? lines.length - 1 : lines.length,
    hasHeader,
    columns: hasHeader ? firstCells : []
  };
}

export function validateTargetCsvFile(file: Pick<File, 'name' | 'size'>, summary?: TargetCsvSummary): string {
  if (!/\.csv$/i.test(file.name)) return 'Choose a .csv file.';
  if (file.size === 0) return 'The selected file is empty.';
  if (file.size > TARGET_CSV_MAX_BYTES) {
    return `The file is ${Math.ceil(file.size / 1024)} KB. The limit is ${TARGET_CSV_MAX_BYTES / 1024} KB; split it into smaller files.`;
  }
  if (summary && summary.rowCount === 0) return 'No target rows were found in the file.';
  if (summary && summary.rowCount > TARGET_CSV_MAX_ROWS) {
    return `The file has ${summary.rowCount} rows. The limit is ${TARGET_CSV_MAX_ROWS} rows per import.`;
  }
  return '';
}

function normalizeRowError(entry: unknown): TargetCsvRowError {
  if (entry && typeof entry === 'object') {
    const record = entry as { row?: unknown; error?: unknown; message?: unknown };
    const row = Number(record.row);
    const detail = typeof record.message === 'string' && record.message.trim() ? record.message : record.error;
    return {
      row: Number.isFinite(row) ? row : null,
      error: typeof detail === 'string' && detail.trim() ? detail.trim().replace(/^([a-z][a-z0-9_]+)$/, (code) => code.replace(/_/g, ' ')) : 'Row rejected.'
    };
  }
  return { row: null, error: typeof entry === 'string' && entry.trim() ? entry.trim() : 'Row rejected.' };
}

export function normalizeTargetCsvImportResult(payload: unknown): TargetCsvImportResult {
  const record = payload && typeof payload === 'object' ? payload as { created?: unknown; errors?: unknown } : {};
  return {
    created: Array.isArray(record.created) ? record.created.filter((item): item is DataItem => Boolean(item) && typeof item === 'object') : [],
    errors: Array.isArray(record.errors) ? record.errors.map(normalizeRowError) : []
  };
}

export function targetCsvImportPath(targetGroupId: string) {
  return `/v1/target-groups/${encodeURIComponent(targetGroupId)}/targets:csv`;
}

export async function importTargetCsv(
  config: PortalConfig,
  session: Session,
  targetGroupId: string,
  file: File
): Promise<TargetCsvImportResult> {
  const headers = buildApiHeaders(config, session);
  delete headers['Content-Type'];
  const body = new FormData();
  body.append(TARGET_CSV_FORM_FIELD, file, file.name);
  const response = await fetch(targetCsvImportPath(targetGroupId), { method: 'POST', headers, body });
  const payload = await response.json().catch(() => null);
  if (response.status === 422 && Array.isArray((payload as { errors?: unknown } | null)?.errors)) {
    return { ...normalizeTargetCsvImportResult(payload), created: [] };
  }
  if (!response.ok) {
    const message = response.status === 404
      ? 'CSV import is not available for this target group on this deployment.'
      : response.status === 413
        ? 'The CSV exceeds the import limit (256 KB or 1,000 rows). Split it and try again.'
        : response.status >= 500
          ? 'Something went wrong on the server. Try again.'
          : `CSV import failed (${response.status}).`;
    const error = new Error(message) as Error & { status?: number; payload?: unknown };
    error.status = response.status;
    error.payload = response.status >= 500 ? null : payload;
    throw error;
  }
  return normalizeTargetCsvImportResult(payload);
}
