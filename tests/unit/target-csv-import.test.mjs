import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  extractMultipartField,
  parseTargetCsv,
  TARGET_CSV_MAX_BYTES,
  validateTargetImportRows,
} from '../../src/lib/targetCsvImport.mjs';

describe('target CSV parsing', () => {
  it('parses quoted fields, CRLF, BOM, and header aliases', () => {
    const parsed = parseTargetCsv('﻿type,target,expected_behavior\r\nfqdn,"a.example.com","must, block"\r\n\r\nurl,https://b.example.com/x,\r\n');
    assert.deepEqual(parsed.errors, []);
    assert.deepEqual(parsed.rows, [
      { row: 2, kind: 'fqdn', value: 'a.example.com', expected_behavior: 'must, block' },
      { row: 4, kind: 'url', value: 'https://b.example.com/x', expected_behavior: null },
    ]);
  });

  it('uses the value column name as the default kind and ignores label columns', () => {
    const parsed = parseTargetCsv('ip,label\n192.0.2.1,edge\n');
    assert.deepEqual(parsed.rows, [{ row: 2, kind: 'ip', value: '192.0.2.1', expected_behavior: null }]);
  });

  it('supports headerless layouts and rejects ambiguous ones', () => {
    assert.deepEqual(parseTargetCsv('tcp,a.example.com:443\n').rows, [
      { row: 1, kind: 'tcp', value: 'a.example.com:443', expected_behavior: null },
    ]);
    assert.equal(parseTargetCsv('a,b,c,d\n').error, 'invalid_csv');
  });

  it('accepts a headerless kind,value row whose first cell is also a header alias (finding 2)', () => {
    // `fqdn` is a valid header alias AND a valid kind. A data row `fqdn,api.example.com` must be
    // read as kind=fqdn,value=api.example.com, not mistaken for a header (which rejected the value).
    assert.deepEqual(parseTargetCsv('fqdn,api.example.com\n').rows, [
      { row: 1, kind: 'fqdn', value: 'api.example.com', expected_behavior: null },
    ]);
    assert.equal(parseTargetCsv('fqdn,api.example.com\n').errors.length, 0);
    // A genuine all-known header row still parses as a header.
    assert.deepEqual(parseTargetCsv('kind,value\nfqdn,b.example.com\n').rows, [
      { row: 2, kind: 'fqdn', value: 'b.example.com', expected_behavior: null },
    ]);
    // A header-only first cell (never a valid kind) with an unknown column is still a header, so it
    // rejects the unknown column rather than silently treating it as data.
    const unknownCol = parseTargetCsv('value,owner\ncsv-f.example.com,alice\n');
    assert.equal(unknownCol.error, 'invalid_csv');
    assert.equal(unknownCol.status, 400);
    assert.match(unknownCol.message, /Unsupported CSV columns: owner/);
  });

  it('reports ragged rows, unterminated quotes, port columns, and size limits', () => {
    assert.deepEqual(parseTargetCsv('kind,value\nfqdn\n').errors.map((entry) => entry.row), [2]);
    assert.equal(parseTargetCsv('value\n"a.example.com\n').error, 'invalid_csv');
    assert.match(parseTargetCsv('value,port\na.example.com,443\n').message, /host:port/);
    assert.equal(parseTargetCsv(`value\n${'a'.repeat(TARGET_CSV_MAX_BYTES)}\n`).error, 'csv_too_large');
  });

  it('validates rows with single-target rules and dedupes against existing and in-file targets', () => {
    const { accepted, errors } = validateTargetImportRows(
      [
        { row: 2, kind: 'fqdn', value: 'A.Example.com', expected_behavior: null },
        { row: 3, kind: 'fqdn', value: 'a.example.com.', expected_behavior: null },
        { row: 4, kind: 'fqdn', value: 'taken.example.com', expected_behavior: null },
        { row: 5, kind: 'bogus', value: 'x', expected_behavior: null },
      ],
      new Set(['fqdn\u0000taken.example.com']),
    );
    assert.deepEqual(accepted.map((entry) => entry.normalized.value), ['a.example.com']);
    assert.deepEqual(errors.map((entry) => [entry.row, entry.error]), [
      [3, 'duplicate_row'],
      [4, 'target_exists'],
      [5, 'invalid_target'],
    ]);
  });

  it('client preview agrees with the server on header detection', async () => {
    const { summarizeTargetCsv } = await import('../../apps/web/react/src/lib/target-csv-import.ts');
    const cases = [
      'fqdn,api.example.com\n',
      'fqdn,a.example.com\nfqdn,b.example.com\n',
      'value,owner\ncsv-f.example.com,alice\n',
      'kind,value\nfqdn,b.example.com\n',
      'ip,label\n192.0.2.1,edge\n',
      'tcp,a.example.com:443\n',
      'a.example.com\nb.example.com\n',
    ];
    for (const csv of cases) {
      const server = parseTargetCsv(csv);
      // The server either returns rows (first data row is 2 when a header was consumed) or rejects
      // a header's unknown column.
      const serverHeader = server.rows ? server.rows[0].row === 2 : /Unsupported CSV columns/.test(server.message ?? '');
      const client = summarizeTargetCsv(csv);
      assert.equal(client.hasHeader, serverHeader, `header mismatch for ${JSON.stringify(csv)}`);
      if (server.rows) assert.equal(client.rowCount, server.rows.length + server.errors.length, `row count for ${JSON.stringify(csv)}`);
    }
  });

  it('extracts the named multipart file field', () => {
    const body = '--b1\r\nContent-Disposition: form-data; name="other"\r\n\r\nx\r\n--b1\r\nContent-Disposition: form-data; name="file"; filename="t.csv"\r\nContent-Type: text/csv\r\n\r\nvalue\na.example.com\r\n--b1--\r\n';
    assert.deepEqual(extractMultipartField(body, 'multipart/form-data; boundary=b1'), { value: 'value\na.example.com' });
    assert.equal(extractMultipartField(body, 'multipart/form-data').error, 'invalid_multipart');
    assert.equal(extractMultipartField(body, 'multipart/form-data; boundary=b1', 'missing').error, 'invalid_csv');
  });
});
