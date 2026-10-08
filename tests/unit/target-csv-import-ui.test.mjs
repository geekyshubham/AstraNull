import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import {
  importTargetCsv,
  normalizeTargetCsvImportResult,
  summarizeTargetCsv,
  TARGET_CSV_FORM_FIELD,
  TARGET_CSV_MAX_BYTES,
  TARGET_CSV_MAX_ROWS,
  targetCsvImportPath,
  validateTargetCsvFile,
} from '../../apps/web/react/src/lib/target-csv-import.ts';

const DEV_CONFIG = { authMode: 'dev-headers' };
const ENGINEER = { principal: 'customer', tenant_id: 'ten_example', user_id: 'usr_example', role: 'engineer' };
const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe('target CSV import helpers', () => {
  it('counts data rows and skips a recognised header', () => {
    assert.deepEqual(summarizeTargetCsv('value,kind\napp.example.com,fqdn\n\n203.0.113.10,ip\n'), {
      rowCount: 2,
      hasHeader: true,
      columns: ['value', 'kind'],
    });
    assert.equal(summarizeTargetCsv('﻿app.example.com\r\nhttps://www.example.com/health\r\n').rowCount, 2);
    assert.equal(summarizeTargetCsv('app.example.com').hasHeader, false);
    assert.equal(summarizeTargetCsv('  \n ').rowCount, 0);
  });

  it('enforces file type, size, and row limits before upload', () => {
    assert.match(validateTargetCsvFile({ name: 'targets.txt', size: 10 }), /\.csv/);
    assert.match(validateTargetCsvFile({ name: 'targets.csv', size: 0 }), /empty/);
    assert.match(validateTargetCsvFile({ name: 'targets.csv', size: TARGET_CSV_MAX_BYTES + 1 }), /limit/);
    assert.match(validateTargetCsvFile({ name: 'targets.csv', size: 10 }, { rowCount: 0, hasHeader: true, columns: [] }), /No target rows/);
    assert.match(
      validateTargetCsvFile({ name: 'targets.csv', size: 10 }, { rowCount: TARGET_CSV_MAX_ROWS + 1, hasHeader: false, columns: [] }),
      /rows per import/,
    );
    assert.equal(validateTargetCsvFile({ name: 'TARGETS.CSV', size: 10 }, { rowCount: 3, hasHeader: false, columns: [] }), '');
  });

  it('normalizes the created/errors response contract', () => {
    assert.deepEqual(
      normalizeTargetCsvImportResult({
        created: [{ id: 'tgt_1' }, null],
        errors: [{ row: 3, error: 'invalid_target_value' }, { row: 'x', message: 'Duplicate target.' }, 'bad row'],
      }),
      {
        created: [{ id: 'tgt_1' }],
        errors: [
          { row: 3, error: 'invalid target value' },
          { row: null, error: 'Duplicate target.' },
          { row: null, error: 'bad row' },
        ],
      },
    );
    assert.deepEqual(normalizeTargetCsvImportResult(null), { created: [], errors: [] });
  });

  it('posts the file as multipart to the direct target CSV endpoint', async () => {
    let captured;
    globalThis.fetch = async (path, init) => {
      captured = { path, init };
      return new Response(JSON.stringify({ created: [{ id: 'tgt_1' }], errors: [{ row: 2, error: 'Invalid IP.' }] }), { status: 201 });
    };
    const file = new File(['value\napp.example.com\n999.1.1.1\n'], 'targets.csv', { type: 'text/csv' });
    const result = await importTargetCsv(DEV_CONFIG, ENGINEER, file);

    assert.equal(captured.path, targetCsvImportPath());
    assert.equal(captured.path, '/v1/targets:csv');
    assert.equal(captured.init.method, 'POST');
    assert.equal(captured.init.headers['Content-Type'], undefined);
    assert.equal(captured.init.headers['x-role'], 'engineer');
    assert.ok(captured.init.body instanceof FormData);
    assert.equal(captured.init.body.get(TARGET_CSV_FORM_FIELD).name, 'targets.csv');
    assert.deepEqual(result, { created: [{ id: 'tgt_1' }], errors: [{ row: 2, error: 'Invalid IP.' }] });
  });

  it('surfaces a friendly error and hides 5xx payloads', async () => {
    globalThis.fetch = async () => new Response(JSON.stringify({ error: 'db_exploded', message: 'relation targets missing' }), { status: 500 });
    const file = new File(['app.example.com'], 'targets.csv');
    await assert.rejects(importTargetCsv(DEV_CONFIG, ENGINEER, file), (err) => {
      assert.equal(err.status, 500);
      assert.equal(err.payload, null);
      assert.doesNotMatch(err.message, /relation/);
      return true;
    });

    globalThis.fetch = async () => new Response(JSON.stringify({ error: 'not_found' }), { status: 404 });
    await assert.rejects(importTargetCsv(DEV_CONFIG, ENGINEER, file), /not available/);
  });

  it('returns per-row errors from an all-or-nothing 422 rejection and explains 413 limits', async () => {
    globalThis.fetch = async () => new Response(JSON.stringify({
      error: 'csv_import_rejected',
      created: [],
      errors: [{ row: 3, error: 'invalid_target_value', field: 'value', message: 'Invalid IP.' }],
    }), { status: 422 });
    const file = new File(['value\napp.example.com\n999.1.1.1\n'], 'targets.csv');
    const result = await importTargetCsv(DEV_CONFIG, ENGINEER, file);
    assert.deepEqual(result.created, []);
    assert.equal(result.errors.length, 1);
    assert.equal(result.errors[0].row, 3);

    globalThis.fetch = async () => new Response(JSON.stringify({ error: 'csv_too_large' }), { status: 413 });
    await assert.rejects(importTargetCsv(DEV_CONFIG, ENGINEER, file), /import limit/);
  });
});
