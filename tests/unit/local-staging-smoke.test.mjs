import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import {
  buildDevHeaders,
  runLocalStagingValidationLoopSmoke,
} from '../../scripts/local-staging-smoke.mjs';

const originalFetch = globalThis.fetch;

function jsonResponse(status, body) {
  return {
    status,
    async text() {
      return JSON.stringify(body);
    },
  };
}

function installFetchQueue(queue, calls) {
  globalThis.fetch = async (url, options = {}) => {
    const next = queue.shift();
    if (!next) throw new Error(`unexpected fetch ${url}`);
    const actual = new URL(String(url));
    const method = options.method ?? 'GET';
    calls.push({
      method,
      path: `${actual.pathname}${actual.search}`,
      headers: options.headers ?? {},
      body: options.body ? JSON.parse(options.body) : undefined,
    });
    assert.equal(method, next.method);
    assert.equal(`${actual.pathname}${actual.search}`, next.path);
    if (next.assertBody) next.assertBody(calls.at(-1).body);
    return jsonResponse(next.status, next.body);
  };
}

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe('local staging smoke', () => {
  it('runs the safe validation loop and verifies report custody', async () => {
    const calls = [];
    const headers = buildDevHeaders();
    const queue = [
      {
        method: 'GET',
        path: '/v1/test-runs',
        status: 200,
        body: { items: [] },
      },
      {
        method: 'POST',
        path: '/v1/test-runs',
        status: 201,
        assertBody(body) {
          assert.equal(body.check_id, 'origin.leak_scan.safe');
          assert.equal(body.target_group_id, 'tg_demo_origin');
          assert.equal(body.target_id, 'tgt_demo_1');
        },
        body: {
          run: {
            id: 'run_1',
            status: 'collecting',
            correlation: { nonce_hash: 'nonce_hash_1' },
          },
        },
      },
      {
        method: 'GET',
        path: '/ready',
        status: 200,
        body: { probe_mode: 'simulation' },
      },
      {
        method: 'GET',
        path: '/v1/test-runs/run_1',
        status: 200,
        body: { id: 'run_1', status: 'verdicted', verdict: { verdict: 'edge_exposed', confidence: 'external_only' } },
      },
      {
        method: 'GET',
        path: '/v1/test-runs/run_1/events',
        status: 200,
        body: { items: [{ signal_type: 'probe_result' }] },
      },
      {
        method: 'GET',
        path: '/v1/findings',
        status: 200,
        body: { items: [{ id: 'finding_1', test_run_id: 'run_1' }] },
      },
      {
        method: 'POST',
        path: '/v1/reports',
        status: 201,
        body: { id: 'report_1', summary: { readiness_score: 67 } },
      },
      {
        method: 'GET',
        path: '/v1/reports/report_1/export?format=json',
        status: 200,
        body: {
          payload: { verdicts: [{ test_run_id: 'run_1' }] },
          custody: { artifact_type: 'report_export', content_sha256: 'sha256' },
        },
      },
    ];
    installFetchQueue(queue, calls);

    const result = await runLocalStagingValidationLoopSmoke('http://127.0.0.1:3000', headers);

    assert.equal(result.run_id, 'run_1');
    assert.equal(result.report_id, 'report_1');
    assert.equal(result.verdict, 'edge_exposed');
    assert.equal(queue.length, 0);
    assert.ok(calls.every((call) => !call.path.startsWith('/v1/agents') && !call.path.startsWith('/v1/bootstrap-tokens')));
    assert.ok(result.checks.includes('report_export_custody'));
  });
});
