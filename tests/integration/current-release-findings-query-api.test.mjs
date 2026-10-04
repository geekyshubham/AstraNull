import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { it } from 'node:test';
import { loadRuntimeConfig } from '../../src/config.mjs';
import { createServer } from '../../src/server.mjs';
import { closeServer, demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

it('rejects unknown, internal, and duplicate findings filters before reading the list', async () => {
  freshStore();
  const env = { ...process.env, ASTRANULL_NO_PERSIST: '1', ASTRANULL_RATE_LIMIT_DISABLED: '1' };
  let reads = 0;
  const server = createServer({
    env, runtimeConfig: loadRuntimeConfig(env),
    services: { findings: { async listFindingsEnvelope() {
      reads += 1;
      return { items: [], count: 0, total: 0, meta: {} };
    } } },
  });
  server.listen(0);
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    for (const [query, code, field] of [
      ['owner=team', 'unknown_query_param', 'owner'],
      ['client=untrusted', 'unknown_query_param', 'client'],
      ['status=open&status=closed', 'invalid_query_value', 'status'],
      ['status=&status=closed', 'invalid_query_value', 'status'],
      ['limit=1&limit=50', 'invalid_query_value', 'limit'],
    ]) {
      const result = await request(base, 'GET', `/v1/findings?${query}`, { headers: demoHeaders() });
      assert.equal(result.status, 400, query);
      assert.equal(result.json.error, code, query);
      assert.equal(result.json.field, field, query);
    }
    assert.equal(reads, 0);
    const valid = await request(base, 'GET', '/v1/findings?status=all&limit=1&page=1', { headers: demoHeaders() });
    assert.equal(valid.status, 200);
    assert.equal(reads, 1);
  } finally {
    await closeServer(server);
  }
});
