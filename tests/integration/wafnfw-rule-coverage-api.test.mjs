import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { loadRuntimeConfig } from '../../src/config.mjs';
import { createServer } from '../../src/server.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { closeServer, demoHeaders, request } from '../helpers/http.mjs';

const envSnapshot = { ...process.env };

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in envSnapshot)) delete process.env[key];
  }
  Object.assign(process.env, envSnapshot);
}

function testEnv() {
  return { ...process.env, ASTRANULL_NO_PERSIST: '1' };
}

describe('rule-coverage API', () => {
  let server;
  let baseUrl;

  before(() => {
    Object.assign(process.env, testEnv());
    freshStore();
    const runtimeConfig = loadRuntimeConfig(testEnv());
    server = createServer({ runtimeConfig, env: testEnv() });
    server.listen(0);
    baseUrl = `http://127.0.0.1:${server.address().port}`;
  });

  after(async () => {
    await closeServer(server);
    restoreEnv();
  });

  it('returns catalog coverage to a tenant reader', async () => {
    const res = await request(baseUrl, 'GET', '/v1/rule-coverage', { headers: demoHeaders('viewer') });
    assert.equal(res.status, 200);
    assert.equal(res.json.version, 'rule-coverage.v1');
    const sqli = res.json.categories.find((row) => row.id === 'sqli');
    assert.equal(sqli.assurance, 'verdict');
  });

  it('returns target coverage for the owning tenant and 404 for another tenant', async () => {
    const owned = await request(baseUrl, 'GET', '/v1/targets/tgt_1/rule-coverage', { headers: demoHeaders('admin') });
    assert.equal(owned.status, 200);
    assert.equal(owned.json.target_id, 'tgt_1');
    const foreign = await request(baseUrl, 'GET', '/v1/targets/tgt_1/rule-coverage', {
      headers: demoHeaders('admin', 'ten_other', 'usr_other'),
    });
    assert.equal(foreign.status, 404);
    assert.equal(foreign.json.error, 'not_found');
  });

  it('rejects unauthenticated catalog reads', async () => {
    const res = await request(baseUrl, 'GET', '/v1/rule-coverage', {
      headers: { 'x-principal-type': 'staff', 'x-staff-id': 'staff_x', 'x-staff-role': 'internal_admin' },
    });
    assert.ok(res.status === 401 || res.status === 403);
  });
});
