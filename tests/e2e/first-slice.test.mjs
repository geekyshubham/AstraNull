import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

// ADR-0008: outside-in only. The validation loop is start -> external probe evidence ->
// finalization -> verdict -> finding. There are no agents, bootstrap tokens, or observations.

let baseUrl;
let server;

before(() => {
  process.env.ASTRANULL_NO_PERSIST = '1';
  freshStore();
  server = createServer();
  server.listen(0);
  const { port } = server.address();
  baseUrl = `http://127.0.0.1:${port}`;
});

after(() => server.close());

describe('e2e first slice', () => {
  it('completes the external-only validation loop and state reflects evidence', async () => {
    const admin = demoHeaders('admin');

    const runRes = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers: demoHeaders('engineer'),
      body: {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      },
    });
    assert.equal(runRes.status, 201);
    const runId = runRes.json.run.id;
    assert.ok(runId);
    // Inline simulation mode records a probe_result event and moves the run to collecting.
    assert.equal(runRes.json.run.status, 'collecting');

    const state = await request(baseUrl, 'GET', '/v1/state', { headers: admin });
    assert.equal(state.status, 200);
    assert.ok(state.json.readiness.score >= 0);
    assert.ok(state.json.recent_runs.some((r) => r.id === runId));
    // No agent fields are exposed on state (ADR-0008).
    assert.equal('agents_online' in state.json, false);
    assert.equal('agents_total' in state.json, false);

    const events = await request(baseUrl, 'GET', `/v1/test-runs/${runId}/events`, {
      headers: admin,
    });
    // Verdicts come from external probe evidence only — a probe_result event, never an agent one.
    assert.ok(events.json.items.some((e) => e.signal_type === 'probe_result'));
    assert.equal(events.json.items.some((e) => e.signal_type === 'agent_observation'), false);
  });
});
