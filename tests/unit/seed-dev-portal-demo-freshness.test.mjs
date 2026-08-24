import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import '../helpers/dev-data-dir.mjs';
import { buildPortalDemoStore, PORTAL_DEMO_IDS } from '../fixtures/portal-demo/seed.mjs';
import { rebaseDemoStoreTimestamps } from '../../scripts/seed-dev-portal-demo.mjs';

const NOW = new Date('2026-08-24T09:00:00.000Z');

function seededStore() {
  return rebaseDemoStoreTimestamps(buildPortalDemoStore(), NOW);
}

describe('seed:dev-demo freshness', () => {
  it('gives the online agent a recent heartbeat and a version', () => {
    const agent = seededStore().agents.find((row) => row.id === PORTAL_DEMO_IDS.agentId);
    assert.equal(agent.status, 'online');
    assert.ok(agent.version, 'seeded agent must report a version');

    const ageMs = NOW.getTime() - Date.parse(agent.last_heartbeat_at);
    assert.ok(ageMs >= 0 && ageMs <= 30_000, `heartbeat age was ${ageMs}ms`);
  });

  it('starts the running run minutes ago, not weeks ago', () => {
    const running = seededStore().testRuns.find((row) => row.status === 'running');
    const ageMs = NOW.getTime() - Date.parse(running.started_at);
    assert.ok(ageMs > 0 && ageMs <= 60 * 60 * 1000, `running run age was ${ageMs}ms`);
  });

  it('replays the frozen fixture instant relative to seed time', () => {
    const store = seededStore();
    const frozenMs = Date.parse(PORTAL_DEMO_IDS.frozenAt);
    for (const finding of store.findings) {
      assert.notEqual(Date.parse(finding.opened_at), frozenMs);
      assert.ok(Date.parse(finding.opened_at) <= NOW.getTime());
    }
    for (const run of store.testRuns) {
      assert.ok(Date.parse(run.created_at) <= NOW.getTime());
      assert.ok(NOW.getTime() - Date.parse(run.created_at) <= 24 * 60 * 60 * 1000);
    }
  });

  it('leaves hash-chained and custody-digested records on their signed instants', () => {
    const store = seededStore();
    const frozenMs = Date.parse(PORTAL_DEMO_IDS.frozenAt);

    // Rewriting these breaks the integrity check computed over the same timestamp.
    for (const loa of store.loaSignatures) {
      assert.equal(Date.parse(loa.signed_at), frozenMs);
    }
    const chained = store.auditLog.filter((row) => row.entry_hash);
    assert.ok(chained.length > 0);
    for (const entry of chained) {
      assert.ok(Date.parse(entry.timestamp) <= frozenMs);
    }
  });
});
