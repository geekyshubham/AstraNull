import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  HISTORICAL_RUN_ATTRIBUTION_UNAVAILABLE,
  resolveAgentRunAttributionStatus,
  runAgentAttribution,
  selectAgentAttributedRuns,
  selectAgentRecentRuns,
  selectAgentRunEventCandidates,
} from '../../apps/web/react/src/lib/agent-run-attribution.mjs';

const EMPTY_RUN_EVENTS_RESPONSE = { items: [] };

function observation(overrides = {}) {
  return {
    id: 'evt_observation_1',
    test_run_id: 'run_1',
    signal_type: 'agent_observation',
    producer_kind: 'authenticated_agent',
    agent_id: 'agt_1',
    timestamp: '2026-09-01T10:00:00.000Z',
    metadata: {},
    ...overrides,
  };
}

describe('agent detail run attribution', () => {
  it('ignores unsupported run-level agent fields and aliases', () => {
    const fabricatedRunBindings = [
      { agent_id: 'agt_1' },
      { agentId: 'agt_1' },
      { agent_ids: ['agt_1'] },
      { agentIds: ['agt_1'] },
    ];

    for (const binding of fabricatedRunBindings) {
      assert.deepEqual(
        runAgentAttribution(
          { id: 'run_1', target_group_id: 'tg_1', ...binding },
          EMPTY_RUN_EVENTS_RESPONSE,
          'agt_1',
        ),
        { attributed: false, source: null },
      );
    }
  });

  it('never treats target-group membership or nested caller metadata as attribution', () => {
    const sameGroupRun = {
      id: 'run_1',
      target_group_id: 'tg_1',
      metadata: { agent_id: 'agt_1' },
      observations: [{ agent_id: 'agt_1' }],
    };
    assert.deepEqual(
      runAgentAttribution(sameGroupRun, EMPTY_RUN_EVENTS_RESPONSE, 'agt_1'),
      { attributed: false, source: null },
    );
  });

  it('attributes a real run-events endpoint envelope with exact authenticated observation provenance', () => {
    const runEventsEndpointResponse = { items: [observation()] };
    assert.deepEqual(
      runAgentAttribution({ id: 'run_1', target_group_id: 'tg_1' }, runEventsEndpointResponse, 'agt_1'),
      { attributed: true, source: 'run_event' },
    );
  });

  it('selects event candidates before group filtering and slices only after provenance filtering', () => {
    const candidates = selectAgentRunEventCandidates([
      {
        id: 'run_current_group',
        target_group_id: 'tg_current',
        updated_at: '2026-09-01T10:03:00.000Z',
      },
      {
        id: 'run_unrelated_decoy',
        target_group_id: 'tg_unrelated',
        updated_at: '2026-09-01T10:02:00.000Z',
      },
      {
        id: 'run_historical',
        target_group_id: 'tg_previous',
        updated_at: '2026-09-01T10:01:00.000Z',
      },
      {
        id: 'run_outside_candidate_window',
        target_group_id: 'tg_previous',
        updated_at: '2026-09-01T10:00:00.000Z',
      },
    ], 3);
    assert.deepEqual(
      candidates.map((run) => run.id),
      ['run_current_group', 'run_unrelated_decoy', 'run_historical'],
      'candidate endpoint fetches are selected before group filtering and display slicing',
    );

    const selected = selectAgentRecentRuns(candidates, {
      run_current_group: { items: [] },
      run_unrelated_decoy: { items: [] },
      run_historical: {
        items: [observation({
          id: 'evt_historical_observation',
          test_run_id: 'run_historical',
        })],
      },
    }, 'agt_1', 'tg_current', 2);

    assert.deepEqual(
      selected.map((run) => run.id),
      ['run_current_group', 'run_historical'],
      'exact endpoint provenance keeps the historical run after group rebinding and display slicing',
    );
    assert.deepEqual(
      runAgentAttribution(selected[1], {
        items: [observation({ test_run_id: 'run_historical' })],
      }, 'agt_1'),
      { attributed: true, source: 'run_event' },
    );
  });

  it('gives placement only the older exact historical run, never a newer current-group-only run', () => {
    const candidates = selectAgentRunEventCandidates([
      {
        id: 'run_current_group_newer',
        target_group_id: 'tg_current',
        check_id: 'path.protected_canary.safe',
        updated_at: '2026-09-01T10:06:00.000Z',
      },
      {
        id: 'run_historical_exact',
        target_group_id: 'tg_previous',
        check_id: 'path.protected_canary.safe',
        updated_at: '2026-09-01T10:01:00.000Z',
      },
    ]);
    const envelopes = {
      run_current_group_newer: { items: [] },
      run_historical_exact: {
        items: [observation({
          id: 'evt_historical_exact',
          test_run_id: 'run_historical_exact',
        })],
      },
    };

    assert.deepEqual(
      selectAgentAttributedRuns(candidates, envelopes, 'agt_1').map((run) => run.id),
      ['run_historical_exact'],
    );
    assert.deepEqual(
      selectAgentAttributedRuns(candidates, { run_current_group_newer: { items: [] } }, 'agt_1'),
      [],
      'a group-only placement run leaves the panel pending',
    );
  });

  it('does not mistake endpoint-shaped evidence-vault rows for event provenance', () => {
    const evidenceEndpointResponse = {
      items: [{
        id: 'evidence_1',
        test_run_id: 'run_1',
        label: 'probe_worker_evidence',
        related_event_id: 'evt_probe_1',
        metadata: { agent_id: 'agt_1' },
        created_at: '2026-09-01T10:00:01.000Z',
      }],
    };
    assert.deepEqual(
      runAgentAttribution({ id: 'run_1', target_group_id: 'tg_1' }, evidenceEndpointResponse, 'agt_1'),
      { attributed: false, source: null },
    );
  });

  it('requires exact run ID, signal, producer, and authenticated top-level agent ID', () => {
    const invalidEvents = [
      observation({ test_run_id: 'run_other' }),
      observation({ signal_type: 'probe_result' }),
      observation({ producer_kind: 'public_api' }),
      observation({ agent_id: 'agt_other' }),
      observation({ agent_id: undefined, metadata: { agent_id: 'agt_1' } }),
    ];
    for (const event of invalidEvents) {
      assert.deepEqual(
        runAgentAttribution({ id: 'run_1', target_group_id: 'tg_1' }, { items: [event] }, 'agt_1'),
        { attributed: false, source: null },
      );
    }
  });

  it('fails aggregate historical attribution closed when any candidate endpoint fails', () => {
    const candidates = [
      { id: 'run_loaded', target_group_id: 'tg_previous' },
      { id: 'run_failed_unknown', target_group_id: 'tg_previous' },
    ];
    assert.equal(HISTORICAL_RUN_ATTRIBUTION_UNAVAILABLE, 'Historical run attribution unavailable');
    assert.equal(resolveAgentRunAttributionStatus(candidates, {
      run_loaded: 'loaded',
      run_failed_unknown: 'loading',
    }), 'loading');
    assert.equal(resolveAgentRunAttributionStatus(candidates, {
      run_loaded: 'loaded',
      run_failed_unknown: 'error',
    }), 'unavailable');
    assert.deepEqual(
      selectAgentAttributedRuns(candidates, {
        run_loaded: { items: [] },
      }, 'agt_1'),
      [],
      'a missing failed envelope never associates its unknown run with the agent',
    );
    assert.equal(resolveAgentRunAttributionStatus(candidates, {
      run_loaded: 'loaded',
      run_failed_unknown: 'loaded',
    }), 'available');
  });

  it('rejects raw caller-assembled event arrays instead of treating them as endpoint responses', () => {
    assert.deepEqual(
      runAgentAttribution({ id: 'run_1' }, [observation()], 'agt_1'),
      { attributed: false, source: null },
    );
  });
});
