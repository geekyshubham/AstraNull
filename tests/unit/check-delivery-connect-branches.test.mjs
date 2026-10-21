import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { getCheckById } from '../../src/contracts/checks.mjs';
import { CHECK_DELIVERY_INVENTORY, accountDeliveryReceipts } from '../fixtures/check-delivery-coverage.mjs';
import { createCheckDeliveryFixtures } from '../helpers/check-delivery-fixtures.mjs';
import { CONNECT_FAULT_KINDS, createConnectFaultFixture, executeConnectFaultDelivery } from '../helpers/check-delivery-connect-fault.mjs';
import { assertExistingBehaviorCase } from '../helpers/existing-behavior-coverage.mjs';
import { CONNECT_FAULT_LAB_CONFIG, connectFaultContainerArguments, assertConnectFaultContainerIsolation } from '../../scripts/check-delivery-connect-fault-lab.mjs';

describe('connect fault lab fail-closed isolation contract (helper-only, no coverage receipts)', () => {
  const args = connectFaultContainerArguments('astranull-connect-fault-01234567-abcd');
  const source = args[args.indexOf('--mount') + 1].match(/^type=bind,src=(.*),dst=\/source,readonly$/)[1];
  const inspection = () => ({ Image: CONNECT_FAULT_LAB_CONFIG.image,
    HostConfig: { NetworkMode: 'none', Privileged: false, ReadonlyRootfs: true, PidMode: '', IpcMode: 'private',
      NanoCpus: 1e9, Memory: 268435456, MemorySwap: 268435456, PidsLimit: 32,
      CapDrop: ['ALL'], CapAdd: ['CAP_NET_ADMIN', 'CAP_NET_RAW'], SecurityOpt: ['no-new-privileges'],
      PortBindings: {}, PublishAllPorts: false, Devices: [], DeviceRequests: [], Tmpfs: { '/scratch': 'rw,noexec,nosuid,nodev,size=16777216,mode=0700' } },
    Mounts: [{ Type: 'bind', Source: source, Destination: '/source', RW: false }],
    Config: { WorkingDir: '/scratch', Entrypoint: ['/usr/bin/timeout'],
      Cmd: ['--signal=KILL', '20', '/usr/local/bin/node', '/source/tests/fixtures/check-delivery-connect-fault-preflight.mjs'] },
  });
  it('pins cached image, disables pulls/network, and separates readonly source from bounded scratch', () => {
    assert.equal(args[args.indexOf('--pull') + 1], 'never');
    assert.equal(args[args.indexOf('--network') + 1], 'none');
    assert.equal(args[args.indexOf('--tmpfs') + 1], '/scratch:rw,noexec,nosuid,nodev,size=16777216,mode=0700');
    assert.ok(args.includes(CONNECT_FAULT_LAB_CONFIG.image));
    assert.doesNotThrow(() => assertConnectFaultContainerIsolation(inspection()));
    assert.throws(() => connectFaultContainerArguments('unrelated-resource'));
  });
  for (const [name, mutate] of [
    ['host networking', (row) => { row.HostConfig.NetworkMode = 'host'; }],
    ['privileged mode', (row) => { row.HostConfig.Privileged = true; }],
    ['writable root', (row) => { row.HostConfig.ReadonlyRootfs = false; }],
    ['host PID namespace', (row) => { row.HostConfig.PidMode = 'host'; }],
    ['host IPC namespace', (row) => { row.HostConfig.IpcMode = 'host'; }],
    ['unbounded CPU', (row) => { row.HostConfig.NanoCpus = 0; }],
    ['unbounded memory', (row) => { row.HostConfig.Memory = 0; }],
    ['unbounded swap', (row) => { row.HostConfig.MemorySwap = -1; }],
    ['unbounded processes', (row) => { row.HostConfig.PidsLimit = 0; }],
    ['extra capabilities', (row) => { row.HostConfig.CapAdd.push('SYS_ADMIN'); }],
    ['retained default capabilities', (row) => { row.HostConfig.CapDrop = []; }],
    ['privilege escalation', (row) => { row.HostConfig.SecurityOpt = []; }],
    ['published ports', (row) => { row.HostConfig.PortBindings = { '443/tcp': [] }; }],
    ['automatic port publication', (row) => { row.HostConfig.PublishAllPorts = true; }],
    ['host device', (row) => { row.HostConfig.Devices.push({ PathOnHost: '/dev/x' }); }],
    ['device request', (row) => { row.HostConfig.DeviceRequests.push({ Driver: 'x' }); }],
    ['docker socket mount', (row) => { row.Mounts.push({ Destination: '/var/run/docker.sock' }); }],
    ['writable source', (row) => { row.Mounts[0].RW = true; }],
    ['wrong source tree', (row) => { row.Mounts[0].Source = '/other'; }],
    ['missing scratch', (row) => { row.HostConfig.Tmpfs = {}; }],
    ['unbounded scratch', (row) => { row.HostConfig.Tmpfs['/scratch'] = 'rw'; }],
    ['unbounded runtime', (row) => { row.Config.Cmd[1] = '0'; }],
    ['unreviewed entrypoint', (row) => { row.Config.Entrypoint = ['/bin/sh']; }],
    ['wrong image', (row) => { row.Image = 'node:latest'; }],
  ]) it(`rejects ${name}`, () => {
    const value = inspection(); mutate(value);
    assert.throws(() => assertConnectFaultContainerIsolation(value));
  });
});

const obligations = CHECK_DELIVERY_INVENTORY.branch_obligations.filter((row) => CONNECT_FAULT_KINDS.includes(row.kind));
const native = obligations;
const nativeReceipts = [];

describe('owned native TCP refused endpoints, unanswered SYN timeouts and post-handshake cancellation', () => {
  let fixtures;
  before(async () => { fixtures = await createCheckDeliveryFixtures(); });
  after(async () => { await fixtures?.close(); });
  it('owns all nine fingerprint owners across refusal, timeout and cancellation', () => {
    assert.equal(obligations.length, 27);
    assert.equal(obligations.filter((row) => row.branch === 'timeout').length, 9);
    assert.equal(new Set(obligations.map((row) => row.branch_id)).size, 27);
  });
  for (const obligation of native) {
    it(`${obligation.check_id} / branch ${obligation.branch}`, { timeout: 15_000 }, async (t) => {
      const check = getCheckById(obligation.check_id);
      const fixture = await createConnectFaultFixture(fixtures, check, obligation.branch);
      try {
        const result = await executeConnectFaultDelivery(check, fixture);
        const { receipt, outcome } = result;
        receipt.branch_id = obligation.branch_id;
        await assertExistingBehaviorCase(t, { channel: 'delivery', receipt }, async () => {
          assert.equal(result.verdict.confidence, 'external_only');
          assert.equal(result.findings.length, 0);
          assert.equal(result.readiness.coverage.passed_count, 0);
          assert.ok(receipt.execution_receipt.digest && receipt.accepted_event.id && receipt.published_verdict.id);
          assert.ok(outcome.total_operations <= result.job.constraints.max_total_operations);
          assert.ok(result.networkAttempts.length > 0);
          assert.ok(result.networkAttempts.every((row) => row.closed_at));
          if (obligation.branch === 'peer_refused') {
            assert.equal(outcome.external_result, 'blocked', JSON.stringify(outcome));
            assert.deepEqual(receipt.actual_wire, [], 'refused attempts are not accepted sessions or requests');
            assert.ok(result.networkAttempts.every((row) => row.error_code === 'ECONNREFUSED' && !row.accepted));
            assert.ok(receipt.branch_peer_evidence.some((row) => row.event === 'connection_refused' && row.phase === 'connect'));
            if (obligation.kind === 'tcp_connect') assert.equal(outcome.metadata.tcp_outcome, 'refused_rst');
            if (obligation.kind === 'connection_limit_probe') {
              assert.equal(outcome.metadata.accepted_count, 0);
              assert.equal(outcome.metadata.refused_after, 0);
            }
            if (obligation.kind === 'port_scan_bounded') {
              assert.equal(outcome.metadata.open_ports.length, 0);
              assert.ok(outcome.metadata.closed_ports.length > 0);
            }
          } else if (obligation.branch === 'timeout') {
            if (obligation.kind === 'port_scan_bounded') {
              assert.equal(outcome.external_result, 'blocked', 'the scan reserves a deadline margin so silent ports finish as filtered, not as a job timeout');
              assert.equal(outcome.metadata.open_ports.length, 0);
              assert.ok(outcome.metadata.filtered_ports.length > 0);
            } else assert.equal(outcome.external_result, 'timeout', JSON.stringify(outcome));
            assert.deepEqual(receipt.actual_wire, [], 'a saturated listener never accepts the worker connection');
            assert.ok(result.networkAttempts.every((row) => !row.accepted && !row.connected_at && row.closed_at));
            assert.ok(receipt.branch_peer_evidence.some((row) => row.event === 'listen_queue_saturated' && row.probe_result === 'syn_ack_withheld'));
            assert.ok(outcome.duration_ms >= 100, 'timeout must reflect real elapsed time');
          } else {
            assert.ok(['error', 'timeout', 'not_run'].includes(outcome.external_result), JSON.stringify(outcome));
            assert.ok(outcome.duration_ms < 1000, 'native cancellation must finish before signed deadline');
            assert.equal(result.networkAttempts.length, 1, 'abort must prevent subsequent samples/ports/connections');
            assert.ok(receipt.branch_peer_evidence.some((row) => row.event === 'cancel_requested'
              && row.phase === 'established_connection_before_next_attempt'));
            assert.ok(receipt.actual_wire.some((row) => row.transport === 'tcp_connect'
              && row.remote_port === result.networkAttempts[0].local_port
              && row.fixture_port === result.networkAttempts[0].fixture_port), 'native cancellation must bind actual accepted peer to initiating client socket');
          }
          receipt.branch_assertions = [
            'unchanged signed catalog job admitted leased reserved executed ingested and published with custody',
            obligation.branch === 'peer_refused' ? 'native ECONNREFUSED and close observed separately from accepted sessions'
              : obligation.branch === 'timeout' ? 'kernel withheld SYN-ACK from a proven saturated owned listener until the signed deadline and the client socket closed'
                : 'native established handshake cancellation prevents next operation and closes clients before teardown',
            'negative observation earns no finding or readiness credit',
          ];
          nativeReceipts.push(receipt);
          return receipt.branch_assertions;
        });
      } finally { await fixture.close(); }
    });
  }
  it('accounts every native TCP branch with no remaining gaps', () => {
    const inventory = { ...CHECK_DELIVERY_INVENTORY,
      rows: CHECK_DELIVERY_INVENTORY.rows.filter((row) => obligations.some((item) => item.check_id === row.check_id)),
      branch_obligations: obligations };
    const result = accountDeliveryReceipts(nativeReceipts, inventory);
    assert.deepEqual(result.errors, []);
    assert.equal(result.invoked_branches, 27);
    assert.equal(result.invoked_definitions, 0, 'branch receipts do not substitute for default invocations');
    assert.deepEqual(result.branch_gaps, []);
    const omitted = accountDeliveryReceipts(nativeReceipts.slice(1), inventory);
    assert.ok(omitted.branch_gaps.some((row) => row.branch_id === nativeReceipts[0].branch_id));
    for (const [name, mutate] of [
      ['missing attempt', (row) => { row.actual_network_attempts = []; }],
      ['wrong phase', (row) => { row.actual_network_attempts[0].phase = 'accepted_request'; }],
      ['wrong invocation', (row) => { row.actual_network_attempts[0].invocation_id = 'another_invocation'; }],
      ['accepted instead of refused', (row) => { row.actual_network_attempts[0].accepted = true; }],
      ['wrong endpoint', (row) => { row.actual_network_attempts[0].fixture_host = '192.0.2.1'; }],
      ['missing closure', (row) => { delete row.actual_network_attempts[0].closed_at; }],
      ['wrong runtime scope', (row) => { row.runtime_provenance.scope = 'public_network'; }],
      ['missing causal refusal', (row) => { row.branch_peer_evidence = row.branch_peer_evidence.filter((item) => item.event !== 'connection_refused'); }],
    ]) {
      const mutated = structuredClone(nativeReceipts);
      mutate(mutated[0]);
      const rejected = accountDeliveryReceipts(mutated, inventory);
      assert.ok(rejected.errors.length > 0, `must reject ${name}`);
    }
    const timeoutIndex = nativeReceipts.findIndex((row) => obligations.find((item) => item.branch_id === row.branch_id)?.branch === 'timeout');
    for (const [name, mutate] of [
      ['missing saturation proof', (row) => { row.branch_peer_evidence = row.branch_peer_evidence.filter((item) => item.event !== 'listen_queue_saturated'); }],
      ['saturation not withheld', (row) => { row.branch_peer_evidence.find((item) => item.event === 'listen_queue_saturated').probe_result = 'connected'; }],
      ['saturation after attempt', (row) => { row.branch_peer_evidence.find((item) => item.event === 'listen_queue_saturated').at = new Date(Date.now() + 60_000).toISOString(); }],
      ['saturation on another port', (row) => { row.branch_peer_evidence.find((item) => item.event === 'listen_queue_saturated').fixture_port += 1; }],
      ['missing abort evidence', (row) => { row.branch_peer_evidence = row.branch_peer_evidence.filter((item) => item.event !== 'connect_aborted_without_synack'); }],
      ['accepted attempt', (row) => { row.actual_network_attempts[0].accepted = true; }],
      ['connected attempt', (row) => { row.actual_network_attempts[0].connected_at = row.actual_network_attempts[0].started_at; }],
      ['missing closure', (row) => { delete row.actual_network_attempts[0].closed_at; }],
      ['refusal passed off as timeout', (row) => { row.actual_network_attempts[0].error_code = 'ECONNREFUSED'; }],
    ]) {
      const mutated = structuredClone(nativeReceipts);
      mutate(mutated[timeoutIndex]);
      assert.ok(accountDeliveryReceipts(mutated, inventory).errors.length > 0, `must reject timeout mutation: ${name}`);
    }
  });
});
