import '../helpers/dev-data-dir.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { executeProbeForJob } from '../../workers/probe-worker.mjs';

function createFakeSocket() {
  const socket = new EventEmitter();
  socket.close = () => {};
  socket.send = (query, ...args) => {
    const cb = typeof args[args.length - 1] === 'function' ? args[args.length - 1] : () => {};
    const host = typeof args[args.length - 2] === 'string' ? args[args.length - 2] : '172.31.41.10';
    const port = typeof args[args.length - 3] === 'number' ? args[args.length - 3] : 53;
    cb();
    queueMicrotask(() => {
      const response = Buffer.from(query);
      response.writeUInt16BE(0x8400, 2);
      socket.emit('message', response, { address: host, port, family: 'IPv4', size: response.length });
    });
  };
  return socket;
}

function makeJob() {
  return {
    id: 'job_lab',
    check_id: 'dns.authoritative_response.safe',
    vector_family: 'dns',
    target: {
      kind: 'fqdn',
      value: 'lab.efficacy.invalid'
    },
    probe_profile: {
      kind: 'dns_wire_query',
      max_requests: 1,
      timeout_ms: 1000,
      dns_qtype: 'SOA',
      dns_transport: 'udp'
    },
    constraints: {
      max_requests: 4,
      max_probe_requests: 1,
      min_destination_resolver_attempts: 3,
      max_destination_resolver_attempts: 3,
      max_total_operations: 4,
      timeout_ms: 1000
    }
  };
}

function createDeps(env) {
  let socketCount = 0;
  return {
    getSocketCount: () => socketCount,
    deps: {
      env,
      resolveNsFn: async () => ['ns1.lab.efficacy.invalid'],
      resolve4Fn: async () => ['172.31.41.10'],
      resolve6Fn: async () => [],
      createSocket: () => {
        socketCount++;
        return createFakeSocket();
      }
    }
  };
}

test('allows private destination in test environment when opt-in enabled', async () => {
  const { deps, getSocketCount } = createDeps({
    NODE_ENV: 'test',
    ASTRANULL_PROBE_ALLOW_PRIVATE_DESTINATIONS: '1'
  });
  const outcome = await executeProbeForJob(makeJob(), deps);
  const res = outcome;
  assert.strictEqual(getSocketCount(), 1);
  assert.strictEqual(res.external_result, 'connected');
  assert.strictEqual(res.probe_requests_sent, 1);
  assert.strictEqual(res.destination_resolver_attempts ?? res.resolver_attempts, 3);
  assert.strictEqual(res.total_operations ?? res.total_operations_count, 4);
  assert.strictEqual(Boolean(res.protection_detected ?? res.protection), false);
});

test('blocks private destination in test environment without opt-in', async () => {
  const { deps, getSocketCount } = createDeps({
    NODE_ENV: 'test'
  });
  const outcome = await executeProbeForJob(makeJob(), deps);
  const res = outcome;
  assert.strictEqual(getSocketCount(), 0);
  const errCode = res.metadata.error_class;
  assert.strictEqual(errCode, 'EDESTINATION');
});

test('blocks private destination in production even with opt-in', async () => {
  const { deps, getSocketCount } = createDeps({
    NODE_ENV: 'production',
    ASTRANULL_PROBE_ALLOW_PRIVATE_DESTINATIONS: '1'
  });
  const outcome = await executeProbeForJob(makeJob(), deps);
  const res = outcome;
  assert.strictEqual(getSocketCount(), 0);
  const errCode = res.metadata.error_class;
  assert.strictEqual(errCode, 'EDESTINATION');
});
