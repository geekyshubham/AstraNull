import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { probeConnectionLimit } from '../../src/lib/connectionLimitProbe.mjs';

function refusingSocket() {
  const socket = new EventEmitter();
  socket.destroy = () => {};
  queueMicrotask(() => socket.emit('error', Object.assign(new Error('refused'), { code: 'ECONNREFUSED' })));
  return socket;
}

for (const [value, vetted] of [['172.31.31.2:8083', '172.31.31.2'], ['[fd00:a57a:31::2]:8083', 'fd00:a57a:31::2']]) {
  test(`tcp target ${value} consumes the vetted host without DNS`, async () => {
    const connected = [];
    const result = await probeConnectionLimit({
      target: { kind: 'tcp', value },
      probe_profile: { declarations: { connection_limits: [{ protocol: 'tcp', port: 8083, max_connections_per_source: 2 }] } },
      constraints: { timeout_ms: 50 },
    }, {
      vettedHost: vetted,
      vettedAddresses: [vetted],
      destinationPolicy: { allowPrivate: true, allowLoopback: false },
      resolve4Fn: async () => { throw new Error('DNS must not be used for a vetted tcp target'); },
      resolve6Fn: async () => { throw new Error('DNS must not be used for a vetted tcp target'); },
      connectFn: (opts) => { connected.push(opts); return refusingSocket(); },
    });
    assert.equal(result.external_result, 'blocked');
    assert.equal(result.requests_sent, 4);
    assert.equal(result.metadata.address, vetted);
    assert.deepEqual(connected.map((c) => [c.host, c.port]), Array(4).fill([vetted, 8083]));
  });
}
