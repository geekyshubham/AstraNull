import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { describe, it } from 'node:test';
import { MAX_PAYLOAD_BYTES, REFLECTOR_PAYLOADS } from '../../src/lib/reflectorPayloads.mjs';
import { probeReflectionService } from '../../src/lib/safeNetworkProbes.mjs';

// Enforces the regression contract in docs/adr/0007-reflector-exposure-probes.md at runtime.
// If any of these fail, the reflector probes have drifted toward amplification tooling and the ADR
// requires moving them behind SOC approval.

/** A fake UDP socket that records every send and never touches the network. */
function recordingSockets({ reply = null, replyFrom = null } = {}) {
  const sends = [];
  const created = [];
  const createSocket = (type) => {
    const socket = new EventEmitter();
    socket.type = type;
    socket.bound = null;
    socket.bind = (...args) => { socket.bound = args; };
    socket.send = (payload, port, host, cb) => {
      sends.push({ bytes: payload.length, port, host });
      cb?.(null);
      if (reply) {
        const from = replyFrom ?? { address: host, port };
        setImmediate(() => socket.emit('message', reply, { ...from, family: 'IPv4', size: reply.length }));
      }
    };
    socket.close = () => {};
    created.push(socket);
    return socket;
  };
  return { createSocket, sends, created };
}

// A public address the default egress policy allows, so the probe runs without a policy override.
const PUBLIC_IP = '8.8.8.8';

function job(overrides = {}) {
  return {
    nonce_hash: 'guardrail',
    target: { value: `${PUBLIC_IP}:1900` },
    probe_profile: { kind: 'reflection_service_probe', payload_profile: 'ssdp_msearch' },
    constraints: { timeout_ms: 60, max_requests: 2 },
    ...overrides,
  };
}

describe('ADR-0007 reflector probe guardrails (runtime)', () => {
  it('guardrail 1: sends at most 2 packets even when a job asks for many more', async () => {
    const sockets = recordingSockets(); // no reply -> the probe uses its full retry budget
    const result = await probeReflectionService(job({ constraints: { timeout_ms: 60, max_requests: 1000 } }), sockets);
    assert.ok(sockets.sends.length <= 2, `sent ${sockets.sends.length} packets`);
    assert.ok(result.requests_sent <= 2, `requests_sent=${result.requests_sent}`);
  });

  it('guardrail 2: only ever sends to the single pinned destination, with no source-address binding', async () => {
    const sockets = recordingSockets();
    await probeReflectionService(job(), sockets);
    assert.ok(sockets.sends.length >= 1);
    for (const send of sockets.sends) {
      assert.equal(send.host, PUBLIC_IP);
      assert.equal(send.port, 1900);
    }
    // Reflection abuse needs a spoofed victim source; the probe must never choose its source address.
    for (const socket of sockets.created) assert.equal(socket.bound, null, 'probe socket must not bind a chosen source');
  });

  it('guardrail 2: ignores replies from any peer other than the pinned destination', async () => {
    const sockets = recordingSockets({ reply: Buffer.alloc(400, 0x41), replyFrom: { address: '198.51.100.99', port: 1900 } });
    const result = await probeReflectionService(job(), sockets);
    assert.equal(result.metadata.reflector_confirmed, false, 'a reply from another host must not count');
    assert.equal(result.metadata.amplification_ratio, null);
  });

  it('guardrail 3: refuses private, loopback and metadata destinations by default, sending nothing', async () => {
    for (const host of ['127.0.0.1', '10.0.0.5', '192.168.1.1', '169.254.169.254', '::1']) {
      const sockets = recordingSockets();
      const value = host.includes(':') ? `[${host}]:1900` : `${host}:1900`;
      const result = await probeReflectionService(job({ target: { value, port: 1900 } }), sockets);
      assert.equal(sockets.sends.length, 0, `${host}: no packet may leave`);
      assert.equal(result.requests_sent, 0, host);
      assert.equal(result.metadata.reflector_confirmed, false, host);
    }
  });

  it('guardrail 4: every reflector payload stays within MAX_PAYLOAD_BYTES (512)', () => {
    assert.equal(MAX_PAYLOAD_BYTES, 512);
    for (const [id, entry] of Object.entries(REFLECTOR_PAYLOADS)) {
      const payload = entry.build({ nonceHash: 'x', queryName: '_services._dns-sd._udp.local' });
      assert.ok(payload.length <= MAX_PAYLOAD_BYTES, `${id} is ${payload.length} bytes`);
    }
  });

  it('guardrail 5: output is metadata only — no response bytes are retained or returned', async () => {
    const secret = Buffer.from('REFLECTED-RESPONSE-BODY-THAT-MUST-NOT-BE-KEPT');
    const sockets = recordingSockets({ reply: secret });
    const result = await probeReflectionService(job(), sockets);
    assert.equal(result.metadata.reflector_confirmed, true);
    assert.equal(result.metadata.response_bytes, secret.length);
    const serialized = JSON.stringify(result);
    assert.equal(serialized.includes('REFLECTED-RESPONSE-BODY'), false, 'response payload must not be retained');
    for (const forbidden of ['payload', 'response_body', 'raw', 'packet']) {
      assert.equal(Object.hasOwn(result.metadata, forbidden), false, `metadata must not carry "${forbidden}"`);
    }
  });
});
