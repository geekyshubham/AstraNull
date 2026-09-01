import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { describe, it } from 'node:test';
import { probeDnsWireQuery } from '../../src/lib/dnsWireQuery.mjs';
import { frameDnsTcpMessage } from '../../src/lib/dnsTcpWire.mjs';

function baseJob(overrides = {}) {
  return {
    id: 'pjob_dns_wire',
    check_id: 'dns.authoritative_response.safe',
    nonce_hash: 'dns-wire-nonce-hash',
    nonce: 'random-prefix',
    constraints: { timeout_ms: 100, max_requests: 2 },
    probe_profile: {
      kind: 'dns_wire_query',
      dns_qtype: 'A',
      dns_transport: 'udp',
      max_requests: 2,
      timeout_ms: 100,
    },
    target: { kind: 'ip', value: '203.0.113.53' },
    ...overrides,
  };
}

function dnsResponse(query, options = {}) {
  const size = Math.max(12, options.size ?? 12);
  const response = Buffer.alloc(size, 0xa5);
  query.copy(response, 0, 0, 2);
  response[2] = 0x80
    | (options.authoritative === false ? 0 : 0x04)
    | (options.truncated ? 0x02 : 0);
  response[3] = options.rcode ?? 0;
  response.writeUInt16BE(1, 4);
  response.writeUInt16BE(options.answerCount ?? 0, 6);
  response.writeUInt16BE(0, 8);
  response.writeUInt16BE(0, 10);
  if (options.data) Buffer.from(options.data).copy(response, 12);
  return response;
}

function udpSocket(options = {}) {
  const socket = new EventEmitter();
  socket.send = (query, port, host, callback) => {
    options.onSend?.(query, port, host);
    callback(null);
    if (options.respond === false) return;
    const response = dnsResponse(query, options.response);
    queueMicrotask(() => socket.emit('message', response, { address: host, port }));
  };
  socket.close = () => {};
  return socket;
}

function tcpConnector(responseOptions, onConnect) {
  return (_endpoint, connected) => {
    onConnect?.();
    const socket = new EventEmitter();
    socket.destroy = () => {};
    socket.setTimeout = () => {};
    socket.write = (framedQuery, callback) => {
      callback?.(null);
      const queryLength = framedQuery.readUInt16BE(0);
      const query = framedQuery.subarray(2, 2 + queryLength);
      const response = frameDnsTcpMessage(dnsResponse(query, responseOptions));
      queueMicrotask(() => socket.emit('data', response));
    };
    queueMicrotask(connected);
    return socket;
  };
}

function injectedResolutionDeps(overrides = {}) {
  return {
    resolve4Fn: async () => { throw new Error('literal destination must not use DNS'); },
    resolve6Fn: async () => { throw new Error('literal destination must not use DNS'); },
    ...overrides,
  };
}

describe('probeDnsWireQuery', () => {
  it('encodes the declared qtype into the DNS question', async () => {
    let encodedQtype = null;
    const outcome = await probeDnsWireQuery(baseJob({
      probe_profile: {
        kind: 'dns_wire_query',
        dns_qtype: 'TXT',
        dns_transport: 'udp',
      },
    }), injectedResolutionDeps({
      createSocket: () => udpSocket({
        onSend(query) {
          encodedQtype = query.readUInt16BE(query.length - 4);
        },
      }),
    }));

    assert.equal(encodedQtype, 16);
    assert.equal(outcome.metadata.qtype, 'TXT');
    assert.equal(outcome.external_result, 'connected');
  });

  const fallbackCases = [
    { transport: 'auto', truncated: true, expectedTcpCalls: 1 },
    { transport: 'auto', truncated: false, expectedTcpCalls: 0 },
    { transport: 'udp', truncated: true, expectedTcpCalls: 0 },
  ];

  for (const { transport, truncated, expectedTcpCalls } of fallbackCases) {
    it(`${transport} transport with TC=${truncated} uses TCP ${expectedTcpCalls} time(s)`, async () => {
      let tcpCalls = 0;
      const outcome = await probeDnsWireQuery(baseJob({
        probe_profile: {
          kind: 'dns_wire_query',
          dns_qtype: 'A',
          dns_transport: transport,
        },
      }), injectedResolutionDeps({
        createSocket: () => udpSocket({ response: { truncated } }),
        connectFn: tcpConnector({}, () => { tcpCalls += 1; }),
      }));

      assert.equal(tcpCalls, expectedTcpCalls);
      assert.equal(outcome.metadata.tcp_fallback_used, expectedTcpCalls === 1);
      assert.equal(outcome.metadata.transport, expectedTcpCalls === 1 ? 'tcp' : 'udp');
    });
  }

  it('treats authoritative NXDOMAIN as evidence rather than blocked transport', async () => {
    const outcome = await probeDnsWireQuery(baseJob({
      check_id: 'dns.random_prefix_nxdomain.safe',
      target: { kind: 'ip', value: '203.0.113.53', metadata: { zone: 'example.test' } },
    }), injectedResolutionDeps({
      createSocket: () => udpSocket({ response: { rcode: 3, authoritative: true } }),
    }));

    assert.notEqual(outcome.external_result, 'blocked');
    assert.equal(outcome.external_result, 'connected');
    assert.equal(outcome.metadata.rcode, 3);
    assert.equal(outcome.metadata.authoritative, true);
    assert.equal(outcome.metadata.wildcard_response_detected, false);
  });

  it('marks a positive random-prefix answer as a wildcard response', async () => {
    const outcome = await probeDnsWireQuery(baseJob({
      check_id: 'dns.random_prefix_nxdomain.safe',
      target: { kind: 'ip', value: '203.0.113.53', metadata: { zone: 'example.test' } },
    }), injectedResolutionDeps({
      createSocket: () => udpSocket({ response: { rcode: 0, answerCount: 1 } }),
    }));

    assert.equal(outcome.metadata.query_name, 'random-prefix.example.test');
    assert.equal(outcome.metadata.wildcard_response_detected, true);
    assert.equal(outcome.metadata.answer_count, 1);
  });

  it('computes amplification ratio without returning response record data', async () => {
    const secretRecordData = 'SECRET_DNS_RECORD_DATA';
    let queryBytes = 0;
    const responseBytes = 96;
    const outcome = await probeDnsWireQuery(baseJob(), injectedResolutionDeps({
      createSocket: () => udpSocket({
        response: { answerCount: 1, size: responseBytes, data: secretRecordData },
        onSend(query) { queryBytes = query.length; },
      }),
    }));

    assert.equal(
      outcome.metadata.amplification_ratio,
      Math.round((responseBytes / queryBytes) * 100) / 100,
    );
    assert.equal(outcome.metadata.response_bytes, responseBytes);
    assert.equal(JSON.stringify(outcome).includes(secretRecordData), false);
    assert.equal(Object.hasOwn(outcome.metadata, 'answers'), false);
    assert.equal(Object.hasOwn(outcome.metadata, 'records'), false);
    assert.equal(Object.hasOwn(outcome.metadata, 'response'), false);
  });

  it('reports a null amplification ratio on timeout', async () => {
    const outcome = await probeDnsWireQuery(baseJob({
      constraints: { timeout_ms: 10, max_requests: 1 },
      probe_profile: {
        kind: 'dns_wire_query',
        dns_qtype: 'A',
        dns_transport: 'udp',
      },
    }), injectedResolutionDeps({
      createSocket: () => udpSocket({ respond: false }),
    }));

    assert.equal(outcome.external_result, 'timeout');
    assert.equal(outcome.metadata.amplification_ratio, null);
    assert.equal(outcome.metadata.response_bytes, 0);
  });
});
