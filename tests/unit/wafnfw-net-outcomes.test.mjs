import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { describe, it } from 'node:test';
import {
  probeAxfrLeak,
  probeConnectionLimit,
  probePortScanBounded,
  ASTRANULL_PROBE_USER_AGENT,
  CAPABILITY_PROBE_DISPATCH,
} from '../../src/lib/capabilityProbes.mjs';
import {
  buildAxfrDnsMessage,
  frameDnsTcpMessage,
} from '../../src/lib/dnsTcpWire.mjs';
import {
  classifyTcpErrno,
  classifyUdpErrno,
  peerIsCdn,
  resolveDeclaredNetworkPort,
} from '../../src/lib/networkProbeOutcomes.mjs';
import { sourcePerspectiveFromEnv } from '../../src/lib/probeSourcePerspective.mjs';
import { VETTED_SCAN_PORTS, VETTED_SCAN_PORT_SET } from '../../src/lib/probeEndpoint.mjs';
import {
  payloadProfilesForJob,
  reflectorPayloadForProfile,
  validateReflectionResponse,
  COMPOSITE_PAYLOAD_PROFILES,
} from '../../src/lib/reflectorPayloads.mjs';
import {
  probeTcpConnect,
  probeUdpDatagram,
  probeReflectionService,
} from '../../src/lib/safeNetworkProbes.mjs';
import { ASTRANULL_PROBE_USER_AGENT as PINNED_UA } from '../../src/lib/pinnedHttpRequest.mjs';

function tcpJob(overrides = {}) {
  return {
    id: 'pjob_nfw',
    check_id: 'l3.forbidden_tcp_port.safe',
    constraints: { timeout_ms: 200, max_requests: 2 },
    probe_profile: { kind: 'tcp_connect', max_requests: 2, timeout_ms: 200 },
    target: { kind: 'fqdn', value: 'origin.test', port: 443 },
    ...overrides,
  };
}

function udpJob(overrides = {}) {
  return {
    id: 'pjob_nfw_udp',
    check_id: 'l3.forbidden_udp_port.safe',
    constraints: { timeout_ms: 200, max_requests: 2 },
    probe_profile: { kind: 'udp_probe', max_requests: 2, timeout_ms: 200 },
    target: { kind: 'fqdn', value: 'origin.test', port: 53 },
    ...overrides,
  };
}

function errorSocket(code) {
  const socket = new EventEmitter();
  socket.destroy = () => {};
  socket.end = () => {};
  queueMicrotask(() => socket.emit('error', Object.assign(new Error(code), { code })));
  return socket;
}

function handshakeSocket() {
  const socket = new EventEmitter();
  socket.destroy = () => {};
  socket.end = () => {};
  queueMicrotask(() => socket.emit('connect'));
  return socket;
}

function connectedUdpSocket({ onSend, errorCode, reply } = {}) {
  const socket = new EventEmitter();
  socket.closeCount = 0;
  socket.peer = null;
  socket.connect = (port, host, cb) => {
    socket.peer = { port, host };
    queueMicrotask(() => cb?.());
  };
  socket.send = (payload, a, b, c) => {
    const cb = typeof a === 'function' ? a : typeof c === 'function' ? c : null;
    const usedConnectedSend = typeof a === 'function';
    onSend?.({ payload, connected: Boolean(socket.peer), usedConnectedSend, port: socket.peer?.port, host: socket.peer?.host });
    cb?.(null);
    if (errorCode) {
      queueMicrotask(() => socket.emit('error', Object.assign(new Error(errorCode), { code: errorCode })));
    } else if (reply) {
      queueMicrotask(() => socket.emit('message', reply, {
        address: socket.peer.host,
        port: socket.peer.port,
      }));
    }
  };
  socket.close = () => { socket.closeCount += 1; };
  return socket;
}

function refusedAxfrFrame(zone, transactionId = 0x4242) {
  const dns = buildAxfrDnsMessage(zone, { transactionId });
  dns.writeUInt16BE(0x8005, 2);
  return frameDnsTcpMessage(dns);
}

function axfrSocket(framed) {
  return {
    once(event, handler) {
      if (event === 'connect') setImmediate(handler);
    },
    on(event, handler) {
      if (event === 'data') setImmediate(() => handler(framed));
    },
    write() {},
    destroy() {},
  };
}

describe('T2 NFW TCP/UDP outcome classes (F19)', () => {
  it('classifies TCP handshake, RST, ICMP reject, and timeout separately', async () => {
    assert.equal(classifyTcpErrno('ECONNREFUSED').tcp_outcome, 'refused_rst');
    assert.equal(classifyTcpErrno('EHOSTUNREACH').tcp_outcome, 'rejected_icmp');
    assert.equal(classifyTcpErrno('EHOSTUNREACH').icmp.kind, 'host_unreachable');
    assert.equal(classifyTcpErrno('ENETUNREACH').icmp.kind, 'net_unreachable');
    assert.deepEqual(classifyTcpErrno('EPERM'), { tcp_outcome: 'error', icmp: null, local_error: true });

    const handshake = await probeTcpConnect(tcpJob({
      constraints: { timeout_ms: 200, max_requests: 1 },
      probe_profile: { kind: 'tcp_connect', max_requests: 1 },
    }), {
      sampleGapMs: 0,
      vettedHost: 'origin.test',
      vettedAddresses: ['203.0.113.20'],
      connectFn: () => handshakeSocket(),
    });
    assert.equal(handshake.metadata.tcp_outcome, 'handshake');
    assert.equal(handshake.external_result, 'connected');
    assert.equal(handshake.metadata.service_validated, true);

    const rst = await probeTcpConnect(tcpJob({
      constraints: { timeout_ms: 200, max_requests: 1 },
      probe_profile: { kind: 'tcp_connect', max_requests: 1 },
    }), {
      sampleGapMs: 0,
      vettedHost: 'origin.test',
      vettedAddresses: ['203.0.113.20'],
      connectFn: () => errorSocket('ECONNREFUSED'),
    });
    assert.equal(rst.metadata.tcp_outcome, 'refused_rst');
    assert.equal(rst.external_result, 'blocked');
    assert.equal(rst.metadata.icmp, null);

    const icmp = await probeTcpConnect(tcpJob({
      constraints: { timeout_ms: 200, max_requests: 1 },
      probe_profile: { kind: 'tcp_connect', max_requests: 1 },
    }), {
      sampleGapMs: 0,
      vettedHost: 'origin.test',
      vettedAddresses: ['203.0.113.20'],
      connectFn: () => errorSocket('EHOSTUNREACH'),
    });
    assert.equal(icmp.metadata.tcp_outcome, 'rejected_icmp');
    assert.equal(icmp.metadata.icmp.kind, 'host_unreachable');
    assert.equal(icmp.metadata.icmp.errno, 'EHOSTUNREACH');
  });

  it('uses a connected UDP socket so ICMP port-unreachable surfaces', async () => {
    assert.equal(classifyUdpErrno('ECONNREFUSED').udp_outcome, 'port_unreachable');
    assert.equal(classifyUdpErrno('ECONNREFUSED').icmp.kind, 'port_unreachable');
    assert.deepEqual(classifyUdpErrno('EACCES'), { udp_outcome: 'error', icmp: null, local_error: true });

    let sendShape;
    const socket = connectedUdpSocket({
      errorCode: 'ECONNREFUSED',
      onSend: (info) => { sendShape = info; },
    });
    const outcome = await probeUdpDatagram(udpJob({
      constraints: { timeout_ms: 200, max_requests: 1 },
      probe_profile: { kind: 'udp_probe', max_requests: 1 },
    }), {
      sampleGapMs: 0,
      vettedHost: 'origin.test',
      vettedAddresses: ['203.0.113.20'],
      createSocket: () => socket,
    });
    assert.equal(sendShape.usedConnectedSend, true);
    assert.equal(outcome.metadata.udp_outcome, 'port_unreachable');
    assert.equal(outcome.external_result, 'timeout');
    assert.equal(outcome.metadata.service_validated, false);
  });

  it('records an unvalidated UDP reply instead of discarding it', async () => {
    const socket = connectedUdpSocket({ reply: Buffer.from('not-a-protocol') });
    const outcome = await probeUdpDatagram(udpJob({
      constraints: { timeout_ms: 200, max_requests: 1 },
      probe_profile: { kind: 'udp_probe', max_requests: 1 },
    }), {
      sampleGapMs: 0,
      vettedHost: 'origin.test',
      vettedAddresses: ['203.0.113.20'],
      createSocket: () => socket,
    });
    assert.equal(outcome.metadata.udp_outcome, 'unvalidated_reply');
    assert.equal(outcome.external_result, 'connected');
    assert.equal(outcome.metadata.service_validated, false);
  });
});

describe('T2 reflection identity validators (F20)', () => {
  const ctx = { nonceHash: 'nfw-identity', queryName: '_services._dns-sd._udp.local' };

  it('validates CLDAP, CHARGEN, TFTP, MSSQL, Jenkins, WS-Discovery, IPMI, OpenVPN, TP-240, L2TP', () => {
    const cases = [
      ['cldap_root_dse', Buffer.from([0x30, 0x07, 0x02, 0x01, 0x01, 0x64, 0x02, 0x01, 0x00])],
      ['chargen_trigger', Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWXYZ\r\n')],
      ['tftp_read_request', Buffer.from([0x00, 0x05, 0x00, 0x01, 0x66, 0x00])],
      ['mssql_resolution_request', Buffer.from([0x05, 0x04, 0x00, 0x41, 0x42, 0x43, 0x44])],
      ['jenkins_discovery', Buffer.from('http://jenkins.example:8080 1')],
      ['ipmi_rmcp_ping', Buffer.from([0x06, 0x00, 0xff, 0x06, 0x00, 0x00, 0x11, 0xbe, 0x40, 0x00, 0x00, 0x00])],
      ['openvpn_reset', Buffer.concat([Buffer.from([0x40]), Buffer.alloc(13)])],
    ];
    for (const [profile, response] of cases) {
      const spec = reflectorPayloadForProfile(profile);
      assert.equal(spec.identity_supported, true, profile);
      const request = spec.build(ctx);
      assert.equal(validateReflectionResponse(profile, request, response), true, profile);
      assert.equal(validateReflectionResponse(profile, request, Buffer.from([0xff, 0x00, 0x01, 0x80])), false, `${profile} junk`);
    }

    const ws = reflectorPayloadForProfile('ws_discovery_probe');
    const wsReq = ws.build(ctx);
    const id = /<w:MessageID>([^<]+)</.exec(wsReq.toString())[1];
    const wsOk = Buffer.from(
      '<?xml version="1.0"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
        + `<s:Header><a:RelatesTo>${id}</a:RelatesTo></s:Header>`
        + '<s:Body><d:ProbeMatches xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
        + '</d:ProbeMatches></s:Body></s:Envelope>',
    );
    assert.equal(validateReflectionResponse('ws_discovery_probe', wsReq, wsOk), true);

    const tp240 = reflectorPayloadForProfile('tp240_status_request');
    const tpReq = tp240.build(ctx);
    const tpOk = Buffer.concat([Buffer.alloc(4), tpReq.subarray(4, 6), Buffer.alloc(4)]);
    assert.equal(tp240.identity_supported, true);
    assert.equal(validateReflectionResponse('tp240_status_request', tpReq, tpOk), true);

    const l2tp = reflectorPayloadForProfile('l2tp_sccrq');
    const l2Req = l2tp.build(ctx);
    const l2Ok = Buffer.alloc(20);
    l2Ok.writeUInt16BE(0xc802, 0);
    l2Ok.writeUInt16BE(20, 2);
    l2Ok.writeUInt16BE(2, 18);
    assert.equal(l2tp.identity_supported, true);
    assert.equal(validateReflectionResponse('l2tp_sccrq', l2Req, l2Ok), true);
  });

  it('sends named composite protocols within budget and records per-protocol sub-results', async () => {
    assert.deepEqual(COMPOSITE_PAYLOAD_PROFILES.mdns_netbios_wsdiscovery, [
      'mdns_ptr_query', 'netbios_nbstat', 'ws_discovery_probe',
    ]);
    const names = payloadProfilesForJob({
      check_id: 'reflect.mdns_netbios_wsdiscovery_exposure.safe',
      probe_profile: { kind: 'reflection_service_probe' },
    });
    assert.deepEqual(names, COMPOSITE_PAYLOAD_PROFILES.mdns_netbios_wsdiscovery);

    const sent = [];
    const outcome = await probeReflectionService({
      check_id: 'reflect.mdns_netbios_wsdiscovery_exposure.safe',
      nonce_hash: 'composite',
      target: { value: 'origin.test', port: 5353 },
      probe_profile: { kind: 'reflection_service_probe' },
      constraints: { timeout_ms: 200, max_requests: 2 },
    }, {
      vettedHost: 'origin.test',
      vettedAddresses: ['203.0.113.20'],
      createSocket: () => connectedUdpSocket({
        reply: Buffer.from('not-identity'),
        onSend: (info) => sent.push(info.port),
      }),
    });
    assert.equal(outcome.metadata.udp_outcome, 'unvalidated_reply');
    assert.equal(outcome.external_result, 'not_run');
    assert.ok(outcome.metadata.protocol_results.length >= 1);
    assert.equal(outcome.metadata.protocol_results[0].udp_outcome, 'unvalidated_reply');
    assert.deepEqual(outcome.metadata.payload_profiles_sent, outcome.metadata.protocol_results.map((row) => row.payload_profile));
    assert.ok(outcome.metadata.payload_profiles_declared.includes('mdns_ptr_query'));
    assert.ok(sent.length <= 2);
  });
});

describe('T2 address families, ports, samples, CDN (F14/F07/F21)', () => {
  it('resolves ports in CONTRACT §3 order and refuses a missing port with zero requests', async () => {
    const job = {
      probe_profile: {
        port: 22,
        default_port: 80,
        declarations: { network_policy: [{ protocol: 'tcp', port: 443 }] },
      },
      target: { value: 'origin.test', port: 8080 },
    };
    assert.equal(resolveDeclaredNetworkPort(job, { protocol: 'tcp' }), 22);
    assert.equal(resolveDeclaredNetworkPort({
      probe_profile: { default_port: 80, declarations: { network_policy: [{ protocol: 'tcp', port: 443 }] } },
      target: { value: 'origin.test', port: 8080 },
    }, { protocol: 'tcp' }), 8080);
    assert.equal(resolveDeclaredNetworkPort({
      probe_profile: { default_port: 80, declarations: { network_policy: [{ protocol: 'tcp', port: 443 }] } },
      target: { value: 'origin.test' },
    }, { protocol: 'tcp' }), 443);
    assert.equal(resolveDeclaredNetworkPort({
      probe_profile: { default_port: 80 },
      target: { value: 'origin.test' },
    }, { protocol: 'tcp' }), 80);

    const missing = await probeTcpConnect({
      probe_profile: { kind: 'tcp_connect' },
      target: { value: 'origin.test' },
      constraints: { timeout_ms: 100, max_requests: 1 },
    }, { connectFn: () => { throw new Error('must not connect'); } });
    assert.equal(missing.result, 'unsupported_target');
    assert.equal(missing.reason, 'no_port_declared');
    assert.equal(missing.requests_sent, 0);
  });

  it('probes A and AAAA separately and reports family parity', async () => {
    const codes = [];
    const outcome = await probeTcpConnect(tcpJob({
      constraints: { timeout_ms: 400, max_requests: 2 },
      probe_profile: { kind: 'tcp_connect', address_family: 'both', max_requests: 2 },
    }), {
      sampleGapMs: 0,
      vettedHost: 'origin.test',
      vettedAddresses: ['203.0.113.20', '2001:db8::20'],
      connectFn: ({ host }) => {
        codes.push(host);
        return host.includes(':') ? errorSocket('ECONNREFUSED') : handshakeSocket();
      },
    });
    assert.ok(outcome.metadata.families.ipv4);
    assert.ok(outcome.metadata.families.ipv6);
    assert.equal(outcome.metadata.parity, 'mismatch');
    assert.equal(outcome.metadata.families.ipv4.tcp_outcome, 'handshake');
    assert.equal(outcome.metadata.families.ipv6.tcp_outcome, 'refused_rst');
    assert.deepEqual(codes, ['203.0.113.20', '2001:db8::20']);
  });

  it('takes two TCP samples spaced by the injected gap and reports sample_agreement', async () => {
    let connects = 0;
    const outcome = await probeTcpConnect(tcpJob({
      constraints: { timeout_ms: 400, max_requests: 2 },
      probe_profile: { kind: 'tcp_connect', address_family: 'ipv4', max_requests: 2 },
    }), {
      sampleGapMs: 0,
      vettedHost: 'origin.test',
      vettedAddresses: ['203.0.113.20'],
      connectFn: () => {
        connects += 1;
        return handshakeSocket();
      },
    });
    assert.equal(connects, 2);
    assert.equal(outcome.metadata.samples.length, 2);
    assert.equal(outcome.metadata.sample_agreement, 'agree');
    assert.equal(outcome.requests_sent, 2);
  });

  it('emits peer_is_cdn from existing CDN range data', async () => {
    assert.equal(peerIsCdn('108.138.5.5'), true);
    assert.equal(peerIsCdn('203.0.113.20'), false);
    const outcome = await probeTcpConnect(tcpJob({
      constraints: { timeout_ms: 200, max_requests: 1 },
      probe_profile: { kind: 'tcp_connect', max_requests: 1 },
    }), {
      sampleGapMs: 0,
      vettedHost: 'origin.test',
      vettedAddresses: ['108.138.5.5'],
      connectFn: () => handshakeSocket(),
    });
    assert.equal(outcome.metadata.peer_is_cdn, true);
  });

  it('port scan accepts a vetted declared list, rejects outsiders, retries silent ports, and emits extra fields', async () => {
    assert.ok(VETTED_SCAN_PORT_SET.has(3306));
    assert.ok(VETTED_SCAN_PORTS.includes(2049));
    const probed = [];
    const outcome = await probePortScanBounded({
      constraints: { timeout_ms: 2000, max_requests: 8 },
      target: { kind: 'ip', value: '203.0.113.20' },
      probe_profile: {
        kind: 'port_scan_bounded',
        declared_ports: [443, 3306, 9999, 22],
        address_family: 'ipv4',
      },
    }, {
      connectFn: ({ port }) => {
        probed.push(port);
        if (port === 22 && probed.filter((value) => value === 22).length === 1) {
          const socket = new EventEmitter();
          socket.destroy = () => {};
          queueMicrotask(() => socket.emit('error', Object.assign(new Error('ETIMEDOUT'), { code: 'ETIMEDOUT' })));
          return socket;
        }
        if (port === 22) return handshakeSocket();
        if (port === 443) return errorSocket('ECONNREFUSED');
        if (port === 3306) return errorSocket('EHOSTUNREACH');
        return errorSocket('ECONNREFUSED');
      },
    });
    assert.equal(outcome.metadata.declared_port_list_used, true);
    assert.ok(outcome.metadata.rejected_declared_ports.includes(9999));
    assert.ok(!outcome.metadata.ports_scanned.includes(9999));
    assert.deepEqual(outcome.metadata.open_ports, [22]);
    assert.deepEqual(outcome.metadata.closed_ports, [443]);
    assert.deepEqual(outcome.metadata.rejected_ports, [3306]);
    assert.ok(probed.filter((port) => port === 22).length === 2);
    assert.ok(outcome.metadata.ports_scanned.includes(443));
  });
});

describe('T2 connection-limit, perspectives, UA, AXFR (F12/F25/F29)', () => {
  it('connection_limit_probe requires a declaration and caps at 12', async () => {
    const missing = await probeConnectionLimit({
      probe_profile: { kind: 'connection_limit_probe' },
      target: { value: 'origin.test', port: 443 },
    });
    assert.equal(missing.result, 'unsupported_target');
    assert.equal(missing.reason, 'no_connection_limit_declared');
    assert.equal(missing.requests_sent, 0);

    let opens = 0;
    const sockets = [];
    const outcome = await probeConnectionLimit({
      constraints: { timeout_ms: 30, max_requests: 12 },
      probe_profile: {
        kind: 'connection_limit_probe',
        declarations: { connection_limits: [{ protocol: 'tcp', port: 443, max_connections_per_source: 3 }] },
      },
      target: { value: 'origin.test' },
    }, {
      vettedHost: 'origin.test',
      vettedAddresses: ['203.0.113.20'],
      connectFn: () => {
        opens += 1;
        if (opens > 3) return errorSocket('ECONNREFUSED');
        const socket = handshakeSocket();
        sockets.push(socket);
        return socket;
      },
    });
    assert.equal(outcome.metadata.declared_limit, 3);
    assert.equal(outcome.metadata.attempted, 5);
    assert.equal(outcome.metadata.accepted_count, 3);
    assert.equal(outcome.metadata.refused_after, 3);
    assert.equal(outcome.metadata.port, 443);
    assert.ok(CAPABILITY_PROBE_DISPATCH.connection_limit_probe);
  });

  it('reads worker source perspective from env and stamps results', async () => {
    const perspective = sourcePerspectiveFromEnv({
      ASTRANULL_PROBE_PERSPECTIVE_ID: 'eu-west',
      ASTRANULL_PROBE_PERSPECTIVE_LABEL: 'EU West',
    });
    assert.equal(perspective.id, 'eu-west');
    assert.equal(perspective.label, 'EU West');
    assert.equal(sourcePerspectiveFromEnv({}).id, 'default');

    const outcome = await probeTcpConnect(tcpJob({
      constraints: { timeout_ms: 200, max_requests: 1 },
      probe_profile: { kind: 'tcp_connect', max_requests: 1 },
    }), {
      sampleGapMs: 0,
      sourcePerspective: perspective,
      vettedHost: 'origin.test',
      vettedAddresses: ['203.0.113.20'],
      connectFn: () => handshakeSocket(),
    });
    assert.equal(outcome.metadata.source_perspective.id, 'eu-west');
    assert.equal(outcome.metadata.source_perspective.label, 'EU West');
  });

  it('exports the documented probe User-Agent', () => {
    assert.equal(ASTRANULL_PROBE_USER_AGENT, 'AstraNull-Probe/1.0 (+https://astranull.io/probe)');
    assert.equal(PINNED_UA, ASTRANULL_PROBE_USER_AGENT);
  });

  it('queries every listed NS within budget and requires every NS refused for enforcement', async () => {
    const framed = refusedAxfrFrame('example.test');
    const hosts = [];
    const outcome = await probeAxfrLeak({
      constraints: { timeout_ms: 1000, max_requests: 4 },
      probe_profile: { kind: 'dns_axfr_leak', max_requests: 4 },
      target: { kind: 'fqdn', value: 'example.test' },
    }, {
      axfrTransactionId: 0x4242,
      resolveNsFn: async () => ['ns1.example.test', 'ns2.example.test'],
      resolve4Fn: async (host) => {
        hosts.push(host);
        return host === 'ns1.example.test' ? ['203.0.113.53'] : ['198.51.100.53'];
      },
      resolve6Fn: async () => [],
      connectFn: ({ host }) => {
        hosts.push(['tcp', host]);
        return axfrSocket(framed);
      },
    });
    assert.equal(outcome.metadata.nameserver_results.length, 2);
    assert.ok(outcome.metadata.nameserver_results.every((row) => row.axfr_refused === true));
    assert.equal(outcome.metadata.enforcement, 'enforced');
    assert.equal(outcome.external_result, 'blocked');

    const allowedFrame = (() => {
      const dns = buildAxfrDnsMessage('example.test', { transactionId: 0x4242 });
      dns.writeUInt16BE(0x8400, 2);
      return frameDnsTcpMessage(dns);
    })();
    let nsIndex = 0;
    const mixed = await probeAxfrLeak({
      constraints: { timeout_ms: 1000, max_requests: 4 },
      probe_profile: { kind: 'dns_axfr_leak', max_requests: 4 },
      target: { kind: 'fqdn', value: 'example.test' },
    }, {
      axfrTransactionId: 0x4242,
      resolveNsFn: async () => ['ns1.example.test', 'ns2.example.test'],
      resolve4Fn: async (host) => (host === 'ns1.example.test' ? ['203.0.113.53'] : ['198.51.100.53']),
      resolve6Fn: async () => [],
      connectFn: () => {
        nsIndex += 1;
        return axfrSocket(nsIndex === 1 ? framed : allowedFrame);
      },
    });
    assert.equal(mixed.metadata.enforcement, 'not_enforced');
  });
});
