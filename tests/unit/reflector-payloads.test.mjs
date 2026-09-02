import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import * as reflectorPayloadModule from '../../src/lib/reflectorPayloads.mjs';

const {
  MAX_PAYLOAD_BYTES,
  REFLECTOR_PAYLOADS,
  reflectorPayloadForProfile,
} = reflectorPayloadModule;

const BUILD_CONTEXT = {
  nonceHash: 'reflector-payload-test-nonce',
  queryName: 'probe.example.test',
};

const PAYLOAD_CASES = [
  ['ssdp_msearch', (payload) => {
    assert.equal(payload.subarray(0, 19).toString('ascii'), 'M-SEARCH * HTTP/1.1');
  }],
  ['snmp_v2c_get_sysdescr', (payload) => {
    assert.equal(payload[0], 0x30);
    assert.equal(payload.subarray(7, 13).toString('ascii'), 'public');
  }],
  ['mdns_ptr_query', (payload) => {
    assert.equal(payload.readUInt16BE(0), 0);
    assert.equal(payload.readUInt16BE(4), 1);
    assert.equal(payload.readUInt16BE(payload.length - 4), 12);
  }],
  ['netbios_nbstat', (payload) => {
    assert.equal(payload.readUInt16BE(4), 1);
    assert.equal(payload.readUInt16BE(payload.length - 4), 0x21);
  }],
  ['ws_discovery_probe', (payload) => {
    assert.equal(payload.subarray(0, 5).toString('ascii'), '<?xml');
    assert.match(payload.toString('utf8'), /<d:Probe\/>/);
  }],
  ['chargen_trigger', (payload) => assert.equal(payload.length, 0)],
  ['coap_get_wellknown', (payload) => {
    assert.equal(payload[0] >> 6, 1);
    assert.equal((payload[0] >> 4) & 0x03, 0);
    assert.equal(payload[1], 0x01);
  }],
  ['stun_binding_request', (payload) => {
    assert.equal(payload.readUInt16BE(0), 0x0001);
    assert.equal(payload.readUInt32BE(4), 0x2112a442);
    assert.equal(payload.length, 20);
  }],
  ['ipmi_rmcp_ping', (payload) => {
    assert.equal(payload[0], 0x06);
    assert.equal(payload[3], 0x06);
    assert.equal(payload[8], 0x80);
  }],
  ['mssql_resolution_request', (payload) => {
    assert.deepEqual(payload, Buffer.from([0x02]));
  }],
  ['tftp_read_request', (payload) => {
    assert.equal(payload.readUInt16BE(0), 1);
    assert.equal(payload.subarray(-6).toString('ascii'), 'octet\0');
  }],
  ['memcached_udp_stats', (payload) => {
    assert.equal(payload.readUInt16BE(4), 1);
    assert.equal(payload.subarray(8).toString('ascii'), 'stats\r\n');
  }],
  ['dtls_client_hello', (payload) => {
    assert.equal(payload[0], 0x16);
    assert.equal(payload.readUInt16BE(1), 0xfefd);
    assert.equal(payload[13], 0x01);
  }],
  ['portmap_dump', (payload) => {
    assert.equal((payload.readUInt32BE(0) & 0x80000000) >>> 0, 0x80000000);
    assert.equal(payload.readUInt32BE(16), 100000);
    assert.equal(payload.readUInt32BE(24), 4);
  }],
  ['ntp_mode6_readvar', (payload) => {
    assert.equal((payload[0] >> 3) & 0x07, 4);
    assert.equal(payload[0] & 0x07, 6);
    assert.equal(payload[1] & 0x1f, 2);
  }],
  ['cldap_root_dse', (payload) => {
    assert.equal(payload[0], 0x30);
    assert.equal(payload[5], 0x63);
  }],
  ['openvpn_reset', (payload) => assert.equal(payload[0] >> 3, 7)],
  ['jenkins_discovery', (payload) => assert.deepEqual(payload, Buffer.from([0x00]))],
  ['rip_v1_request', (payload) => {
    assert.equal(payload[0], 0x01);
    assert.equal(payload[1], 0x01);
  }],
  ['generic_probe', (payload) => {
    assert.equal(payload.subarray(0, 14).toString('ascii'), 'ASTRANULL:udp:');
  }],
];

describe('reflector payload profiles', () => {
  it('covers every table entry with a bounded protocol-signature assertion', () => {
    assert.deepEqual(
      PAYLOAD_CASES.map(([profile]) => profile).sort(),
      Object.keys(REFLECTOR_PAYLOADS).sort(),
    );

    for (const [profile, assertSignature] of PAYLOAD_CASES) {
      const definition = reflectorPayloadForProfile(profile);
      const payload = definition.build(BUILD_CONTEXT);
      assert.ok(Buffer.isBuffer(payload), `${profile} must build a Buffer`);
      assert.ok(
        payload.length <= MAX_PAYLOAD_BYTES,
        `${profile} exceeds ${MAX_PAYLOAD_BYTES} bytes`,
      );
      assertSignature(payload);
    }
  });

  it('rejects an injected non-hostname before encoding queryName', () => {
    assert.throws(
      () => REFLECTOR_PAYLOADS.mdns_ptr_query.build({
        ...BUILD_CONTEXT,
        queryName: 'safe.example\r\nIN TXT injected',
      }),
      /Invalid DNS query name/,
    );
  });

  it('does not expose count, repeat, or concurrency controls', () => {
    const forbidden = /(^|_)(count|repeat|concurrency)($|_)/i;
    const visited = new Set();
    const inspect = (value, path) => {
      if ((typeof value !== 'object' && typeof value !== 'function') || value === null) return;
      if (visited.has(value)) return;
      visited.add(value);
      for (const key of Object.keys(value)) {
        assert.doesNotMatch(key, forbidden, `${path}.${key} exposes a scaling control`);
        inspect(value[key], `${path}.${key}`);
      }
    };

    inspect(reflectorPayloadModule, 'reflectorPayloadModule');
    for (const definition of Object.values(REFLECTOR_PAYLOADS)) {
      assert.ok(definition.build.length <= 1);
    }
  });
});
