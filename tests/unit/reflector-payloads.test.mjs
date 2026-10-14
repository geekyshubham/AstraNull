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
  ['sip_options', (payload) => {
    assert.equal(payload.subarray(0, 7).toString('ascii'), 'OPTIONS');
  }],
  ['rdp_udp_syn', (payload) => {
    assert.equal(payload.readUInt32BE(0), 0xffffffff);
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


describe('bounded reflection golden response identity', () => {
  const check = reflectorPayloadModule.validateReflectionResponse;
  const requestFor = (profile) => REFLECTOR_PAYLOADS[profile].build(BUILD_CONTEXT);
  it('accepts only complete matched STUN identities, never byte counts or a matching-size packet', () => {
    const request = requestFor('stun_binding_request');
    const response = Buffer.from(request); response.writeUInt16BE(0x0101, 0);
    assert.equal(check('stun_binding_request', request, response), true);
    const wrongId = Buffer.from(response); wrongId[8] ^= 1;
    for (const bad of [wrongId, Buffer.alloc(response.length), response.subarray(0, 19), response.length]) {
      assert.equal(check('stun_binding_request', request, bad), false);
    }
  });
  it('requires a full matched SNMP PDU and varbind rather than the outer envelope alone', () => {
    const request = requestFor('snmp_v2c_get_sysdescr');
    const good = Buffer.from(request);
    good[good.indexOf(0xa0)] = 0xa2;
    good[good.length - 2] = 4; // valid empty sysDescr octet string
    assert.equal(check('snmp_v2c_get_sysdescr', request, good), true);
    for (const mutate of [(b) => { b[17] ^= 1; }, (b) => { b[b.length - 3] ^= 1; }, (b) => { b[b.length - 1] = 1; }]) {
      const bad = Buffer.from(good); mutate(bad); assert.equal(check('snmp_v2c_get_sysdescr', request, bad), false);
    }
    assert.equal(check('snmp_v2c_get_sysdescr', request, good.subarray(0, 22)), false);
  });
  it('requires CoAP message identity and complete option/payload framing', () => {
    const request = requestFor('coap_get_wellknown');
    const good = Buffer.from([0x60, 0x45, request[2], request[3]]);
    assert.equal(check('coap_get_wellknown', request, good), true);
    for (const bad of [Buffer.concat([good, Buffer.from([0xff])]), Buffer.concat([good, Buffer.from([0xff, 1])]).subarray(0, 5),
      Buffer.concat([good, Buffer.from([0x1f])]), Buffer.concat([good, Buffer.from([0x0d])]), Buffer.from([0x60, 0x45, request[2] ^ 1, request[3]])]) {
      assert.equal(check('coap_get_wellknown', request, bad), false);
    }
  });
  it('rejects truncated NTP read-variable messages and fragmented replies', () => {
    const request = requestFor('ntp_mode6_readvar');
    const good = Buffer.from(request); good[1] = 0x82;
    assert.equal(check('ntp_mode6_readvar', request, good), true);
    const more = Buffer.from(good); more[1] |= 0x20;
    const count = Buffer.from(good); count.writeUInt16BE(1, 10);
    const wrongVersion = Buffer.from(good); wrongVersion[0] = 0x06;
    const wrongAssociation = Buffer.from(good); wrongAssociation[6] = 1;
    assert.equal(check('ntp_mode6_readvar', request, wrongVersion), false);
    assert.equal(check('ntp_mode6_readvar', request, wrongAssociation), false);
    assert.equal(check('ntp_mode6_readvar', request, more), false);
    assert.equal(check('ntp_mode6_readvar', request, count), false);
  });
  it('requires exact DNS questions plus matched typed PTR answers', () => {
    const request = requestFor('mdns_ptr_query');
    const good = Buffer.from(Buffer.concat([request, Buffer.from([0xc0, 0x0c, 0, 12, 0, 1, 0, 0, 0, 0, 0, 1, 0])]));
    good.writeUInt16BE(0x8000, 2); good.writeUInt16BE(1, 6);
    assert.equal(check('mdns_ptr_query', request, good), true);
    const wrongQuestion = Buffer.from(good); wrongQuestion[13] ^= 1;
    const badRdata = Buffer.from(good); badRdata[badRdata.length - 1] = 0xff;
    for (const bad of [wrongQuestion, badRdata, Buffer.concat([good, Buffer.from([0])])]) assert.equal(check('mdns_ptr_query', request, bad), false);
  });
  it('accepts complete same-XID RPC results, not truncated or wrong-XID frames', () => {
    const request = requestFor('portmap_dump');
    const good = Buffer.alloc(32); good.writeUInt32BE(0x8000001c, 0); request.copy(good, 4, 4, 8); good.writeUInt32BE(1, 8);
    assert.equal(check('portmap_dump', request, good), true);
    const wrongId = Buffer.from(good); wrongId[4] ^= 1;
    assert.equal(check('portmap_dump', request, wrongId), false);
    assert.equal(check('portmap_dump', request, good.subarray(0, 31)), false);
  });
  it('requires complete valid SSDP status/header syntax and unambiguous matching ST/USN', () => {
    const request = requestFor('ssdp_msearch');
    const good = 'HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nUSN: uuid:12345678-1234-1234-1234-123456789abc::upnp:rootdevice\r\n\r\n';
    assert.equal(check('ssdp_msearch', request, Buffer.from(good)), true);
    for (const text of [good.replace('200 OK', '200garbage'), good.replace('200 OK', '200  OK\n'),
      good.replace('ST: ', 'Malformed-Header\r\nST: '), good.replace('ST: ', 'ST: unrelated\r\nST: '),
      good.replace('USN: ', 'USN: uuid:other\r\nUSN: '), good.replace('::upnp:rootdevice', '::unrelated'),
      good.replace('ST: ', ' ST: '), good.replace('200 OK', '200 \x80'), good + 'trailing', good.slice(0, -1)]) {
      assert.equal(check('ssdp_msearch', request, Buffer.from(text, 'latin1')), false, JSON.stringify(text));
    }
  });
  it('validates every memcached STAT line, not just a valid prefix and END trailer', () => {
    const request = requestFor('memcached_udp_stats');
    const header = request.subarray(0, 8);
    const good = Buffer.concat([header, Buffer.from('STAT pid 123\r\nSTAT uptime 7\r\nEND\r\n')]);
    assert.equal(check('memcached_udp_stats', request, good), true);
    for (const body of ['STAT pid 123\r\nmalformed\r\nEND\r\n', 'STAT pid 123\r\n\r\nEND\r\n',
      'STAT pid\r\nEND\r\n', 'STAT pid 123\nEND\r\n', 'STAT pid 123\r\nEND\r\ntrailing',
      'STAT pid 123\r\nSTAT odd \x80\r\nEND\r\n']) {
      assert.equal(check('memcached_udp_stats', request, Buffer.concat([header, Buffer.from(body, 'latin1')])), false);
    }
    const fragmented = Buffer.from(good); fragmented.writeUInt16BE(2, 4);
    assert.equal(check('memcached_udp_stats', request, fragmented), false);
  });
  it('does not regex-confirm malformed WS-Discovery XML without a complete parser', () => {
    const request = requestFor('ws_discovery_probe');
    const id = /<w:MessageID>([^<]+)</.exec(request.toString())[1];
    const malformed = Buffer.from(`<ProbeMatches><RelatesTo>${id}</RelatesTo>schemas.xmlsoap.org/ws/2005/04/discovery`);
    assert.equal(REFLECTOR_PAYLOADS.ws_discovery_probe.identity_supported, true);
    assert.equal(check('ws_discovery_probe', request, malformed), false);
  });
});
