import { createHash, randomBytes } from 'node:crypto';
import { buildDnsQueryMessage } from './dnsTcpWire.mjs';
import { extraReflectorPayloadForProfile } from './vectorProbes/extraReflectorPayloads.mjs';

export const MAX_PAYLOAD_BYTES = 512;

function boundedPayload(build) {
  return (ctx = {}) => {
    const payload = build(ctx);
    if (!Buffer.isBuffer(payload)) throw new TypeError('Reflector payload builders must return a Buffer.');
    if (payload.length > MAX_PAYLOAD_BYTES) {
      throw new RangeError(`Reflector payload exceeds ${MAX_PAYLOAD_BYTES} bytes.`);
    }
    return payload;
  };
}

function stableIdentifier(value, length) {
  return createHash('sha256').update(String(value ?? 'astranull-probe')).digest().subarray(0, length);
}

function validateQueryName(value) {
  const queryName = String(value ?? '').replace(/\.$/, '');
  if (queryName.length < 1 || queryName.length > 253) throw new RangeError('Invalid DNS query name.');
  const labels = queryName.split('.');
  if (labels.some((label) => (
    label.length < 1
    || label.length > 63
    || !/^[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?$/.test(label)
  ))) {
    throw new RangeError('Invalid DNS query name.');
  }
  return queryName;
}

function responseSizeClass(byteCount) {
  if (byteCount === 0) return 'none';
  if (byteCount <= 64) return 'tiny';
  if (byteCount <= 512) return 'small';
  if (byteCount <= 1200) return 'medium';
  return 'large';
}

function classifyReflection(requestBytes, responseBytes, responseReceived = responseBytes != null) {
  const requestLength = Buffer.isBuffer(requestBytes)
    ? requestBytes.length
    : Math.max(0, Number(requestBytes) || 0);
  const responseLength = Buffer.isBuffer(responseBytes)
    ? responseBytes.length
    : Math.max(0, Number(responseBytes) || 0);
  return {
    amplification_ratio: responseReceived && requestLength > 0
      ? Math.round((responseLength / requestLength) * 100) / 100
      : null,
    response_size_class: responseReceived ? responseSizeClass(responseLength) : 'none',
    reflector_confirmed: Boolean(responseReceived),
  };
}

function buildSnmpGetRequest(ctx) {
  const requestId = stableIdentifier(ctx.nonceHash, 4);
  const oid = Buffer.from([0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]);
  const variableBinding = Buffer.concat([Buffer.from([0x30, 0x0c]), oid, Buffer.from([0x05, 0x00])]);
  const variableBindings = Buffer.concat([Buffer.from([0x30, variableBinding.length]), variableBinding]);
  const pduBody = Buffer.concat([
    Buffer.from([0x02, 0x04]), requestId,
    Buffer.from([0x02, 0x01, 0x00, 0x02, 0x01, 0x00]),
    variableBindings,
  ]);
  const pdu = Buffer.concat([Buffer.from([0xa0, pduBody.length]), pduBody]);
  const body = Buffer.concat([
    Buffer.from([0x02, 0x01, 0x01, 0x04, 0x06]),
    Buffer.from('public', 'ascii'),
    pdu,
  ]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

function buildNetbiosNbstat(ctx) {
  const rawName = Buffer.concat([Buffer.from('*', 'ascii'), Buffer.alloc(15, 0x20)]);
  const encodedName = Buffer.alloc(32);
  for (let index = 0; index < rawName.length; index += 1) {
    encodedName[index * 2] = 0x41 + (rawName[index] >> 4);
    encodedName[index * 2 + 1] = 0x41 + (rawName[index] & 0x0f);
  }
  const header = Buffer.alloc(12);
  stableIdentifier(ctx.nonceHash, 2).copy(header, 0);
  header.writeUInt16BE(1, 4);
  return Buffer.concat([
    header,
    Buffer.from([0x20]),
    encodedName,
    Buffer.from([0x00, 0x00, 0x21, 0x00, 0x01]),
  ]);
}

function buildWsDiscoveryProbe(ctx) {
  const messageId = stableIdentifier(ctx.nonceHash, 16).toString('hex');
  return Buffer.from(
    '<?xml version="1.0" encoding="UTF-8"?>'
      + '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
      + 'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
      + 'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
      + '<e:Header><w:MessageID>urn:uuid:' + messageId + '</w:MessageID>'
      + '<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>'
      + '<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>'
      + '</e:Header><e:Body><d:Probe/></e:Body></e:Envelope>',
    'utf8',
  );
}

function buildDtlsClientHello(ctx) {
  const random = stableIdentifier(ctx.nonceHash, 32);
  const body = Buffer.concat([
    Buffer.from([0xfe, 0xfd]),
    random,
    Buffer.from([0x00, 0x00, 0x00, 0x02, 0xc0, 0x2f, 0x01, 0x00, 0x00, 0x00]),
  ]);
  const handshake = Buffer.alloc(12);
  handshake[0] = 0x01;
  handshake.writeUIntBE(body.length, 1, 3);
  handshake.writeUIntBE(body.length, 9, 3);
  const record = Buffer.alloc(13);
  record[0] = 0x16;
  record.writeUInt16BE(0xfefd, 1);
  record.writeUInt16BE(handshake.length + body.length, 11);
  return Buffer.concat([record, handshake, body]);
}

function buildPortmapDump(ctx) {
  const body = Buffer.alloc(40);
  stableIdentifier(ctx.nonceHash, 4).copy(body, 0);
  body.writeUInt32BE(0, 4);
  body.writeUInt32BE(2, 8);
  body.writeUInt32BE(100000, 12);
  body.writeUInt32BE(2, 16);
  body.writeUInt32BE(4, 20);
  const record = Buffer.alloc(4);
  record.writeUInt32BE(0x80000000 + body.length, 0);
  return Buffer.concat([record, body]);
}

function buildCldapRootDse() {
  const filter = Buffer.concat([Buffer.from([0x87, 0x0b]), Buffer.from('objectClass', 'ascii')]);
  const search = Buffer.concat([
    Buffer.from([0x04, 0x00, 0x0a, 0x01, 0x00, 0x0a, 0x01, 0x00]),
    Buffer.from([0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01, 0x01, 0x00]),
    filter,
    Buffer.from([0x30, 0x00]),
  ]);
  const message = Buffer.concat([
    Buffer.from([0x02, 0x01, 0x01, 0x63, search.length]),
    search,
  ]);
  return Buffer.concat([Buffer.from([0x30, message.length]), message]);
}

function entry(id, transport, defaultPort, build) {
  return Object.freeze({
    id,
    transport,
    default_port: defaultPort,
    build: boundedPayload(build),
    classify: classifyReflection,
  });
}

export const REFLECTOR_PAYLOADS = Object.freeze({
  ssdp_msearch: entry('ssdp_msearch', 'udp', 1900, () => Buffer.from(
    'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n',
    'ascii',
  )),
  snmp_v2c_get_sysdescr: entry('snmp_v2c_get_sysdescr', 'udp', 161, buildSnmpGetRequest),
  mdns_ptr_query: entry('mdns_ptr_query', 'udp', 5353, (ctx) => buildDnsQueryMessage(
    validateQueryName(ctx.queryName ?? '_services._dns-sd._udp.local'),
    { qtype: 'PTR', recursionDesired: false, id: 0 },
  )),
  netbios_nbstat: entry('netbios_nbstat', 'udp', 137, buildNetbiosNbstat),
  ws_discovery_probe: entry('ws_discovery_probe', 'udp', 3702, buildWsDiscoveryProbe),
  chargen_trigger: entry('chargen_trigger', 'udp', 19, () => Buffer.alloc(0)),
  coap_get_wellknown: entry('coap_get_wellknown', 'udp', 5683, (ctx) => Buffer.concat([
    Buffer.from([0x40, 0x01]),
    stableIdentifier(ctx.nonceHash, 2),
    Buffer.from([0xbb]),
    Buffer.from('.well-known', 'ascii'),
    Buffer.from([0x04]),
    Buffer.from('core', 'ascii'),
  ])),
  stun_binding_request: entry('stun_binding_request', 'udp', 3478, () => {
    const payload = Buffer.alloc(20);
    payload.writeUInt16BE(0x0001, 0);
    payload.writeUInt32BE(0x2112a442, 4);
    randomBytes(12).copy(payload, 8);
    return payload;
  }),
  ipmi_rmcp_ping: entry('ipmi_rmcp_ping', 'udp', 623, () => Buffer.from([
    0x06, 0x00, 0xff, 0x06, 0x00, 0x00, 0x11, 0xbe, 0x80, 0x00, 0x00, 0x00,
  ])),
  mssql_resolution_request: entry('mssql_resolution_request', 'udp', 1434, () => Buffer.from([0x02])),
  tftp_read_request: entry('tftp_read_request', 'udp', 69, () => Buffer.concat([
    Buffer.from([0x00, 0x01]),
    Buffer.from('astranull-nonexistent', 'ascii'),
    Buffer.from([0x00]),
    Buffer.from('octet', 'ascii'),
    Buffer.from([0x00]),
  ])),
  memcached_udp_stats: entry('memcached_udp_stats', 'udp', 11211, (ctx) => {
    const header = Buffer.alloc(8);
    stableIdentifier(ctx.nonceHash, 2).copy(header, 0);
    header.writeUInt16BE(1, 4);
    return Buffer.concat([header, Buffer.from('stats\r\n', 'ascii')]);
  }),
  dtls_client_hello: entry('dtls_client_hello', 'udp', 443, buildDtlsClientHello),
  portmap_dump: entry('portmap_dump', 'tcp', 111, buildPortmapDump),
  ntp_mode6_readvar: entry('ntp_mode6_readvar', 'udp', 123, (ctx) => {
    const payload = Buffer.alloc(12);
    payload[0] = 0x26;
    payload[1] = 0x02;
    stableIdentifier(ctx.nonceHash, 2).copy(payload, 2);
    return payload;
  }),
  cldap_root_dse: entry('cldap_root_dse', 'udp', 389, buildCldapRootDse),
  openvpn_reset: entry('openvpn_reset', 'udp', 1194, (ctx) => Buffer.concat([
    Buffer.from([0x38]),
    stableIdentifier(ctx.nonceHash, 8),
    Buffer.from([0x00, 0x00, 0x00, 0x00, 0x01]),
  ])),
  jenkins_discovery: entry('jenkins_discovery', 'udp', 33848, () => Buffer.from([0x00])),
  rip_v1_request: entry('rip_v1_request', 'udp', 520, () => {
    const payload = Buffer.alloc(24);
    payload[0] = 0x01;
    payload[1] = 0x01;
    payload.writeUInt32BE(16, 20);
    return payload;
  }),
  generic_probe: entry('generic_probe', 'udp', null, (ctx) => Buffer.from(
    `ASTRANULL:udp:${String(ctx.nonceHash ?? 'probe').slice(0, 16)}`,
    'utf8',
  )),
});

export function reflectorPayloadForProfile(profile = 'generic_probe') {
  return REFLECTOR_PAYLOADS[profile] ?? extraReflectorPayloadForProfile(profile) ?? REFLECTOR_PAYLOADS.generic_probe;
}
