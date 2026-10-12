import { createHash, randomBytes } from 'node:crypto';
import { buildDnsQueryMessage, parseDnsResponseStructure, parseDnsResponseHeader } from './dnsTcpWire.mjs';
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

function classifyReflection(profile, requestBytes, responseBytes, responseReceived = responseBytes != null) {
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
    protocol_identity_confirmed: responseReceived && validateReflectionResponse(profile, requestBytes, responseBytes),
    reflector_confirmed: responseReceived && validateReflectionResponse(profile, requestBytes, responseBytes),
    identity_validation: Buffer.isBuffer(responseBytes) ? 'bounded_protocol_message' : 'response_bytes_not_available',
    assurance_scope: 'single_direct_service_response_not_spoofed_reflection_or_capacity',
  };
}


function berElement(bytes, offset = 0) {
  if (!Buffer.isBuffer(bytes) || offset + 2 > bytes.length) return null;
  const tag = bytes[offset++];
  let length = bytes[offset++];
  if (length & 0x80) {
    const width = length & 0x7f;
    if (width === 0 || width > 3 || offset + width > bytes.length) return null;
    length = bytes.readUIntBE(offset, width); offset += width;
  }
  if (offset + length > bytes.length) return null;
  return { tag, value: bytes.subarray(offset, offset + length), end: offset + length };
}
function snmpIdentity(bytes) {
  const sequence = berElement(bytes);
  if (!sequence || sequence.tag !== 0x30 || sequence.end !== bytes.length) return null;
  const version = berElement(sequence.value);
  const community = version && berElement(sequence.value, version.end);
  const pdu = community && berElement(sequence.value, community.end);
  const id = pdu && berElement(pdu.value);
  if (!version || version.tag !== 2 || !community || community.tag !== 4 || !pdu || pdu.end !== sequence.value.length || !id || id.tag !== 2) return null;
  const errorStatus = berElement(pdu.value, id.end);
  const errorIndex = errorStatus && berElement(pdu.value, errorStatus.end);
  const bindings = errorIndex && berElement(pdu.value, errorIndex.end);
  const binding = bindings && berElement(bindings.value);
  const oid = binding && berElement(binding.value);
  const value = oid && berElement(binding.value, oid.end);
  if (version.value.length !== 1 || version.value[0] !== 1 || id.value.length < 1 || id.value.length > 5
    || !errorStatus || errorStatus.tag !== 2 || errorStatus.value.length !== 1 || errorStatus.value[0] !== 0
    || !errorIndex || errorIndex.tag !== 2 || errorIndex.value.length !== 1 || errorIndex.value[0] !== 0
    || !bindings || bindings.tag !== 0x30 || bindings.end !== pdu.value.length
    || !binding || binding.tag !== 0x30 || binding.end !== bindings.value.length
    || !oid || oid.tag !== 6 || !value || value.end !== binding.value.length) return null;
  return { version: version.value, community: community.value, tag: pdu.tag, id: id.value, oid: oid.value, valueTag: value.tag };
}
/** Strict bounded response identity. A byte count or an arbitrary banner never confirms a protocol. */
export function validateReflectionResponse(profile, request, response) {
  if (!Buffer.isBuffer(request) || !Buffer.isBuffer(response) || response.length === 0 || response.length > 65536) return false;
  try {
    if (profile === 'stun_binding_request') {
      if (request.length !== 20 || response.length < 20 || ![0x0101, 0x0111].includes(response.readUInt16BE(0)) || response.readUInt32BE(4) !== 0x2112a442 || !response.subarray(8,20).equals(request.subarray(8,20)) || response.readUInt16BE(2) % 4 || response.length !== 20 + response.readUInt16BE(2)) return false;
      let offset = 20;
      while (offset < response.length) {
        if (offset + 4 > response.length) return false;
        const length = response.readUInt16BE(offset + 2);
        offset += 4 + Math.ceil(length / 4) * 4;
        if (offset > response.length) return false;
      }
      return offset === response.length;
    }
    if (profile === 'snmp_v2c_get_sysdescr') {
      const sent = snmpIdentity(request); const got = snmpIdentity(response);
      return Boolean(sent && got && got.tag === 0xa2 && got.id.equals(sent.id) && got.version.equals(sent.version) && got.community.equals(sent.community) && got.oid.equals(sent.oid) && [4, 0x80, 0x81, 0x82].includes(got.valueTag));
    }
    if (profile === 'memcached_udp_stats') {
      if (request.length < 8 || response.length < 8 || !response.subarray(0,2).equals(request.subarray(0,2))
        || response.readUInt16BE(2) !== 0 || response.readUInt16BE(4) !== 1 || response.readUInt16BE(6) !== 0) return false;
      const body = response.subarray(8).toString('latin1');
      if (!body.endsWith('END\r\n')) return false;
      const lines = body.slice(0, -5).split('\r\n');
      if (lines.pop() !== '' || lines.length === 0 || lines.length > 8192) return false;
      return lines.every((line) => /^STAT [\x21-\x7e]+ [\x20-\x7e]*$/.test(line));
    }
    if (profile === 'ntp_mode6_readvar') return response.length >= 12 && (response[0] & 7) === 6 && (response[1] & 0x80) !== 0 && (response[1] & 0x1f) === 2 && response.subarray(2,4).equals(request.subarray(2,4)) && (response[0] & 0x38) === (request[0] & 0x38) && response.subarray(6,8).equals(request.subarray(6,8)) && (response[1] & 0x60) === 0 && response.readUInt16BE(8) === 0 && response.readUInt16BE(10) === response.length - 12;
    if (profile === 'coap_get_wellknown') {
      if (response.length < 4 || response[0] >> 6 !== 1 || ((response[0] >> 4) & 3) !== 2 || (response[0] & 15) !== 0
        || ![2, 4, 5].includes(response[1] >> 5) || !response.subarray(2,4).equals(request.subarray(2,4))) return false;
      let offset = 4;
      while (offset < response.length) {
        const option = response[offset++];
        if (option === 255) return offset < response.length;
        const deltaNibble = option >> 4; const lengthNibble = option & 15;
        if (deltaNibble === 15 || lengthNibble === 15) return false;
        const deltaWidth = deltaNibble === 13 ? 1 : deltaNibble === 14 ? 2 : 0;
        const lengthWidth = lengthNibble === 13 ? 1 : lengthNibble === 14 ? 2 : 0;
        if (offset + deltaWidth + lengthWidth > response.length) return false;
        offset += deltaWidth;
        const length = lengthWidth === 0 ? lengthNibble : response.readUIntBE(offset, lengthWidth) + (lengthWidth === 1 ? 13 : 269);
        offset += lengthWidth + length;
        if (offset > response.length) return false;
      }
      return offset === response.length;
    }
    if (['mdns_ptr_query', 'netbios_nbstat'].includes(profile)) {
      const header = parseDnsResponseHeader(response, { transport: 'udp' });
      if (header.incomplete || header.transaction_id !== request.readUInt16BE(0) || (response[2] & 0xf8) !== 0x80 || header.rcode !== 0 || header.truncated) return false;
      let offset = 12;
      const labels = [];
      while (offset < request.length && request[offset]) {
        const length = request[offset++];
        labels.push(request.subarray(offset, offset + length).toString('ascii')); offset += length;
      }
      offset += 1;
      const structure = parseDnsResponseStructure(response, { expectedQuestion: { name: labels.join('.'), qtype: request.readUInt16BE(offset), qclass: request.readUInt16BE(offset + 2) } });
      return structure.structure_valid && structure.matching_answer_count > 0;
    }
    if (profile === 'portmap_dump') {
      if (response.length < 32 || (response.readUInt32BE(0) & 0x80000000) === 0
        || (response.readUInt32BE(0) & 0x7fffffff) !== response.length - 4
        || !response.subarray(4,8).equals(request.subarray(4,8))
        || response.readUInt32BE(8) !== 1 || response.readUInt32BE(12) !== 0) return false;
      const verifierLength = response.readUInt32BE(20);
      let offset = 24 + Math.ceil(verifierLength / 4) * 4;
      if (offset + 4 > response.length || response.readUInt32BE(offset) !== 0) return false;
      offset += 4;
      for (let count = 0; count < 4096; count += 1) {
        if (offset + 4 > response.length) return false;
        const present = response.readUInt32BE(offset); offset += 4;
        if (present === 0) return offset === response.length;
        if (present !== 1 || offset + 16 > response.length) return false;
        offset += 16;
      }
      return false;
    }
    if (profile === 'ssdp_msearch') {
      const text = response.toString('latin1');
      if (!text.endsWith('\r\n\r\n')) return false;
      const lines = text.slice(0, -4).split('\r\n');
      if (!/^HTTP\/1\.[01] 200 [\x20-\x7e]*$/.test(lines.shift()) || lines.length > 128) return false;
      const headers = new Map();
      for (const line of lines) {
        const match = /^([!#$%&'*+.^_`|~0-9A-Za-z-]+):[\t ]*([\t\x20-\x7e]*)$/.exec(line);
        if (!match) return false;
        const name = match[1].toLowerCase();
        if (headers.has(name) && ['st', 'usn'].includes(name)) return false;
        headers.set(name, match[2].trim());
      }
      return headers.get('st')?.toLowerCase() === 'upnp:rootdevice'
        && /^uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}::upnp:rootdevice$/i.test(headers.get('usn') ?? '');
    }
    // WS-Discovery XML requires a complete namespace-aware message parser.
    // A substring/regex match is not a supported message identity contract.
    // Protocols lacking validated message identity remain unsupported observations.
    return false;
  } catch { return false; }
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
    classify: (request, response, received) => classifyReflection(id, request, response, received),
    identity_supported: ['ssdp_msearch', 'snmp_v2c_get_sysdescr', 'mdns_ptr_query', 'netbios_nbstat', 'coap_get_wellknown', 'stun_binding_request', 'memcached_udp_stats', 'portmap_dump', 'ntp_mode6_readvar'].includes(id),
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
  return REFLECTOR_PAYLOADS[profile] ?? extraReflectorPayloadForProfile(profile) ?? null;
}
