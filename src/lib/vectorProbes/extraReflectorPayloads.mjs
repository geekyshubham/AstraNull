import { createHash } from 'node:crypto';

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

function u16(value) {
  const buffer = Buffer.alloc(2);
  buffer.writeUInt16BE(value & 0xffff, 0);
  return buffer;
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

function buildSlpServiceRequest(ctx) {
  const langTag = Buffer.from('en', 'ascii');
  const serviceType = Buffer.from('service:service-agent', 'ascii');
  const scopeList = Buffer.from('DEFAULT', 'ascii');
  const body = Buffer.concat([
    u16(0),
    u16(serviceType.length), serviceType,
    u16(scopeList.length), scopeList,
    u16(0),
    u16(0),
  ]);
  const headerLength = 14 + langTag.length;
  const total = headerLength + body.length;
  const header = Buffer.alloc(headerLength);
  header[0] = 0x02;
  header[1] = 0x01;
  header.writeUIntBE(total, 2, 3);
  header.writeUInt16BE(0x0000, 5);
  header.writeUIntBE(0, 7, 3);
  stableIdentifier(ctx.nonceHash, 2).copy(header, 10);
  header.writeUInt16BE(langTag.length, 12);
  langTag.copy(header, 14);
  return Buffer.concat([header, body]);
}

function buildTp240StatusRequest(ctx) {
  return Buffer.concat([Buffer.from([0x00, 0x00, 0x00, 0x00]), stableIdentifier(ctx.nonceHash, 2)]);
}

function l2tpAvp(attributeType, value) {
  const header = Buffer.alloc(6);
  header.writeUInt16BE(0x8000 | (6 + value.length), 0);
  header.writeUInt16BE(0, 2);
  header.writeUInt16BE(attributeType, 4);
  return Buffer.concat([header, value]);
}

function buildL2tpStartControlRequest(ctx) {
  const avps = Buffer.concat([
    l2tpAvp(0, u16(0x0001)),
    l2tpAvp(2, u16(0x0100)),
    l2tpAvp(7, Buffer.from('astranull', 'ascii')),
    l2tpAvp(3, Buffer.from([0x00, 0x00, 0x00, 0x01])),
    l2tpAvp(9, stableIdentifier(ctx.nonceHash, 2)),
  ]);
  const header = Buffer.alloc(12);
  header.writeUInt16BE(0xc802, 0);
  header.writeUInt16BE(12 + avps.length, 2);
  return Buffer.concat([header, avps]);
}

function buildNatPmpExternalAddressRequest() {
  return Buffer.from([0x00, 0x00]);
}

function ippAttribute(tag, name, value) {
  const nameBuffer = Buffer.from(name, 'ascii');
  const valueBuffer = Buffer.from(value, 'ascii');
  return Buffer.concat([
    Buffer.from([tag]),
    u16(nameBuffer.length), nameBuffer,
    u16(valueBuffer.length), valueBuffer,
  ]);
}

function buildIppGetPrinterAttributes(ctx) {
  const ippBody = Buffer.concat([
    Buffer.from([0x02, 0x00, 0x00, 0x0b]),
    stableIdentifier(ctx.nonceHash, 4),
    Buffer.from([0x01]),
    ippAttribute(0x47, 'attributes-charset', 'utf-8'),
    ippAttribute(0x48, 'attributes-natural-language', 'en'),
    ippAttribute(0x45, 'printer-uri', 'ipp://localhost/ipp/print'),
    Buffer.from([0x03]),
  ]);
  const httpHeader = Buffer.from(
    'POST /ipp/print HTTP/1.1\r\n'
      + 'Host: localhost\r\n'
      + 'Content-Type: application/ipp\r\n'
      + `Content-Length: ${ippBody.length}\r\n\r\n`,
    'ascii',
  );
  return Buffer.concat([httpHeader, ippBody]);
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

export const EXTRA_REFLECTOR_PAYLOADS = Object.freeze({
  slp_srvrqst: entry('slp_srvrqst', 'udp', 427, buildSlpServiceRequest),
  tp240_status_request: entry('tp240_status_request', 'udp', 10074, buildTp240StatusRequest),
  l2tp_sccrq: entry('l2tp_sccrq', 'udp', 1701, buildL2tpStartControlRequest),
  natpmp_external_address: entry('natpmp_external_address', 'udp', 5351, buildNatPmpExternalAddressRequest),
  ipp_get_printer_attributes: entry('ipp_get_printer_attributes', 'tcp', 631, buildIppGetPrinterAttributes),
});

export function extraReflectorPayloadForProfile(profile) {
  return EXTRA_REFLECTOR_PAYLOADS[profile] ?? null;
}
