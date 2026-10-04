import { randomInt } from 'node:crypto';

/**
 * RFC 1035 DNS message encoding and DNS-over-TCP framing helpers.
 * Transport is explicit — callers must pass { transport: 'tcp' } for AXFR/TCP paths.
 */

export const DNS_QCLASS_IN = 1;

export const DNS_QTYPE_CODES = Object.freeze({
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  DNSKEY: 48,
  ANY: 255,
  AXFR: 252,
});

export function encodeDnsQName(zone) {
  const value = String(zone ?? '').replace(/\.$/, '');
  if (value.length < 1 || value.length > 253) throw new RangeError('Invalid DNS query name.');
  const labels = value.split('.');
  const parts = [];
  for (const label of labels) {
    if (
      label.length < 1
      || label.length > 63
      || !/^[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?$/.test(label)
    ) {
      throw new RangeError('Invalid DNS query name.');
    }
    parts.push(Buffer.from([label.length]));
    parts.push(Buffer.from(label, 'ascii'));
  }
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

export function buildDnsQueryMessage(name, options = {}) {
  const qtypeName = String(options.qtype ?? 'A').toUpperCase();
  const qtype = DNS_QTYPE_CODES[qtypeName];
  if (!qtype) throw new RangeError(`Unsupported DNS qtype: ${qtypeName}`);
  const qname = encodeDnsQName(name);
  const header = Buffer.alloc(12);
  header.writeUInt16BE(Number(options.id ?? 0x1234) & 0xffff, 0);
  header.writeUInt16BE(options.recursionDesired === true ? 0x0100 : 0x0000, 2);
  header.writeUInt16BE(1, 4);
  const question = Buffer.alloc(qname.length + 4);
  qname.copy(question, 0);
  question.writeUInt16BE(qtype, qname.length);
  question.writeUInt16BE(1, qname.length + 2);
  return Buffer.concat([header, question]);
}

/** Build a single AXFR DNS query message (payload without TCP length prefix). */
export function buildAxfrDnsMessage(zone, options = {}) {
  const transactionIdFn = options.transactionIdFn ?? randomInt;
  const transactionId = options.transactionId
    ?? transactionIdFn(0, 0x10000);
  if (!Number.isSafeInteger(transactionId) || transactionId < 0 || transactionId > 0xffff) {
    throw new RangeError('Invalid DNS transaction ID.');
  }
  return buildDnsQueryMessage(zone, {
    qtype: 'AXFR',
    recursionDesired: true,
    id: transactionId,
  });
}

/** RFC 1035 §4.2.2 — prepend 16-bit message length for DNS-over-TCP. */
export function frameDnsTcpMessage(message) {
  const framed = Buffer.alloc(2 + message.length);
  framed.writeUInt16BE(message.length, 0);
  message.copy(framed, 2);
  return framed;
}

/**
 * Parse DNS response header from a buffer.
 * @param {Buffer} chunk
 * @param {{ transport?: 'tcp' | 'udp' }} [options] — use 'tcp' for DNS-over-TCP (AXFR); default 'udp' treats buffer as raw DNS.
 */
export function parseDnsResponseHeader(chunk, options = {}) {
  const transport = options.transport ?? 'udp';
  const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk ?? []);

  if (transport === 'tcp') {
    if (buffer.length < 2) {
      return {
        transaction_id: null,
        rcode: null,
        answer_count: 0,
        dns_message: buffer,
        incomplete: true,
        tcp_framed: true,
      };
    }
    const declaredLen = buffer.readUInt16BE(0);
    const transactionId = buffer.length >= 4 ? buffer.readUInt16BE(2) : null;
    if (declaredLen < 12) {
      // A DNS message cannot be shorter than its 12-byte header. Once the 2-byte
      // length prefix has arrived this frame can never become valid.
      return {
        transaction_id: transactionId,
        rcode: null,
        answer_count: 0,
        dns_message: buffer,
        incomplete: false,
        tcp_framed: true,
        axfr_refused: true,
        reason: 'malformed_response',
      };
    }
    if (buffer.length < declaredLen + 2) {
      return {
        transaction_id: transactionId,
        rcode: null,
        answer_count: 0,
        dns_message: buffer,
        incomplete: true,
        tcp_framed: true,
      };
    }
    const dnsMessage = buffer.subarray(2, 2 + declaredLen);
    if (dnsMessage.length < 12) {
      return {
        transaction_id: dnsMessage.length >= 2 ? dnsMessage.readUInt16BE(0) : null,
        rcode: null,
        answer_count: 0,
        dns_message: dnsMessage,
        incomplete: true,
        tcp_framed: true,
      };
    }
    return {
      transaction_id: dnsMessage.readUInt16BE(0),
      rcode: dnsMessage[3] & 0x0f,
      answer_count: dnsMessage.readUInt16BE(6),
      authoritative: (dnsMessage[2] & 0x04) !== 0,
      truncated: (dnsMessage[2] & 0x02) !== 0,
      dns_message: dnsMessage,
      incomplete: false,
      tcp_framed: true,
    };
  }

  if (buffer.length < 12) {
    return {
      transaction_id: buffer.length >= 2 ? buffer.readUInt16BE(0) : null,
      rcode: null,
      answer_count: 0,
      dns_message: buffer,
      incomplete: true,
      tcp_framed: false,
    };
  }
  return {
    transaction_id: buffer.readUInt16BE(0),
    rcode: buffer[3] & 0x0f,
    answer_count: buffer.readUInt16BE(6),
    authoritative: (buffer[2] & 0x04) !== 0,
    truncated: (buffer[2] & 0x02) !== 0,
    dns_message: buffer,
    incomplete: false,
    tcp_framed: false,
  };
}

/** Bounds hostile compression chains and section-count CPU work within one 65,535-byte DNS frame. */
const MAX_DNS_NAME_POINTER_HOPS = 32;
const MAX_DNS_NAME_COMPONENTS = 128;
const MAX_DNS_SECTION_RECORDS = 8192;

function parseDnsName(message, startOffset) {
  if (!Number.isSafeInteger(startOffset) || startOffset < 0 || startOffset >= message.length) {
    throw new RangeError('Malformed DNS name.');
  }
  let cursor = startOffset;
  let nextOffset = null;
  let pointerHops = 0;
  let components = 0;
  let expandedLength = 1;
  const visitedPointers = new Set();
  const labels = [];

  while (components < MAX_DNS_NAME_COMPONENTS) {
    if (cursor >= message.length) throw new RangeError('Malformed DNS name.');
    const length = message[cursor];
    if ((length & 0xc0) === 0xc0) {
      if (cursor + 1 >= message.length) throw new RangeError('Malformed DNS name.');
      const pointer = ((length & 0x3f) << 8) | message[cursor + 1];
      if (
        pointer >= message.length
        || pointerHops >= MAX_DNS_NAME_POINTER_HOPS
        || visitedPointers.has(pointer)
      ) {
        throw new RangeError('Malformed DNS compression pointer.');
      }
      visitedPointers.add(pointer);
      pointerHops += 1;
      if (nextOffset == null) nextOffset = cursor + 2;
      cursor = pointer;
      continue;
    }
    if ((length & 0xc0) !== 0 || length > 63) {
      throw new RangeError('Malformed DNS label.');
    }
    cursor += 1;
    if (length === 0) {
      return {
        nextOffset: nextOffset ?? cursor,
        name: labels.join('.').toLowerCase(),
      };
    }
    if (cursor + length > message.length) throw new RangeError('Malformed DNS label.');
    labels.push(message.subarray(cursor, cursor + length).toString('ascii'));
    expandedLength += length + 1;
    if (expandedLength > 255) throw new RangeError('DNS name exceeds wire limit.');
    cursor += length;
    components += 1;
  }
  throw new RangeError('DNS name has too many components.');
}

function validateSoaRdata(message, startOffset, endOffset) {
  const mname = parseDnsName(message, startOffset);
  if (mname.nextOffset > endOffset) throw new RangeError('Malformed SOA RDATA.');
  const rname = parseDnsName(message, mname.nextOffset);
  if (rname.nextOffset + 20 !== endOffset) throw new RangeError('Malformed SOA RDATA.');
  for (let offset = rname.nextOffset; offset < endOffset; offset += 4) {
    message.readUInt32BE(offset);
  }
}

/**
 * Structurally validate the advertised DNS question and answer sections. The result
 * contains counts/booleans only; parsed names and record bytes are never returned.
 */
export function parseDnsResponseStructure(dnsMessage, options = {}) {
  const message = Buffer.isBuffer(dnsMessage) ? dnsMessage : Buffer.from(dnsMessage ?? []);
  if (message.length < 12) {
    return {
      structure_valid: false,
      question_count: 0,
      answer_count: 0,
      complete_answer_count: 0,
      soa_answer_count: 0,
      has_complete_answer: false,
      has_complete_soa: false,
      reason: 'malformed_response',
    };
  }

  const questionCount = message.readUInt16BE(4);
  const answerCount = message.readUInt16BE(6);
  const expectedQuestion = options.expectedQuestion ?? null;
  const base = {
    question_count: questionCount,
    answer_count: answerCount,
    complete_answer_count: 0,
    soa_answer_count: 0,
    has_complete_answer: false,
    has_complete_soa: false,
    ...(expectedQuestion ? { question_matches: false } : {}),
  };
  if (questionCount > MAX_DNS_SECTION_RECORDS || answerCount > MAX_DNS_SECTION_RECORDS) {
    return { ...base, structure_valid: false, reason: 'section_count_exceeded' };
  }
  if (expectedQuestion && questionCount !== 1) {
    return { ...base, structure_valid: false, reason: 'unexpected_question_count' };
  }

  let offset = 12;
  const questions = [];
  for (let index = 0; index < questionCount; index += 1) {
    try {
      const parsedName = parseDnsName(message, offset);
      offset = parsedName.nextOffset;
      if (offset + 4 > message.length) throw new RangeError('Malformed DNS question.');
      questions.push({
        name: parsedName.name,
        qtype: message.readUInt16BE(offset),
        qclass: message.readUInt16BE(offset + 2),
      });
      offset += 4;
    } catch {
      return { ...base, structure_valid: false, reason: 'malformed_question_section' };
    }
  }
  if (expectedQuestion) {
    const expectedName = String(expectedQuestion.name ?? '')
      .trim()
      .toLowerCase()
      .replace(/\.+$/, '');
    const question = questions[0];
    if (
      !expectedName
      || question.name !== expectedName
      || question.qtype !== expectedQuestion.qtype
      || question.qclass !== expectedQuestion.qclass
    ) {
      return { ...base, structure_valid: false, reason: 'question_mismatch' };
    }
    base.question_matches = true;
  }

  let completeAnswerCount = 0;
  let soaAnswerCount = 0;
  let matchingAnswerCount = 0;
  for (let index = 0; index < answerCount; index += 1) {
    let type;
    let rdataStart;
    let rdataEnd;
    try {
      const owner = parseDnsName(message, offset);
      offset = owner.nextOffset;
      if (offset + 10 > message.length) throw new RangeError('Malformed DNS answer.');
      type = message.readUInt16BE(offset);
      const rdlength = message.readUInt16BE(offset + 8);
      rdataStart = offset + 10;
      rdataEnd = rdataStart + rdlength;
      if (rdataEnd > message.length) throw new RangeError('Malformed DNS RDATA.');
      if (expectedQuestion && owner.name === String(expectedQuestion.name).toLowerCase().replace(/\.+$/, '') && type === expectedQuestion.qtype
        && message.readUInt16BE(offset + 2) === expectedQuestion.qclass) {
        // DNSKEY must include flags, protocol, algorithm, and nonempty public key.
        if (type === DNS_QTYPE_CODES.DNSKEY && (rdlength < 5 || message[rdataStart + 2] !== 3)) {
          throw new RangeError('Malformed DNSKEY RDATA.');
        }
        matchingAnswerCount += 1;
      }
      if (type === DNS_QTYPE_CODES.SOA) {
        try {
          validateSoaRdata(message, rdataStart, rdataEnd);
        } catch {
          return {
            ...base,
            complete_answer_count: completeAnswerCount,
            soa_answer_count: soaAnswerCount,
            has_complete_answer: completeAnswerCount > 0,
            has_complete_soa: soaAnswerCount > 0,
            structure_valid: false,
            reason: 'malformed_soa_rdata',
          };
        }
        soaAnswerCount += 1;
      }
      completeAnswerCount += 1;
      offset = rdataEnd;
    } catch {
      return {
        ...base,
        complete_answer_count: completeAnswerCount,
        soa_answer_count: soaAnswerCount,
        has_complete_answer: completeAnswerCount > 0,
        has_complete_soa: soaAnswerCount > 0,
        structure_valid: false,
        reason: 'malformed_answer_section',
      };
    }
  }

  return {
    ...base,
    complete_answer_count: completeAnswerCount,
    soa_answer_count: soaAnswerCount,
    has_complete_answer: completeAnswerCount > 0,
    has_complete_soa: soaAnswerCount > 0,
    structure_valid: true,
    matching_answer_count: matchingAnswerCount,
    reason: null,
  };
}

/**
 * A DNS-over-TCP frame is a 16-bit length prefix plus at most 65535 payload bytes.
 * Nothing legitimate exceeds this; the ceiling bounds hostile incomplete streams.
 */
export const MAX_DNS_TCP_RESPONSE_BYTES = 2 + 0xffff;

/**
 * Append a TCP DNS response chunk and parse when the frame is complete.
 * @param {Buffer} responseBuffer accumulated bytes so far
 * @param {Buffer} chunk newly received bytes
 * @param {{ transport?: 'tcp' | 'udp' }} [options]
 */
export function accumulateDnsTcpResponse(responseBuffer, chunk, options = { transport: 'tcp' }) {
  const buffer = Buffer.concat([responseBuffer, chunk]);
  if (buffer.length > MAX_DNS_TCP_RESPONSE_BYTES) {
    return {
      buffer: buffer.subarray(0, MAX_DNS_TCP_RESPONSE_BYTES),
      parsed: {
        transaction_id: buffer.length >= 4 ? buffer.readUInt16BE(2) : null,
        rcode: null,
        answer_count: 0,
        dns_message: Buffer.alloc(0),
        incomplete: false,
        tcp_framed: true,
        axfr_refused: true,
        reason: 'response_too_large',
      },
      complete: true,
    };
  }
  const parsed = parseDnsResponseHeader(buffer, options);
  return { buffer, parsed, complete: parsed.incomplete !== true };
}
