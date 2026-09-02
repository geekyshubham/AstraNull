import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  accumulateDnsTcpResponse,
  buildAxfrDnsMessage,
  encodeDnsQName,
  frameDnsTcpMessage,
  parseDnsResponseHeader,
  parseDnsResponseStructure,
} from '../../src/lib/dnsTcpWire.mjs';

function refusedDnsMessage(rcode = 5) {
  const dns = Buffer.alloc(12);
  dns.writeUInt16BE(0x1234, 0);
  dns[3] = rcode;
  return dns;
}

describe('dnsTcpWire', () => {
  const cases = [
    {
      name: 'framed REFUSED strips TCP prefix',
      build: () => frameDnsTcpMessage(refusedDnsMessage(5)),
      options: { transport: 'tcp' },
      expect: { transaction_id: 0x1234, rcode: 5, answer_count: 0, incomplete: false, tcp_framed: true },
    },
    {
      name: 'partial TCP chunk is incomplete',
      build: () => frameDnsTcpMessage(refusedDnsMessage(5)).subarray(0, 6),
      options: { transport: 'tcp' },
      expect: { transaction_id: 0x1234, rcode: null, incomplete: true, tcp_framed: true },
    },
    {
      name: 'raw UDP DNS does not strip txid bytes as TCP length',
      build: () => {
        const dns = refusedDnsMessage(5);
        dns.writeUInt16BE(0xabcd, 0);
        return dns;
      },
      options: { transport: 'udp' },
      expect: { transaction_id: 0xabcd, rcode: 5, answer_count: 0, incomplete: false, tcp_framed: false },
    },
    {
      name: 'two TCP chunks accumulate to complete frame',
      build: () => {
        const framed = frameDnsTcpMessage(refusedDnsMessage(5));
        return Buffer.concat([framed.subarray(0, 4), framed.subarray(4)]);
      },
      options: { transport: 'tcp' },
      expect: { transaction_id: 0x1234, rcode: 5, answer_count: 0, incomplete: false, tcp_framed: true },
    },
  ];

  for (const { name, build, options, expect } of cases) {
    it(name, () => {
      const parsed = parseDnsResponseHeader(build(), options);
      if ('transaction_id' in expect) assert.equal(parsed.transaction_id, expect.transaction_id);
      if ('rcode' in expect) assert.equal(parsed.rcode, expect.rcode);
      if ('answer_count' in expect) assert.equal(parsed.answer_count, expect.answer_count);
      if ('incomplete' in expect) assert.equal(parsed.incomplete, expect.incomplete);
      if ('tcp_framed' in expect) assert.equal(parsed.tcp_framed, expect.tcp_framed);
    });
  }

  it('buildAxfrDnsMessage encodes QNAME and AXFR QTYPE with an injected transaction ID', () => {
    const qname = encodeDnsQName('example.test');
    assert.equal(qname.length, 14);
    const message = buildAxfrDnsMessage('example.test', { transactionId: 0xbeef });
    assert.equal(message.readUInt16BE(0), 0xbeef);
    assert.equal(message.readUInt16BE(qname.length + 12), 252);
    assert.equal(message.readUInt16BE(qname.length + 14), 1);
  });

  it('buildAxfrDnsMessage uses the bounded random-ID seam by default', () => {
    const calls = [];
    const message = buildAxfrDnsMessage('example.test', {
      transactionIdFn: (min, max) => {
        calls.push([min, max]);
        return 0x6a6a;
      },
    });
    assert.deepEqual(calls, [[0, 0x10000]]);
    assert.equal(message.readUInt16BE(0), 0x6a6a);
  });

  it('parseDnsResponseStructure rejects a cyclic compression pointer without looping', () => {
    const dns = Buffer.alloc(18);
    dns.writeUInt16BE(0x4242, 0);
    dns.writeUInt16BE(0x8000, 2);
    dns.writeUInt16BE(1, 4);
    dns[12] = 0xc0;
    dns[13] = 0x0c;
    dns.writeUInt16BE(252, 14);
    dns.writeUInt16BE(1, 16);
    const parsed = parseDnsResponseStructure(dns);
    assert.equal(parsed.structure_valid, false);
    assert.equal(parsed.reason, 'malformed_question_section');
    assert.equal(parsed.complete_answer_count, 0);
  });

  it('parseDnsResponseStructure bounds overlong compression-pointer chains', () => {
    const dns = Buffer.alloc(96);
    dns.writeUInt16BE(0x4242, 0);
    dns.writeUInt16BE(0x8000, 2);
    dns.writeUInt16BE(1, 4);
    dns.writeUInt16BE(0xc012, 12);
    dns.writeUInt16BE(252, 14);
    dns.writeUInt16BE(1, 16);
    for (let offset = 18; offset < 86; offset += 2) {
      dns.writeUInt16BE(0xc000 | (offset + 2), offset);
    }
    dns[86] = 0;
    const parsed = parseDnsResponseStructure(dns);
    assert.equal(parsed.structure_valid, false);
    assert.equal(parsed.reason, 'malformed_question_section');
  });

  it('frameDnsTcpMessage prefixes RFC 1035 TCP length', () => {
    const message = buildAxfrDnsMessage('example.test');
    const framed = frameDnsTcpMessage(message);
    assert.equal(framed.readUInt16BE(0), message.length);
    assert.deepEqual(framed.subarray(2), message);
  });

  it('accumulateDnsTcpResponse completes only after split chunks arrive', () => {
    const framed = frameDnsTcpMessage(refusedDnsMessage(5));
    const first = accumulateDnsTcpResponse(Buffer.alloc(0), framed.subarray(0, 4));
    assert.equal(first.complete, false);
    assert.equal(first.parsed.incomplete, true);

    const second = accumulateDnsTcpResponse(first.buffer, framed.subarray(4));
    assert.equal(second.complete, true);
    assert.equal(second.parsed.transaction_id, 0x1234);
    assert.equal(second.parsed.rcode, 5);
    assert.equal(second.parsed.answer_count, 0);
  });
});