import assert from 'node:assert/strict';
import net from 'node:net';
import { EventEmitter } from 'node:events';
import { describe, it } from 'node:test';
import {
  encodeDnsQName,
  frameDnsTcpMessage,
} from '../../src/lib/dnsTcpWire.mjs';
import { runDnsTcpAxfrQuery } from '../../src/lib/dnsTcpAxfrSession.mjs';

async function runWithLocalAxfrResponse(buildDnsResponse, {
  split = false,
  transactionId = 0x4242,
} = {}) {
  const server = net.createServer((socket) => {
    socket.once('data', (query) => {
      const framed = frameDnsTcpMessage(buildDnsResponse(query));
      if (split) {
        socket.write(framed.subarray(0, 4), () => socket.write(framed.subarray(4)));
      } else {
        socket.write(framed);
      }
    });
    socket.on('error', () => {});
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const { port } = server.address();
  try {
    return await runDnsTcpAxfrQuery({
      nsHost: '127.0.0.1',
      zone: 'example.test',
      timeoutMs: 5000,
      transactionId,
      connectFn: (opts) => net.connect({ ...opts, port }),
    });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

function responseHeader(transactionId, { rcode = 0, questions = 0, answers = 0 } = {}) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(transactionId, 0);
  header.writeUInt16BE(0x8400 | rcode, 2);
  header.writeUInt16BE(questions, 4);
  header.writeUInt16BE(answers, 6);
  return header;
}

function validSoaResponse(query, transactionId) {
  const queryLength = query.readUInt16BE(0);
  const queryDns = query.subarray(2, 2 + queryLength);
  const question = queryDns.subarray(12);
  const owner = Buffer.from([0xc0, 0x0c]);
  const mname = encodeDnsQName('ns1.example.test');
  const rname = encodeDnsQName('hostmaster.example.test');
  const integers = Buffer.alloc(20);
  [1, 3600, 600, 86400, 60].forEach((value, index) => {
    integers.writeUInt32BE(value, index * 4);
  });
  const rdata = Buffer.concat([mname, rname, integers]);
  const fixed = Buffer.alloc(10);
  fixed.writeUInt16BE(6, 0);
  fixed.writeUInt16BE(1, 2);
  fixed.writeUInt32BE(60, 4);
  fixed.writeUInt16BE(rdata.length, 8);
  return Buffer.concat([
    responseHeader(transactionId, { questions: 1, answers: 1 }),
    question,
    owner,
    fixed,
    rdata,
  ]);
}

describe('dnsTcpAxfrSession', () => {
  it('runDnsTcpAxfrQuery accumulates split TCP chunks and reports REFUSED rcode', async () => {
    const refusedDns = responseHeader(0x4242, { rcode: 5 });
    const refusedFramed = frameDnsTcpMessage(refusedDns);
    const chunk1 = refusedFramed.subarray(0, 4);
    const chunk2 = refusedFramed.subarray(4);

    const server = net.createServer((socket) => {
      socket.on('data', () => {
        socket.write(chunk1, () => socket.write(chunk2));
      });
      socket.on('error', () => {});
    });

    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const { port } = server.address();

    try {
      const outcome = await runDnsTcpAxfrQuery({
        nsHost: '127.0.0.1',
        zone: 'example.test',
        timeoutMs: 5000,
        transactionId: 0x4242,
        connectFn: (opts) => net.connect({ ...opts, port }),
      });

      assert.equal(outcome.axfr_refused, true);
      assert.equal(outcome.rcode, 5);
      assert.notEqual(outcome.axfr_leak, true);
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  it('rejects a structurally valid response with a mismatched transaction ID', async () => {
    const outcome = await runWithLocalAxfrResponse(
      () => responseHeader(0x4243, { rcode: 5 }),
      { transactionId: 0x4242 },
    );
    assert.equal(outcome.axfr_refused, true);
    assert.equal(outcome.transaction_id_match, false);
    assert.equal(outcome.reason, 'transaction_id_mismatch');
    assert.notEqual(outcome.axfr_leak, true);
  });

  it('rejects a header that advertises an answer but contains no complete RR', async () => {
    const outcome = await runWithLocalAxfrResponse(
      (query) => {
        const queryLength = query.readUInt16BE(0);
        const queryDns = query.subarray(2, 2 + queryLength);
        return Buffer.concat([
          responseHeader(0x4242, { questions: 1, answers: 1 }),
          queryDns.subarray(12),
        ]);
      },
    );
    assert.equal(outcome.axfr_refused, true);
    assert.equal(outcome.answer_count, 1);
    assert.equal(outcome.complete_answer_count, 0);
    assert.equal(outcome.soa_answer_count, 0);
    assert.equal(outcome.reason, 'malformed_answer_section');
    assert.notEqual(outcome.axfr_leak, true);
  });

  it('accepts only a framed response containing a complete SOA RR', async () => {
    const outcome = await runWithLocalAxfrResponse(
      (query) => validSoaResponse(query, 0x4242),
      { split: true },
    );
    assert.equal(outcome.axfr_leak, true);
    assert.equal(outcome.answer_count, 1);
    assert.equal(outcome.complete_answer_count, 1);
    assert.equal(outcome.soa_answer_count, 1);
    assert.equal(outcome.has_complete_answer, true);
    assert.equal(outcome.has_complete_soa, true);
    assert.equal(outcome.transaction_id_match, true);
    assert.equal(Object.hasOwn(outcome, 'dns_message'), false);
  });
});


function dnsQuestion(name, qtype = 252, qclass = 1) {
  const qname = encodeDnsQName(name);
  const tail = Buffer.alloc(4);
  tail.writeUInt16BE(qtype, 0);
  tail.writeUInt16BE(qclass, 2);
  return Buffer.concat([qname, tail]);
}

function soaResponseWithQuestion(question, transactionId = 0x4242) {
  const owner = encodeDnsQName('example.test');
  const mname = encodeDnsQName('ns1.example.test');
  const rname = encodeDnsQName('hostmaster.example.test');
  const integers = Buffer.alloc(20);
  [1, 3600, 600, 86400, 60].forEach((value, index) => {
    integers.writeUInt32BE(value, index * 4);
  });
  const rdata = Buffer.concat([mname, rname, integers]);
  const fixed = Buffer.alloc(10);
  fixed.writeUInt16BE(6, 0);
  fixed.writeUInt16BE(1, 2);
  fixed.writeUInt32BE(60, 4);
  fixed.writeUInt16BE(rdata.length, 8);
  return Buffer.concat([
    responseHeader(transactionId, { questions: 1, answers: 1 }),
    question,
    owner,
    fixed,
    rdata,
  ]);
}

describe('dnsTcpAxfrSession adversarial framing and question binding', () => {
  it('normalizes question case/trailing dot but rejects unrelated name, QTYPE, and QCLASS', async () => {
    const canonical = await runWithLocalAxfrResponse(
      () => soaResponseWithQuestion(dnsQuestion('EXAMPLE.TEST.')),
    );
    assert.equal(canonical.axfr_leak, true);
    assert.equal(canonical.question_matches, true);

    for (const [label, question] of [
      ['unrelated name', dnsQuestion('victim.test')],
      ['wrong qtype', dnsQuestion('example.test', 1, 1)],
      ['wrong qclass', dnsQuestion('example.test', 252, 3)],
    ]) {
      const outcome = await runWithLocalAxfrResponse(
        () => soaResponseWithQuestion(question),
      );
      assert.equal(outcome.axfr_refused, true, label);
      assert.equal(outcome.question_matches, false, label);
      assert.equal(outcome.reason, 'question_mismatch', label);
      assert.notEqual(outcome.axfr_leak, true, label);
    }
  });

  it('rejects absent and multiple questions, including a compressed duplicate', async () => {
    const absent = await runWithLocalAxfrResponse(
      () => responseHeader(0x4242, { questions: 0 }),
    );
    assert.equal(absent.axfr_refused, true);
    assert.equal(absent.reason, 'unexpected_question_count');

    const first = dnsQuestion('example.test');
    const compressedSecond = Buffer.from([0xc0, 0x0c, 0x00, 0xfc, 0x00, 0x01]);
    const multiple = await runWithLocalAxfrResponse(
      () => Buffer.concat([
        responseHeader(0x4242, { questions: 2 }),
        first,
        compressedSecond,
      ]),
    );
    assert.equal(multiple.axfr_refused, true);
    assert.equal(multiple.reason, 'unexpected_question_count');
    assert.notEqual(multiple.axfr_leak, true);
  });

  it('returns incomplete_frame promptly when loopback closes a partial frame', { timeout: 2000 }, async () => {
    const server = net.createServer((socket) => {
      socket.once('data', () => {
        const partial = Buffer.alloc(7);
        partial.writeUInt16BE(64, 0);
        partial.writeUInt16BE(0x4242, 2);
        socket.end(partial);
      });
    });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const port = server.address().port;
    const started = Date.now();
    try {
      const outcome = await runDnsTcpAxfrQuery({
        nsHost: '127.0.0.1',
        zone: 'example.test',
        timeoutMs: 1000,
        transactionId: 0x4242,
        connectFn: (options) => net.connect({ ...options, port }),
      });
      assert.equal(outcome.axfr_refused, true);
      assert.equal(outcome.reason, 'incomplete_frame');
      assert.ok(Date.now() - started < 500, 'partial close waited for the timeout');
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  it('returns no_response_frame promptly for a zero-frame close', { timeout: 2000 }, async () => {
    const server = net.createServer((socket) => socket.once('data', () => socket.end()));
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const port = server.address().port;
    const started = Date.now();
    try {
      const outcome = await runDnsTcpAxfrQuery({
        nsHost: '127.0.0.1',
        zone: 'example.test',
        timeoutMs: 1000,
        transactionId: 0x4242,
        connectFn: (options) => net.connect({ ...options, port }),
      });
      assert.equal(outcome.axfr_refused, true);
      assert.equal(outcome.reason, 'no_response_frame');
      assert.ok(Date.now() - started < 500, 'zero-frame close waited for the timeout');
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  it('cleans listeners and destroys exactly once after a partial end', async () => {
    const socket = new EventEmitter();
    let destroyCalls = 0;
    socket.write = () => {};
    socket.destroy = () => {
      destroyCalls += 1;
      socket.emit('close');
    };
    const outcomePromise = runDnsTcpAxfrQuery({
      nsHost: '127.0.0.1',
      zone: 'example.test',
      timeoutMs: 30,
      transactionId: 0x4242,
      connectFn: () => socket,
    });
    queueMicrotask(() => {
      socket.emit('connect');
      socket.emit('data', Buffer.from([0, 32, 0x42, 0x42]));
      socket.emit('end');
    });
    const outcome = await outcomePromise;
    assert.equal(outcome.reason, 'incomplete_frame');
    await new Promise((resolve) => setTimeout(resolve, 40));
    assert.equal(destroyCalls, 1);
    for (const event of ['connect', 'data', 'timeout', 'error', 'end', 'close']) {
      assert.equal(socket.listenerCount(event), 0, event);
    }
  });
});


describe('AXFR TCP synchronous reservation boundary', () => {
  it('reserves before connect and reports the initiated request once', async () => {
    const events = [];
    let attempts = 0;
    const outcomePromise = runDnsTcpAxfrQuery({
      nsHost: '127.0.0.1',
      zone: 'example.test',
      timeoutMs: 1000,
      transactionId: 0x4242,
      beforeProbeIoAttempt: () => events.push('reserve'),
      onAttempt: () => { attempts += 1; },
      connectFn: () => {
        events.push('io');
        const socket = new EventEmitter();
        socket.destroy = () => {};
        socket.write = (query) => {
          queueMicrotask(() => socket.emit(
            'data',
            frameDnsTcpMessage(validSoaResponse(query, 0x4242)),
          ));
        };
        queueMicrotask(() => socket.emit('connect'));
        return socket;
      },
    });
    const outcome = await outcomePromise;
    assert.deepEqual(events, ['reserve', 'io']);
    assert.equal(attempts, 1);
    assert.equal(outcome.axfr_leak, true);
  });

  it('does not connect after reservation failure', async () => {
    let connectCalls = 0;
    await assert.rejects(
      () => runDnsTcpAxfrQuery({
        nsHost: '127.0.0.1',
        zone: 'example.test',
        timeoutMs: 1000,
        transactionId: 0x4242,
        beforeProbeIoAttempt: () => {
          throw Object.assign(new Error('cap exhausted'), {
            code: 'signed_operation_budget_exceeded',
          });
        },
        connectFn: () => {
          connectCalls += 1;
          throw new Error('must not connect');
        },
      }),
      (error) => error?.code === 'signed_operation_budget_exceeded',
    );
    assert.equal(connectCalls, 0);
  });
});
