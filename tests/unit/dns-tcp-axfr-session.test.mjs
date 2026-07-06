import assert from 'node:assert/strict';
import net from 'node:net';
import { describe, it } from 'node:test';
import { frameDnsTcpMessage } from '../../src/lib/dnsTcpWire.mjs';
import { runDnsTcpAxfrQuery } from '../../src/lib/dnsTcpAxfrSession.mjs';

describe('dnsTcpAxfrSession', () => {
  it('runDnsTcpAxfrQuery accumulates split TCP chunks and reports REFUSED rcode', async () => {
    const refusedDns = Buffer.alloc(12);
    refusedDns[3] = 0x05;
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
        connectFn: (opts) => net.connect({ ...opts, port }),
      });

      assert.equal(outcome.axfr_refused, true);
      assert.equal(outcome.rcode, 5);
      assert.notEqual(outcome.axfr_leak, true);
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });
});