/**
 * DNS-over-TCP AXFR query session — connect, framed write, response accumulation, timeout.
 */

import net from 'node:net';
import {
  accumulateDnsTcpResponse,
  buildAxfrDnsMessage,
  frameDnsTcpMessage,
} from './dnsTcpWire.mjs';

/**
 * Run a single bounded AXFR query against a nameserver over TCP port 53.
 * @param {{ nsHost: string, zone: string, timeoutMs: number, connectFn?: typeof net.connect }} params
 * @returns {Promise<{ axfr_leak?: boolean, axfr_refused?: boolean, rcode?: number, answer_count?: number, reason?: string }>}
 */
export async function runDnsTcpAxfrQuery({ nsHost, zone, timeoutMs, connectFn = net.connect }) {
  return new Promise((resolve) => {
    let settled = false;
    const socket = connectFn({ host: nsHost, port: 53, timeout: timeoutMs });
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ axfr_refused: true, reason: 'timeout' });
    }, timeoutMs);

    let responseBuffer = Buffer.alloc(0);

    socket.once('connect', () => {
      socket.write(frameDnsTcpMessage(buildAxfrDnsMessage(zone)));
    });
    socket.on('data', (chunk) => {
      if (settled) return;
      const accumulated = accumulateDnsTcpResponse(responseBuffer, chunk, { transport: 'tcp' });
      responseBuffer = accumulated.buffer;
      if (!accumulated.complete) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      const { rcode, answer_count: answerCount } = accumulated.parsed;
      if (rcode === 0 && answerCount > 0) {
        resolve({ axfr_leak: true, rcode, answer_count: answerCount });
      } else {
        resolve({ axfr_refused: true, rcode, answer_count: answerCount });
      }
    });
    socket.once('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ axfr_refused: true, reason: err.code ?? 'error' });
    });
  });
}