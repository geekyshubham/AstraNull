/**
 * DNS-over-TCP AXFR query session — connect, framed write, response accumulation, timeout.
 */

import net from 'node:net';
import {
  DNS_QCLASS_IN,
  DNS_QTYPE_CODES,
  accumulateDnsTcpResponse,
  buildAxfrDnsMessage,
  frameDnsTcpMessage,
  parseDnsResponseHeader,
  parseDnsResponseStructure,
} from './dnsTcpWire.mjs';
import { startProbeIoAttempt } from './probeAttempt.mjs';

const AXFR_TRANSPORT_ERROR_CODES = new Set([
  'ECONNRESET',
  'ECONNREFUSED',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'ETIMEDOUT',
  'EPIPE',
]);

function boundedTransportReason(error) {
  const code = String(error?.code ?? '').trim().toUpperCase();
  return AXFR_TRANSPORT_ERROR_CODES.has(code) ? code : 'transport_error';
}

/**
 * Run a single bounded AXFR query against a nameserver over TCP port 53.
 * @param {{
 *   nsHost: string,
 *   zone: string,
 *   timeoutMs: number,
 *   connectFn?: typeof net.connect,
 *   transactionId?: number,
 *   transactionIdFn?: Function,
 *   beforeProbeIoAttempt?: Function,
 *   recordProbeLogicalAttempt?: Function,
 *   onAttempt?: Function,
 * }} params
 */
export async function runDnsTcpAxfrQuery({
  nsHost,
  zone,
  timeoutMs,
  connectFn = net.connect,
  transactionId,
  transactionIdFn,
  beforeProbeIoAttempt,
  recordProbeLogicalAttempt,
  onAttempt,
}) {
  const queryMessage = buildAxfrDnsMessage(zone, { transactionId, transactionIdFn });
  const queryTransactionId = queryMessage.readUInt16BE(0);

  return new Promise((resolve) => {
    let settled = false;
    let cleaned = false;
    let timer = null;
    let socket = null;
    let responseBuffer = Buffer.alloc(0);

    const cleanup = ({ destroy = true } = {}) => {
      if (cleaned) return;
      cleaned = true;
      clearTimeout(timer);
      socket?.removeListener?.('connect', onConnect);
      socket?.removeListener?.('data', onData);
      socket?.removeListener?.('timeout', onTimeout);
      socket?.removeListener?.('error', onError);
      socket?.removeListener?.('end', onEnd);
      socket?.removeListener?.('close', onClose);
      if (destroy) socket?.destroy?.();
    };
    const finish = (outcome, options) => {
      if (settled) return;
      settled = true;
      cleanup(options);
      resolve(outcome);
    };
    const closedBeforeFrame = (destroy) => {
      if (responseBuffer.length === 0) {
        finish({ axfr_refused: true, reason: 'no_response_frame' }, { destroy });
        return;
      }
      const parsed = parseDnsResponseHeader(responseBuffer, { transport: 'tcp' });
      finish({
        axfr_refused: true,
        transaction_id_match: parsed.transaction_id == null
          ? null
          : parsed.transaction_id === queryTransactionId,
        reason: 'incomplete_frame',
      }, { destroy });
    };
    const onConnect = () => {
      try {
        socket.write(frameDnsTcpMessage(queryMessage), (error) => {
          if (error) onError(error);
        });
      } catch (error) {
        onError(error);
      }
    };
    const onData = (chunk) => {
      if (settled) return;
      const accumulated = accumulateDnsTcpResponse(responseBuffer, chunk, { transport: 'tcp' });
      responseBuffer = accumulated.buffer;
      if (!accumulated.complete) return;

      const {
        transaction_id: responseTransactionId,
        rcode,
        answer_count: answerCount,
        axfr_refused: wireRefused,
        reason: wireReason,
        dns_message: dnsMessage,
      } = accumulated.parsed;
      if (responseTransactionId != null && responseTransactionId !== queryTransactionId) {
        finish({
          axfr_refused: true,
          rcode,
          answer_count: answerCount,
          transaction_id_match: false,
          reason: 'transaction_id_mismatch',
        });
        return;
      }
      if (wireRefused) {
        finish({
          axfr_refused: true,
          rcode,
          answer_count: answerCount,
          transaction_id_match: responseTransactionId == null ? null : true,
          reason: wireReason ?? 'malformed_response',
        });
        return;
      }

      const structure = parseDnsResponseStructure(dnsMessage, {
        expectedQuestion: {
          name: zone,
          qtype: DNS_QTYPE_CODES.AXFR,
          qclass: DNS_QCLASS_IN,
        },
      });
      const metadata = {
        rcode,
        answer_count: answerCount,
        complete_answer_count: structure.complete_answer_count,
        soa_answer_count: structure.soa_answer_count,
        has_complete_answer: structure.has_complete_answer,
        has_complete_soa: structure.has_complete_soa,
        question_matches: structure.question_matches ?? false,
        transaction_id_match: true,
        response_message: (dnsMessage[2] & 0x80) !== 0,
      };
      if (!metadata.response_message) {
        finish({ ...metadata, axfr_refused: true, reason: 'not_dns_response' });
        return;
      }
      if (!structure.structure_valid) {
        finish({
          ...metadata,
          axfr_refused: true,
          reason: structure.reason ?? 'malformed_response',
        });
        return;
      }
      if (rcode !== 0) {
        finish({ ...metadata, axfr_refused: true });
        return;
      }
      if (structure.has_complete_soa) {
        finish({ ...metadata, axfr_leak: true });
        return;
      }
      finish({ ...metadata, axfr_refused: true, reason: 'no_complete_soa_answer' });
    };
    const onTimeout = () => finish({ axfr_refused: true, reason: 'timeout' });
    const onError = (error) => finish({
      axfr_refused: true,
      reason: boundedTransportReason(error),
    });
    const onEnd = () => closedBeforeFrame(true);
    const onClose = () => closedBeforeFrame(false);

    socket = startProbeIoAttempt(
      { beforeProbeIoAttempt, recordProbeLogicalAttempt },
      'tcp_axfr',
      () => connectFn({ host: nsHost, port: 53, timeout: timeoutMs }),
      onAttempt,
    );
    socket.once('connect', onConnect);
    socket.on('data', onData);
    socket.once('timeout', onTimeout);
    socket.once('error', onError);
    socket.once('end', onEnd);
    socket.once('close', onClose);
    timer = setTimeout(onTimeout, Math.max(1, timeoutMs));
  });
}
