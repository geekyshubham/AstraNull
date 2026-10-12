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
  signal,
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
      signal?.removeEventListener('abort', onAbort);
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
        finish({ axfr_refused: false, reason: 'no_response_frame' }, { destroy });
        return;
      }
      const parsed = parseDnsResponseHeader(responseBuffer, { transport: 'tcp' });
      finish({
        axfr_refused: false,
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
        reason: wireReason,
        dns_message: dnsMessage,
      } = accumulated.parsed;
      if (responseTransactionId != null && responseTransactionId !== queryTransactionId) {
        finish({
          axfr_refused: false,
          rcode,
          answer_count: answerCount,
          transaction_id_match: false,
          reason: 'transaction_id_mismatch',
        });
        return;
      }
      if (wireReason) {
        finish({
          axfr_refused: false,
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
      if (!metadata.response_message || (dnsMessage[2] & 0x78) !== 0 || (dnsMessage[2] & 0x02) !== 0) {
        finish({ ...metadata, axfr_refused: false, reason: 'not_dns_response' });
        return;
      }
      if (!structure.structure_valid) {
        finish({
          ...metadata,
          axfr_refused: false,
          reason: structure.reason ?? 'malformed_response',
        });
        return;
      }
      if (rcode !== 0) {
        finish({ ...metadata, axfr_refused: rcode === 5, axfr_leak: false,
          protocol_identity_confirmed: true, transfer_complete: false, reason: rcode === 5 ? 'refused_rcode' : 'dns_error_response' });
        return;
      }
      if (structure.has_complete_soa) {
        finish({ ...metadata, axfr_refused: false, axfr_leak: structure.axfr_boundary_soa_match === true,
          transfer_complete: structure.axfr_boundary_soa_match === true, protocol_identity_confirmed: true,
          axfr_records_observed: structure.complete_answer_count,
          reason: structure.axfr_boundary_soa_match ? null : 'bounded_partial_transfer_observation' });
        return;
      }
      finish({ ...metadata, axfr_refused: false, reason: 'no_complete_soa_answer' });
    };
    const onTimeout = () => finish({ axfr_refused: false, axfr_leak: false, error_class: 'timeout', reason: 'timeout' });
    const onAbort = () => finish({ axfr_refused: false, axfr_leak: false, error_class: 'timeout', reason: 'probe_canceled' });
    const onError = (error) => finish({
      axfr_refused: false,
      reason: boundedTransportReason(error),
      error_class: boundedTransportReason(error),
    });
    const onEnd = () => closedBeforeFrame(true);
    const onClose = () => closedBeforeFrame(false);

    if (signal?.aborted) { onAbort(); return; }
    signal?.addEventListener('abort', onAbort, { once: true });
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
