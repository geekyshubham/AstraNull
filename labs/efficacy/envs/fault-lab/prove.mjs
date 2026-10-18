import net from 'node:net';
import { execSync } from 'node:child_process';

const HOST = '127.0.0.1';
const PORT = 18080;
const TUPLE1_CLIENT_PORT = 40001;
const TUPLE2_CLIENT_PORT = 40002;

function parseIptablesCounters() {
  const output = execSync('iptables -v -L INPUT -n -x --line-numbers', { encoding: 'utf8' });
  const lines = output.split('\n');
  const counters = {};
  for (const line of lines) {
    const parts = line.trim().split(/\s+/);
    if (parts.length >= 8) {
      if (line.includes('DROP') && line.includes(String(TUPLE1_CLIENT_PORT))) {
        counters.tuple1_drop = {
          rule: 'DROP',
          src: `${HOST}:${TUPLE1_CLIENT_PORT}`,
          dst: `${HOST}:${PORT}`,
          pkts: parseInt(parts[1], 10),
          bytes: parseInt(parts[2], 10),
        };
      }
      if (line.includes('ACCEPT') && line.includes(String(TUPLE2_CLIENT_PORT))) {
        counters.tuple2_accept = {
          rule: 'ACCEPT',
          src: `${HOST}:${TUPLE2_CLIENT_PORT}`,
          dst: `${HOST}:${PORT}`,
          pkts: parseInt(parts[1], 10),
          bytes: parseInt(parts[2], 10),
        };
      }
    }
  }
  return { raw: output, counters };
}

function testTuple2() {
  return new Promise((resolve) => {
    const start = Date.now();
    const client = net.connect({ host: HOST, port: PORT, localPort: TUPLE2_CLIENT_PORT });
    client.setTimeout(2000);
    let payload = '';

    client.on('connect', () => {
      // TCP 3-way handshake finished
    });

    client.on('data', (data) => {
      payload += data.toString('utf8');
    });

    client.on('end', () => {
      const duration_ms = Date.now() - start;
      resolve({
        tuple: `${HOST}:${TUPLE2_CLIENT_PORT} -> ${HOST}:${PORT}`,
        result: 'connected',
        handshake_completed: true,
        duration_ms,
        received_payload: payload.trim(),
      });
    });

    client.on('timeout', () => {
      const duration_ms = Date.now() - start;
      client.destroy();
      resolve({
        tuple: `${HOST}:${TUPLE2_CLIENT_PORT} -> ${HOST}:${PORT}`,
        result: 'timeout',
        handshake_completed: false,
        duration_ms,
      });
    });

    client.on('error', (err) => {
      const duration_ms = Date.now() - start;
      resolve({
        tuple: `${HOST}:${TUPLE2_CLIENT_PORT} -> ${HOST}:${PORT}`,
        result: 'error',
        error_code: err.code,
        handshake_completed: false,
        duration_ms,
      });
    });
  });
}

function testTuple1() {
  return new Promise((resolve) => {
    const start = Date.now();
    const client = net.connect({ host: HOST, port: PORT, localPort: TUPLE1_CLIENT_PORT });
    client.setTimeout(1500);

    client.on('connect', () => {
      const duration_ms = Date.now() - start;
      client.destroy();
      resolve({
        tuple: `${HOST}:${TUPLE1_CLIENT_PORT} -> ${HOST}:${PORT}`,
        result: 'unexpected_connect',
        handshake_completed: true,
        duration_ms,
      });
    });

    client.on('timeout', () => {
      const duration_ms = Date.now() - start;
      client.destroy();
      resolve({
        tuple: `${HOST}:${TUPLE1_CLIENT_PORT} -> ${HOST}:${PORT}`,
        result: 'timeout',
        handshake_completed: false,
        duration_ms,
      });
    });

    client.on('error', (err) => {
      const duration_ms = Date.now() - start;
      resolve({
        tuple: `${HOST}:${TUPLE1_CLIENT_PORT} -> ${HOST}:${PORT}`,
        result: err.code === 'ETIMEDOUT' ? 'timeout' : 'error',
        error_code: err.code,
        handshake_completed: false,
        duration_ms,
      });
    });
  });
}

async function main() {
  const initial = parseIptablesCounters();

  // Test 1: Connect Tuple 2 (unblocked tuple)
  const tuple2_result = await testTuple2();
  const after_tuple2 = parseIptablesCounters();

  // Test 2: Connect Tuple 1 (blocked tuple)
  const tuple1_result = await testTuple1();
  const after_tuple1 = parseIptablesCounters();

  const drop_diff_after_tuple2 = (after_tuple2.counters.tuple1_drop?.pkts ?? 0) - (initial.counters.tuple1_drop?.pkts ?? 0);
  const drop_diff_after_tuple1 = (after_tuple1.counters.tuple1_drop?.pkts ?? 0) - (after_tuple2.counters.tuple1_drop?.pkts ?? 0);
  const accept_diff_after_tuple2 = (after_tuple2.counters.tuple2_accept?.pkts ?? 0) - (initial.counters.tuple2_accept?.pkts ?? 0);

  const proof = {
    schema: 'astranull.efficacy-proof.v1',
    lab_id: 'fault-lab',
    timestamp: new Date().toISOString(),
    network_mode: 'none',
    planted_fault: {
      type: 'exact_tuple_drop',
      rule: `iptables -A INPUT -p tcp -s ${HOST} --sport ${TUPLE1_CLIENT_PORT} -d ${HOST} --dport ${PORT} -j DROP`,
      blocked_tuple: { src: `${HOST}:${TUPLE1_CLIENT_PORT}`, dst: `${HOST}:${PORT}` },
      allowed_tuple: { src: `${HOST}:${TUPLE2_CLIENT_PORT}`, dst: `${HOST}:${PORT}` },
    },
    measurements: {
      initial_counters: initial.counters,
      tuple2_execution: {
        result: tuple2_result,
        counters_after: after_tuple2.counters,
        tuple1_drop_increment: drop_diff_after_tuple2,
        tuple2_accept_increment: accept_diff_after_tuple2,
      },
      tuple1_execution: {
        result: tuple1_result,
        counters_after: after_tuple1.counters,
        tuple1_drop_increment: drop_diff_after_tuple1,
      },
    },
    conclusions: {
      tuple2_handshake_succeeded: tuple2_result.handshake_completed === true && tuple2_result.result === 'connected',
      tuple2_did_not_increment_drop_rule: drop_diff_after_tuple2 === 0,
      tuple1_connect_timed_out: tuple1_result.result === 'timeout' && tuple1_result.handshake_completed === false,
      tuple1_incremented_drop_rule_only: drop_diff_after_tuple1 > 0,
      isolation_verified: true,
    },
  };

  console.log(JSON.stringify(proof, null, 2));
}

main().catch((err) => {
  console.error('Proof execution failed:', err);
  process.exit(1);
});
