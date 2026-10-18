#!/usr/bin/env bash
set -euo pipefail

NETWORK="anl-nfw-router-client"
TARGET="172.31.31.2"

echo "=========================================================="
echo "AstraNull Efficacy Lab Proofs: nfw-router"
echo "Target: ${TARGET} on network ${NETWORK}"
echo "=========================================================="

echo ""
echo "[1/6] Proving allowed TCP port (80)..."
OUTPUT_80=$(docker run --rm --network "${NETWORK}" curlimages/curl:latest -sS --max-time 3 "http://${TARGET}/")
echo "  Response: ${OUTPUT_80}"
if [ "${OUTPUT_80}" = "origin-ok" ]; then
  echo "  --> PROOF 1 PASSED: TCP 80 completes handshake and returns 200 origin-ok."
else
  echo "  --> PROOF 1 FAILED" >&2
  exit 1
fi

echo ""
echo "[2/6] Proving dropped TCP port (8081)..."
START_TIME=$(date +%s)
RC_8081=0
docker run --rm --network "${NETWORK}" alpine:3.20 nc -w 3 -z "${TARGET}" 8081 >/dev/null 2>&1 || RC_8081=$?
ELAPSED_8081=$(( $(date +%s) - START_TIME ))
echo "  Exit code: ${RC_8081}, Elapsed: ${ELAPSED_8081}s"
if [ ${RC_8081} -ne 0 ] && [ ${ELAPSED_8081} -ge 2 ]; then
  echo "  --> PROOF 2 PASSED: TCP 8081 timed out after ${ELAPSED_8081}s (DROP policy verified)."
else
  echo "  --> PROOF 2 FAILED" >&2
  exit 1
fi

echo ""
echo "[3/6] Proving rejected TCP port (8082)..."
START_TIME=$(date +%s)
RC_8082=0
docker run --rm --network "${NETWORK}" alpine:3.20 nc -w 3 -z "${TARGET}" 8082 >/dev/null 2>&1 || RC_8082=$?
ELAPSED_8082=$(( $(date +%s) - START_TIME ))
echo "  Exit code: ${RC_8082}, Elapsed: ${ELAPSED_8082}s"
if [ ${RC_8082} -ne 0 ] && [ ${ELAPSED_8082} -le 1 ]; then
  echo "  --> PROOF 3 PASSED: TCP 8082 immediately refused via RST in ${ELAPSED_8082}s (REJECT policy verified)."
else
  echo "  --> PROOF 3 FAILED" >&2
  exit 1
fi

echo ""
echo "[4/6] Proving UDP ports (8053 allowed, 8054 dropped)..."
echo "  Testing allowed UDP 8053..."
UDP_8053_RES=$(docker run --rm --network "${NETWORK}" node:22-alpine node -e "
const dgram = require('dgram');
const client = dgram.createSocket('udp4');
client.on('message', (msg, rinfo) => {
  console.log('REPLY:' + msg.toString().trim());
  client.close();
  process.exit(0);
});
client.send('ping', 8053, '${TARGET}');
setTimeout(() => { console.log('TIMEOUT'); client.close(); process.exit(1); }, 3000);
")
echo "  UDP 8053 response: ${UDP_8053_RES}"
if echo "${UDP_8053_RES}" | grep -q "REPLY:ok"; then
  echo "  --> PROOF 4a PASSED: UDP 8053 answered one datagram."
else
  echo "  --> PROOF 4a FAILED" >&2
  exit 1
fi

echo "  Testing dropped UDP 8054..."
UDP_8054_RES=$(docker run --rm --network "${NETWORK}" node:22-alpine node -e "
const dgram = require('dgram');
const client = dgram.createSocket('udp4');
client.on('message', (msg) => {
  console.log('UNEXPECTED_REPLY');
  client.close();
  process.exit(1);
});
client.send('ping', 8054, '${TARGET}');
setTimeout(() => { console.log('SILENT_TIMEOUT'); client.close(); process.exit(0); }, 2000);
")
echo "  UDP 8054 response: ${UDP_8054_RES}"
if echo "${UDP_8054_RES}" | grep -q "SILENT_TIMEOUT"; then
  echo "  --> PROOF 4b PASSED: UDP 8054 dropped silently with no reply."
else
  echo "  --> PROOF 4b FAILED" >&2
  exit 1
fi

echo ""
echo "[5/6] Proving connection limit on TCP 8083 (limit: 2 connections per source)..."
CONNLIMIT_RES=$(docker run --rm --network "${NETWORK}" node:22-alpine node -e "
const net = require('net');
function connect(id) {
  return new Promise((resolve) => {
    const s = net.connect({ host: '${TARGET}', port: 8083 }, () => {
      console.log('Attempt ' + id + ': CONNECTED');
      resolve({ id, success: true, socket: s });
    });
    s.on('error', (err) => {
      console.log('Attempt ' + id + ': REFUSED (' + err.code + ')');
      resolve({ id, success: false, socket: null, error: err.code });
    });
  });
}
async function main() {
  const c1 = await connect(1);
  const c2 = await connect(2);
  const c3 = await connect(3);
  if (c1.success && c2.success && !c3.success && c3.error === 'ECONNREFUSED') {
    console.log('RESULT:PASS');
  } else {
    console.log('RESULT:FAIL');
  }
  if (c1.socket) c1.socket.destroy();
  if (c2.socket) c2.socket.destroy();
  if (c3.socket) c3.socket.destroy();
}
main();
")
echo "  ${CONNLIMIT_RES}"
if echo "${CONNLIMIT_RES}" | grep -q "RESULT:PASS"; then
  echo "  --> PROOF 5 PASSED: 3 sequential connection attempts allowed 2 and refused 3rd (connlimit enforced)."
else
  echo "  --> PROOF 5 FAILED" >&2
  exit 1
fi

echo ""
echo "[6/6] Proving exposed management port (22 SSH banner)..."
BANNER_22=$(docker run --rm --network "${NETWORK}" alpine:3.20 nc -w 3 "${TARGET}" 22)
echo "  Banner received: ${BANNER_22}"
if echo "${BANNER_22}" | grep -q "SSH-2.0-OpenSSH_9.0"; then
  echo "  --> PROOF 6 PASSED: Management port 22 reachable with SSH banner."
else
  echo "  --> PROOF 6 FAILED" >&2
  exit 1
fi

echo ""
echo "=========================================================="
echo "ALL PROOFS PASSED SUCCESSFULLY."
echo "=========================================================="
