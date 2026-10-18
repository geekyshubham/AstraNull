#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT="anl-fault-lab"
CONTAINER="anl-fault-lab-target"
TMP_DIR="/tmp/astranull-lab/fault-lab"

mkdir -p "${TMP_DIR}"

echo "[up.sh] Building image anl-fault-lab-target:local..."
docker build -t anl-fault-lab-target:local "${DIR}"

echo "[up.sh] Starting ${PROJECT}..."
docker compose -p "${PROJECT}" -f "${DIR}/docker-compose.yml" up -d

echo "[up.sh] Waiting for ${CONTAINER} to be healthy..."
MAX_WAIT=30
WAITED=0
while true; do
  STATUS="$(docker inspect --format='{{.State.Health.Status}}' "${CONTAINER}" 2>/dev/null || echo "starting")"
  if [ "$STATUS" = "healthy" ]; then
    echo "[up.sh] ${CONTAINER} is healthy."
    break
  fi
  if [ "$WAITED" -ge "$MAX_WAIT" ]; then
    echo "[up.sh] ERROR: ${CONTAINER} failed to become healthy within ${MAX_WAIT}s (current status: ${STATUS})" >&2
    docker compose -p "${PROJECT}" -f "${DIR}/docker-compose.yml" logs
    exit 1
  fi
  sleep 1
  WAITED=$((WAITED + 1))
done

echo "[up.sh] Running fault proof..."
docker exec "${CONTAINER}" node /app/prove.mjs | tee "${TMP_DIR}/proof.json"
docker exec "${CONTAINER}" iptables -v -L INPUT -n -x > "${TMP_DIR}/iptables-counters.txt"

echo "[up.sh] Efficacy lab fault-lab is up and verified."
