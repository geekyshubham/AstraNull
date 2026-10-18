#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
PROJECT_NAME="anl-waf-coraza"

echo "Bringing up ${PROJECT_NAME}..."
if ! docker compose -p "${PROJECT_NAME}" -f "${COMPOSE_FILE}" up -d; then
  echo "ERROR: Failed to bring up ${PROJECT_NAME}." >&2
  exit 1
fi

echo "Waiting for target http://172.31.25.10/ to become healthy..."
MAX_ATTEMPTS=30
for i in $(seq 1 "${MAX_ATTEMPTS}"); do
  STATUS=$(docker run --rm --network anl-waf-coraza-net curlimages/curl:8.10.1 -s -o /dev/null -w "%{http_code}" -m 2 http://172.31.25.10/ || true)
  if [ "${STATUS}" = "200" ]; then
    echo "anl-waf-coraza is healthy (HTTP 200 returned from origin via Coraza WAF)"
    exit 0
  fi
  sleep 1
done

echo "Error: target 172.31.25.10 did not return HTTP 200 within ${MAX_ATTEMPTS} seconds" >&2
exit 1
