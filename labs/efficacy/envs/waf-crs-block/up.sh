#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
PROJECT_NAME="anl-waf-crs-block"

echo "Bringing up ${PROJECT_NAME}..."
if ! docker compose -p "${PROJECT_NAME}" -f "${COMPOSE_FILE}" up -d; then
  echo "ERROR: Failed to bring up ${PROJECT_NAME}." >&2
  echo "If Docker reports pool overlap on 172.31.0.0/16, check for stale networks like bgp-fixture-acceptance-*." >&2
  exit 1
fi

echo "Waiting for target http://172.31.21.10/ to become healthy..."
MAX_ATTEMPTS=30
for i in $(seq 1 "${MAX_ATTEMPTS}"); do
  STATUS=$(docker run --rm --network anl-waf-crs-block-net curlimages/curl:8.10.1 -s -o /dev/null -w "%{http_code}" -m 2 http://172.31.21.10/ || true)
  if [ "${STATUS}" = "200" ]; then
    echo "anl-waf-crs-block is healthy (HTTP 200 returned from origin via WAF)"
    exit 0
  fi
  sleep 1
done

echo "Error: target 172.31.21.10 did not return HTTP 200 within ${MAX_ATTEMPTS} seconds" >&2
exit 1
