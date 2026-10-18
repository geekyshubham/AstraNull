#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

docker compose -p anl-waf-crs-pl4 -f "${SCRIPT_DIR}/docker-compose.yml" up -d

echo "Waiting for target http://172.31.24.10/ to become healthy..."
MAX_ATTEMPTS=30
for i in $(seq 1 "${MAX_ATTEMPTS}"); do
  STATUS=$(docker run --rm --network anl-waf-crs-pl4-net curlimages/curl:latest -s -o /dev/null -w "%{http_code}" -m 2 http://172.31.24.10/ || true)
  if [ "${STATUS}" = "200" ]; then
    echo "anl-waf-crs-pl4 is healthy (HTTP 200 returned from origin via WAF)"
    exit 0
  fi
  sleep 1
done

echo "Error: target 172.31.24.10 did not return HTTP 200 within ${MAX_ATTEMPTS} seconds" >&2
exit 1
