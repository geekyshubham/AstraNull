#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Starting anl-waf-crs-detect stack..."
docker compose -p anl-waf-crs-detect -f "${SCRIPT_DIR}/docker-compose.yml" up -d

echo "Waiting for target http://172.31.22.10/ to become healthy..."
MAX_ATTEMPTS=30
for i in $(seq 1 "${MAX_ATTEMPTS}"); do
  STATUS=$(docker run --rm --network anl-waf-crs-detect-net alpine:3.20 sh -c "wget -q -O - -T 2 http://172.31.22.10/" 2>/dev/null || true)
  if echo "${STATUS}" | grep -q "origin-ok"; then
    echo "anl-waf-crs-detect is healthy (origin-ok returned from 172.31.22.10:80 via DetectionOnly WAF)"
    exit 0
  fi
  sleep 1
done

echo "Error: target 172.31.22.10 did not become healthy within ${MAX_ATTEMPTS} seconds" >&2
exit 1
