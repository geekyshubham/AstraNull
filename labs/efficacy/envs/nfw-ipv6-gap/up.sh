#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Build target image using docker build (handles environments where compose buildx is not configured)
docker build -t anl-nfw-ipv6-gap-target:local "${SCRIPT_DIR}"

docker compose -p anl-nfw-ipv6-gap -f "${SCRIPT_DIR}/docker-compose.yml" up -d

echo "Waiting for anl-nfw-ipv6-gap-target to become healthy..."
MAX_ATTEMPTS=30
for i in $(seq 1 "${MAX_ATTEMPTS}"); do
  STATUS=$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' anl-nfw-ipv6-gap-target 2>/dev/null || echo "starting")
  if [ "${STATUS}" = "healthy" ]; then
    echo "anl-nfw-ipv6-gap is healthy."
    exit 0
  fi
  sleep 1
done

echo "Error: target container did not become healthy within ${MAX_ATTEMPTS} seconds" >&2
exit 1
