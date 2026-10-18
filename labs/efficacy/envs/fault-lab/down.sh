#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT="anl-fault-lab"

echo "[down.sh] Stopping and removing ${PROJECT} resources..."
docker compose -p "${PROJECT}" -f "${DIR}/docker-compose.yml" down -v --remove-orphans
echo "[down.sh] Done."
