#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_NAME="anl-l7-surface-lab"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"

echo "[down.sh] Tearing down ${PROJECT_NAME}..."
docker compose -p "${PROJECT_NAME}" -f "${COMPOSE_FILE}" down -v --remove-orphans
echo "[down.sh] Cleanup complete."
