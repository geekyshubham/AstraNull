#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_NAME="anl-l7-surface-lab"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"

echo "[up.sh] Starting ${PROJECT_NAME}..."
docker compose -p "${PROJECT_NAME}" -f "${COMPOSE_FILE}" up -d

echo "[up.sh] Waiting for target container to report healthy..."
TARGET_CONTAINER="anl-l7-surface-lab-target"
MAX_ATTEMPTS=30
ATTEMPT=0

while [ "${ATTEMPT}" -lt "${MAX_ATTEMPTS}" ]; do
    HEALTH_STATUS="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${TARGET_CONTAINER}" 2>/dev/null || echo "starting")"
    if [ "${HEALTH_STATUS}" = "healthy" ]; then
        echo "[up.sh] ${TARGET_CONTAINER} is healthy."
        exit 0
    fi
    ATTEMPT=$((ATTEMPT + 1))
    sleep 1
done

echo "[up.sh] ERROR: ${TARGET_CONTAINER} did not become healthy in time (status: ${HEALTH_STATUS})." >&2
exit 1
