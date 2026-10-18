#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

PROJECT_NAME="anl-dns-lab"
CONTAINER_NAME="anl-dns-lab-server"
IMAGE_TAG="anl-dns-lab/dns-server:latest"

# Idempotency check: healthy only counts on the contract address.
STATUS=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${CONTAINER_NAME}" 2>/dev/null || echo "not_found")
PLACE=$(docker inspect --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}={{$v.IPAddress}} {{end}}' "${CONTAINER_NAME}" 2>/dev/null || echo "missing")
if [ "${STATUS}" = "healthy" ] && [ "${PLACE}" = "anl-dns-lab-net=172.31.41.10 " ]; then
    echo "[up.sh] ${CONTAINER_NAME} is already healthy on 172.31.41.10."
    exit 0
fi

if [ "${STATUS}" != "not_found" ]; then
    echo "[up.sh] Replacing ${CONTAINER_NAME} (${PLACE}) so it can join anl-dns-lab-net."
    docker rm -f "${CONTAINER_NAME}" >/dev/null
fi
docker network rm anl-dns-lab-testnet >/dev/null 2>&1 || true

echo "[up.sh] Building image ${IMAGE_TAG}..."
docker build -t "${IMAGE_TAG}" .

echo "[up.sh] Starting ${PROJECT_NAME} on anl-dns-lab-net 172.31.41.0/24..."
docker compose -p "${PROJECT_NAME}" up -d

MAX_WAIT=30
WAITED=0
while [ "${WAITED}" -lt "${MAX_WAIT}" ]; do
    STATUS=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${CONTAINER_NAME}" 2>/dev/null || echo "not_found")
    if [ "${STATUS}" = "healthy" ]; then
        echo "[up.sh] ${CONTAINER_NAME} is healthy (${WAITED}s)."
        exit 0
    fi
    sleep 1
    WAITED=$((WAITED + 1))
done

echo "[up.sh] ERROR: ${CONTAINER_NAME} failed to become healthy within ${MAX_WAIT}s (status: ${STATUS})." >&2
docker logs "${CONTAINER_NAME}" --tail 50 >&2 || true
exit 1
