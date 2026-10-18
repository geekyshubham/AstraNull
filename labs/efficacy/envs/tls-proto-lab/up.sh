#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"

echo "=== [anl-tls-proto-lab] Ensuring synthetic certificates exist ==="
if [[ ! -f "${SCRIPT_DIR}/certs/expired.crt" || ! -f "${SCRIPT_DIR}/certs/not_yet_valid.crt" || ! -f "${SCRIPT_DIR}/certs/valid_h2.crt" ]]; then
    python3 "${SCRIPT_DIR}/certs/generate-certs.py"
fi

echo "=== [anl-tls-proto-lab] Starting services ==="
docker compose -f "${COMPOSE_FILE}" up -d

echo "=== [anl-tls-proto-lab] Waiting for container health ==="
CONTAINERS=(
    "anl-tls-proto-lab-expired"
    "anl-tls-proto-lab-not-yet-valid"
    "anl-tls-proto-lab-h2-unbounded"
)

MAX_WAIT=30
for c in "${CONTAINERS[@]}"; do
    echo "Waiting for ${c}..."
    elapsed=0
    while true; do
        status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${c}" 2>/dev/null || echo "not_found")"
        if [[ "${status}" == "healthy" || "${status}" == "running" ]]; then
            echo "  ${c} is ${status}"
            break
        fi
        if (( elapsed >= MAX_WAIT )); then
            echo "ERROR: ${c} did not become healthy within ${MAX_WAIT}s (current status: ${status})" >&2
            docker logs "${c}" --tail 20 >&2 || true
            exit 1
        fi
        sleep 1
        elapsed=$(( elapsed + 1 ))
    done
done

echo "=== [anl-tls-proto-lab] All services up and healthy ==="
