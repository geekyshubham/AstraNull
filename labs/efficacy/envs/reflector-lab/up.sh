#!/usr/bin/env bash
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$LAB_DIR"

echo "[anl-reflector-lab] Ensuring docker network anl-reflector-lab-net exists..."
if ! docker network inspect anl-reflector-lab-net >/dev/null 2>&1; then
  docker network create --internal --subnet 172.31.42.0/24 anl-reflector-lab-net
fi

echo "[anl-reflector-lab] Building service image anl-reflector-lab-server:local..."
docker build -t anl-reflector-lab-server:local "$LAB_DIR"

echo "[anl-reflector-lab] Starting reflector lab containers..."
docker compose -p anl-reflector-lab -f docker-compose.yml up -d

echo "[anl-reflector-lab] Waiting for containers to become healthy..."
TIMEOUT=30
ELAPSED=0

until [ "$ELAPSED" -ge "$TIMEOUT" ]; do
  EXPOSED_HEALTH="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}unknown{{end}}' anl-reflector-lab-exposed 2>/dev/null || echo 'missing')"
  PROTECTED_HEALTH="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}unknown{{end}}' anl-reflector-lab-protected 2>/dev/null || echo 'missing')"

  if [ "$EXPOSED_HEALTH" = "healthy" ] && [ "$PROTECTED_HEALTH" = "healthy" ]; then
    echo "[anl-reflector-lab] Both containers healthy:"
    echo "  - anl-reflector-lab-exposed (172.31.42.10): healthy"
    echo "  - anl-reflector-lab-protected (172.31.42.20): healthy"
    exit 0
  fi

  sleep 1
  ELAPSED=$((ELAPSED + 1))
done

echo "[anl-reflector-lab] Error: containers failed to become healthy within ${TIMEOUT}s." >&2
docker compose -p anl-reflector-lab -f docker-compose.yml ps
exit 1
