#!/usr/bin/env bash
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$LAB_DIR"

echo "[anl-reflector-lab] Tearing down reflector lab..."
docker compose -p anl-reflector-lab -f docker-compose.yml down -v || true
if docker network inspect anl-reflector-lab-net >/dev/null 2>&1; then
  docker network rm anl-reflector-lab-net || true
fi
docker rmi anl-reflector-lab-server:local 2>/dev/null || true
echo "[anl-reflector-lab] Cleanup complete."
