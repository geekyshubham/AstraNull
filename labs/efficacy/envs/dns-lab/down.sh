#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

PROJECT_NAME="anl-dns-lab"
CONTAINER_NAME="anl-dns-lab-server"
TESTNET_NAME="anl-dns-lab-testnet"

echo "[down.sh] Stopping and removing resources for ${PROJECT_NAME}..."
docker compose -p "${PROJECT_NAME}" down -v --remove-orphans 2>/dev/null || true
docker rm -f "${CONTAINER_NAME}" 2>/dev/null || true
docker network rm "${TESTNET_NAME}" 2>/dev/null || true

echo "[down.sh] ${PROJECT_NAME} cleanup complete."
