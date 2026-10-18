#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

PROJECT_NAME="anl-harness"

echo "Tearing down ${PROJECT_NAME}..."
docker compose -p "${PROJECT_NAME}" down -v --remove-orphans

# Also remove probe worker container if it exists
docker rm -f anl-harness-probe-worker 2>/dev/null || true
