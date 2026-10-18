#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

PROJECT_NAME="anl-nfw-router"

echo "Tearing down ${PROJECT_NAME}..."
docker compose -p "${PROJECT_NAME}" down -v --remove-orphans
