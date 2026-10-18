#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

PROJECT_NAME="anl-harness"

echo "Bringing up ${PROJECT_NAME}..."
docker compose -p "${PROJECT_NAME}" up -d

echo "Verifying anl-harness-net is available..."
docker network inspect anl-harness-net >/dev/null 2>&1 || {
  echo "Error: anl-harness-net was not created" >&2
  exit 1
}

echo "anl-harness network is ready."
