#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

PROJECT_NAME="anl-waf-crs-sqli-gap"

echo "Bringing up ${PROJECT_NAME}..."
docker compose -p "${PROJECT_NAME}" up -d

echo "Waiting for anl-waf-crs-sqli-gap-waf to become healthy..."
MAX_ATTEMPTS=30
ATTEMPT=0

while [ ${ATTEMPT} -lt ${MAX_ATTEMPTS} ]; do
  STATUS="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' anl-waf-crs-sqli-gap-waf 2>/dev/null || echo 'not_found')"
  if [ "${STATUS}" = "healthy" ]; then
    echo "anl-waf-crs-sqli-gap-waf is healthy."
    exit 0
  fi
  ATTEMPT=$((ATTEMPT + 1))
  sleep 1
done

echo "Timed out waiting for anl-waf-crs-sqli-gap-waf to become healthy (status: ${STATUS})" >&2
exit 1
