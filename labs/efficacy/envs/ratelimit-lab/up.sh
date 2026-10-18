#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

PROJECT_NAME="anl-ratelimit-lab"

echo "Bringing up ${PROJECT_NAME}..."
docker compose -p "${PROJECT_NAME}" up -d

echo "Waiting for origins to become healthy..."
MAX_ATTEMPTS=30

for CONTAINER in anl-ratelimit-lab-limited anl-ratelimit-lab-unlimited; do
  echo "Checking ${CONTAINER}..."
  ATTEMPT=0
  STATUS="not_found"
  while [ ${ATTEMPT} -lt ${MAX_ATTEMPTS} ]; do
    STATUS="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${CONTAINER}" 2>/dev/null || echo 'not_found')"
    if [ "${STATUS}" = "healthy" ]; then
      echo "${CONTAINER} is healthy."
      break
    fi
    ATTEMPT=$((ATTEMPT + 1))
    sleep 1
  done
  if [ "${STATUS}" != "healthy" ]; then
    echo "Timed out waiting for ${CONTAINER} to become healthy (status: ${STATUS})" >&2
    exit 1
  fi
done

echo "All targets in ${PROJECT_NAME} are healthy."
