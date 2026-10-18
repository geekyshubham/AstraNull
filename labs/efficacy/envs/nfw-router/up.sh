#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

PROJECT_NAME="anl-nfw-router"

echo "Building images for ${PROJECT_NAME}..."
docker build -t anl-nfw-router-router:local -f Dockerfile.router .
docker build -t anl-nfw-router-server:local -f Dockerfile.server .
docker build -t anl-nfw-router-client:local -f Dockerfile.client .

echo "Bringing up ${PROJECT_NAME}..."
docker compose -p "${PROJECT_NAME}" up -d

echo "Waiting for services to become healthy..."
SERVICES=("anl-nfw-router-router" "anl-nfw-router-server" "anl-nfw-router-client")
MAX_ATTEMPTS=40

for SERVICE in "${SERVICES[@]}"; do
  ATTEMPT=0
  echo "Checking health of ${SERVICE}..."
  while [ ${ATTEMPT} -lt ${MAX_ATTEMPTS} ]; do
    STATUS="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${SERVICE}" 2>/dev/null || echo 'not_found')"
    if [ "${STATUS}" = "healthy" ]; then
      echo "  ${SERVICE} is healthy."
      break
    fi
    ATTEMPT=$((ATTEMPT + 1))
    sleep 1
  done

  if [ "${STATUS}" != "healthy" ]; then
    echo "ERROR: Timed out waiting for ${SERVICE} to become healthy (status: ${STATUS})" >&2
    docker logs "${SERVICE}" || true
    exit 1
  fi
done

echo "All services in ${PROJECT_NAME} are healthy."
