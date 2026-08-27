#!/usr/bin/env bash
# Pull main and rebuild the AWS compose stack. Idempotent. Run on the VM as ubuntu.
set -euo pipefail

ROOT=/opt/astranull
COMPOSE_FILE="$ROOT/ops/aws/docker-compose.yml"
ENV_FILE="$ROOT/ops/aws/.env"

cd "$ROOT"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "deploy: missing $ENV_FILE — copy ops/aws/env.example and fill secrets first" >&2
  exit 1
fi

git fetch --prune origin
git checkout -q main
git reset --hard origin/main

# Compose variable substitution reads the shell env / --env-file, not the
# service env_file. POSTGRES_PASSWORD must be visible here.
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d --build --remove-orphans
docker image prune -f >/dev/null

echo "deploy: ok $(git rev-parse --short HEAD)"
