#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
docker compose -p anl-waf-crs-pl4 -f "${SCRIPT_DIR}/docker-compose.yml" down -v --remove-orphans
