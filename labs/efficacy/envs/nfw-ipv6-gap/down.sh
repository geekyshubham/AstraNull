#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

docker compose -p anl-nfw-ipv6-gap -f "${SCRIPT_DIR}/docker-compose.yml" down -v --remove-orphans
