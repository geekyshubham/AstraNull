#!/usr/bin/env bash
# Host wrapper that applies the AI assistant settings (ADR-0037, ADR-0040) to ops/aws/.env under the deploy lock,
# then recreates only control-plane and assistant-runner on the currently deployed release images.
# Arguments (nonsecret): release SHA, deploy.sh path, release-state.sh path, enabled (0|1), tenants,
# control-plane model, runner backend (agy|openai), LLM base URL, LLM model, LLM static headers (JSON).
# stdin carries two secret lines, in order: the runner token, then the LLM API key.
# Secrets are never echoed, logged or placed on argv.
set -euo pipefail

(( $# == 10 )) || { echo 'assistant: release SHA, deploy.sh path, release-state.sh path, enabled, tenants, model, runner backend, LLM base URL, LLM model and LLM headers are required' >&2; exit 1; }
REQUESTED_SHA=$1
DEPLOY_LIB_PATH=$2
RELEASE_STATE_LIB_PATH=$3
ASSISTANT_ENABLED=$4
ASSISTANT_TENANTS=$5
ASSISTANT_MODEL=$6
ASSISTANT_BACKEND=$7
LLM_BASE_URL=$8
LLM_MODEL=$9
LLM_HEADERS=${10}

[[ "$REQUESTED_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo 'assistant: exact 40-char release SHA required' >&2; exit 1; }
[[ "$DEPLOY_LIB_PATH" =~ ^/tmp/astranull-deploy-${REQUESTED_SHA}-[0-9]+-[0-9]+\.sh$ && -f "$DEPLOY_LIB_PATH" && ! -L "$DEPLOY_LIB_PATH" ]] || {
  echo 'assistant: transferred deploy.sh is not bound to the requested release SHA' >&2; exit 1; }
[[ "$RELEASE_STATE_LIB_PATH" =~ ^/tmp/astranull-release-state-${REQUESTED_SHA}-[0-9]+-[0-9]+\.sh$ && -f "$RELEASE_STATE_LIB_PATH" && ! -L "$RELEASE_STATE_LIB_PATH" ]] || {
  echo 'assistant: transferred release-state.sh is not bound to the requested release SHA' >&2; exit 1; }
[[ "$ASSISTANT_ENABLED" =~ ^[01]$ ]] || { echo 'assistant: enabled must be 0 or 1' >&2; exit 1; }
[[ "$ASSISTANT_TENANTS" =~ ^(\*|[a-z0-9_]{1,64}(,[a-z0-9_]{1,64}){0,49})?$ ]] || { echo 'assistant: tenants must be *, empty or a comma list of tenant ids' >&2; exit 1; }
[[ -z "$ASSISTANT_MODEL" || "$ASSISTANT_MODEL" =~ ^[a-z0-9][a-z0-9._-]{1,80}$ ]] || { echo 'assistant: invalid model name' >&2; exit 1; }
[[ "$ASSISTANT_BACKEND" =~ ^(agy|openai)?$ ]] || { echo 'assistant: runner backend must be agy, openai or empty' >&2; exit 1; }
[[ -z "$LLM_BASE_URL" || "$LLM_BASE_URL" == 'https://opencode.ai/zen/go/v1' ]] || { echo 'assistant: LLM base URL must be empty or exactly https://opencode.ai/zen/go/v1' >&2; exit 1; }
[[ -z "$LLM_MODEL" || "$LLM_MODEL" =~ ^[A-Za-z0-9][A-Za-z0-9._:/-]{1,80}$ ]] || { echo 'assistant: invalid LLM model name' >&2; exit 1; }
headers_pattern='^(\{[A-Za-z0-9 ":,._/;=+@()-]+\})?$'
[[ "$LLM_HEADERS" =~ $headers_pattern && ${#LLM_HEADERS} -le 900 ]] || { echo 'assistant: LLM headers must be empty or a JSON object of plain printable text' >&2; exit 1; }
if [[ -n "$LLM_HEADERS" ]]; then
  LLM_HEADERS_JSON=$LLM_HEADERS python3 -I - <<'PY' || { echo 'assistant: LLM headers must be at most 8 unique non-reserved RFC 7230 header names with printable ASCII values of 1-256 characters' >&2; exit 1; }
import json, os, re, sys
try:
    headers = json.loads(os.environ['LLM_HEADERS_JSON'])
except ValueError:
    sys.exit(1)
reserved = {'authorization', 'host', 'content-type', 'content-length', 'cookie', 'transfer-encoding', 'connection'}
token = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
value = re.compile(r'^[\x20-\x7e]{1,256}$')
if not isinstance(headers, dict) or len(headers) > 8:
    sys.exit(1)
names = [name.lower() for name in headers]
if len(set(names)) != len(names) or any(name in reserved or not token.match(name) for name in names):
    sys.exit(1)
if not all(isinstance(item, str) and value.match(item) for item in headers.values()):
    sys.exit(1)
PY
fi
if [[ "$ASSISTANT_ENABLED" == 1 && "$ASSISTANT_BACKEND" == openai ]]; then
  [[ -n "$LLM_BASE_URL" ]] || { echo 'assistant: the openai backend requires an LLM base URL' >&2; exit 1; }
fi

IFS= read -r -t 30 RUNNER_TOKEN || RUNNER_TOKEN=''
IFS= read -r -t 30 LLM_API_KEY || LLM_API_KEY=''
if [[ "$ASSISTANT_ENABLED" == 1 ]]; then
  [[ "$RUNNER_TOKEN" =~ ^[A-Za-z0-9_-]+$ && ${#RUNNER_TOKEN} -ge 32 && ${#RUNNER_TOKEN} -le 256 ]] || { echo 'assistant: a 32-256 character URL-safe runner token is required on stdin' >&2; exit 1; }
  if [[ "$ASSISTANT_BACKEND" == openai ]]; then
    [[ "$LLM_API_KEY" =~ ^[A-Za-z0-9._~+/=-]+$ && ${#LLM_API_KEY} -ge 16 && ${#LLM_API_KEY} -le 512 ]] || { echo 'assistant: a 16-512 character LLM API key is required on the second stdin line' >&2; exit 1; }
  else
    LLM_API_KEY=''
  fi
else
  RUNNER_TOKEN=''
  LLM_API_KEY=''
fi

export ASTRANULL_RELEASE_STATE_LIB=$RELEASE_STATE_LIB_PATH
# shellcheck source=ops/aws/deploy.sh
source "$DEPLOY_LIB_PATH"

candidate=''
assistant_cleanup() {
  [[ -z "$candidate" ]] || rm -f -- "$candidate"
  cleanup_compose_snapshots || echo 'assistant: CRITICAL: private environment snapshot cleanup failed; immediate operator cleanup is required' >&2
}
trap assistant_cleanup EXIT

acquire_deploy_lock
cd "$ROOT"
[[ "$(git rev-parse HEAD)" == "$REQUESTED_SHA" ]] || { echo 'assistant: deployed HEAD does not match the requested release SHA' >&2; exit 1; }
validate_env_source
[[ "$(stat -c '%u' -- "$ENV_FILE")" == "$(id -u)" ]] || { echo "assistant: $ENV_FILE must be owned by the deploy user to be updated" >&2; exit 1; }
env_mode=$(stat -c '%a' -- "$ENV_FILE")

release_bundle_load "$CURRENT_RELEASE_BUNDLE_FILE" || { echo 'assistant: canonical current release state is missing or invalid' >&2; exit 1; }
[[ "$release_bundle_control_tag" == "$REQUESTED_SHA" ]] || { echo 'assistant: deployed control-plane release tag does not match the requested SHA' >&2; exit 1; }
ACTIVE_COMPOSE_FILE="$ROOT/$COMPOSE_REPO_PATH"
export ASTRANULL_CONTROL_PLANE_IMAGE_ID=$release_bundle_control_image_id
export ASTRANULL_CORE_WORKER_IMAGE_ID=$release_bundle_core_image_id
if [[ "$release_bundle_connector_enabled" == 1 ]]; then
  export ASTRANULL_CONNECTOR_WORKER_IMAGE_ID=$release_bundle_connector_image_id
else
  export ASTRANULL_CONNECTOR_WORKER_IMAGE_ID=$release_bundle_core_image_id
fi

snapshot_env_file
release_runtime_service_matches_id control-plane "$release_bundle_control_image_id" || {
  echo 'assistant: running control-plane does not uniquely match the canonical immutable image ID' >&2; exit 1; }
cleanup_compose_snapshots || { echo 'assistant: could not clean the private environment snapshot before the update' >&2; exit 1; }

candidate=$(mktemp "$(dirname -- "$ENV_FILE")/.env.assistant.XXXXXX")
chmod 600 "$candidate"
grep -v -E '^(ASTRANULL_ASSISTANT_ENABLED|ASTRANULL_ASSISTANT_TENANTS|ASTRANULL_ASSISTANT_RUNNER_TOKEN|ASTRANULL_ASSISTANT_MODEL|ASTRANULL_ASSISTANT_RUNNER_BACKEND|ASTRANULL_ASSISTANT_LLM_BASE_URL|ASTRANULL_ASSISTANT_LLM_API_KEY|ASTRANULL_ASSISTANT_LLM_MODEL|ASTRANULL_ASSISTANT_LLM_HEADERS)=' -- "$ENV_FILE" > "$candidate" || true
{
  printf 'ASTRANULL_ASSISTANT_ENABLED=%s\n' "$ASSISTANT_ENABLED"
  printf 'ASTRANULL_ASSISTANT_TENANTS=%s\n' "$ASSISTANT_TENANTS"
  printf 'ASTRANULL_ASSISTANT_RUNNER_TOKEN=%s\n' "$RUNNER_TOKEN"
  printf 'ASTRANULL_ASSISTANT_MODEL=%s\n' "$ASSISTANT_MODEL"
  printf 'ASTRANULL_ASSISTANT_RUNNER_BACKEND=%s\n' "$ASSISTANT_BACKEND"
  printf 'ASTRANULL_ASSISTANT_LLM_BASE_URL=%s\n' "$LLM_BASE_URL"
  printf 'ASTRANULL_ASSISTANT_LLM_API_KEY=%s\n' "$LLM_API_KEY"
  printf 'ASTRANULL_ASSISTANT_LLM_MODEL=%s\n' "$LLM_MODEL"
  printf "ASTRANULL_ASSISTANT_LLM_HEADERS='%s'\n" "$LLM_HEADERS"
} >> "$candidate"
unset RUNNER_TOKEN LLM_API_KEY
chmod "$env_mode" "$candidate"
mv -f -- "$candidate" "$ENV_FILE"
candidate=''
validate_env_source

snapshot_env_file
compose_timeout 300 up -d --no-deps --force-recreate --wait --wait-timeout 240 control-plane assistant-runner
verify_service_image_tag control-plane "$release_bundle_control_tag" "$release_bundle_control_image_id"
verify_service_image_tag assistant-runner "$release_bundle_core_tag" "$release_bundle_core_image_id"
check_control_plane
check_service_health assistant-runner

printf '{"status":"assistant_configured","enabled":%s,"tenants":"%s","model":"%s","backend":"%s","llm_base_url":"%s","llm_model":"%s","recreated":["control-plane","assistant-runner"]}\n' \
  "$([[ "$ASSISTANT_ENABLED" == 1 ]] && echo true || echo false)" "$ASSISTANT_TENANTS" "$ASSISTANT_MODEL" "$ASSISTANT_BACKEND" "$LLM_BASE_URL" "$LLM_MODEL"
