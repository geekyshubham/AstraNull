#!/usr/bin/env bash
# Host wrapper that sets the AI assistant switch (ADR-0037, ADR-0040) in ops/aws/.env under the deploy lock.
# Arguments (nonsecret): release SHA, deploy.sh path, release-state.sh path, enabled (0|1), tenants, model.
# The runner token arrives only on stdin and is never echoed, logged or placed on argv.
set -euo pipefail

REQUESTED_SHA=${1:-}
DEPLOY_LIB_PATH=${2:-}
RELEASE_STATE_LIB_PATH=${3:-}
ASSISTANT_ENABLED=${4:-}
ASSISTANT_TENANTS=${5:-}
ASSISTANT_MODEL=${6:-}
ASSISTANT_BACKEND=${7:-}
(( $# == 7 )) || { echo 'assistant: release SHA, deploy.sh path, release-state.sh path, enabled, tenants, model and runner backend are required' >&2; exit 1; }

[[ "$REQUESTED_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo 'assistant: exact 40-char release SHA required' >&2; exit 1; }
[[ "$DEPLOY_LIB_PATH" =~ ^/tmp/astranull-deploy-${REQUESTED_SHA}-[0-9]+-[0-9]+\.sh$ && -f "$DEPLOY_LIB_PATH" && ! -L "$DEPLOY_LIB_PATH" ]] || {
  echo 'assistant: transferred deploy.sh is not bound to the requested release SHA' >&2; exit 1; }
[[ "$RELEASE_STATE_LIB_PATH" =~ ^/tmp/astranull-release-state-${REQUESTED_SHA}-[0-9]+-[0-9]+\.sh$ && -f "$RELEASE_STATE_LIB_PATH" && ! -L "$RELEASE_STATE_LIB_PATH" ]] || {
  echo 'assistant: transferred release-state.sh is not bound to the requested release SHA' >&2; exit 1; }
[[ "$ASSISTANT_ENABLED" =~ ^[01]$ ]] || { echo 'assistant: enabled must be 0 or 1' >&2; exit 1; }
[[ "$ASSISTANT_TENANTS" =~ ^(\*|[a-z0-9_]{1,64}(,[a-z0-9_]{1,64}){0,49})?$ ]] || { echo 'assistant: tenants must be *, empty or a comma list of tenant ids' >&2; exit 1; }
[[ -z "$ASSISTANT_MODEL" || "$ASSISTANT_MODEL" =~ ^[a-z0-9][a-z0-9._-]{1,80}$ ]] || { echo 'assistant: invalid model name' >&2; exit 1; }
[[ "$ASSISTANT_BACKEND" =~ ^(agy|openai)?$ ]] || { echo 'assistant: runner backend must be agy, openai or empty' >&2; exit 1; }

IFS= read -r -t 30 RUNNER_TOKEN || RUNNER_TOKEN=''
if [[ "$ASSISTANT_ENABLED" == 1 ]]; then
  [[ "$RUNNER_TOKEN" =~ ^[A-Za-z0-9_-]{32,256}$ ]] || { echo 'assistant: a 32-256 character URL-safe runner token is required on stdin' >&2; exit 1; }
else
  RUNNER_TOKEN=''
fi

export ASTRANULL_RELEASE_STATE_LIB=$RELEASE_STATE_LIB_PATH
# shellcheck source=ops/aws/deploy.sh
source "$DEPLOY_LIB_PATH"

acquire_deploy_lock
cd "$ROOT"
[[ "$(git rev-parse HEAD)" == "$REQUESTED_SHA" ]] || { echo 'assistant: deployed HEAD does not match the requested release SHA' >&2; exit 1; }
validate_env_source
[[ "$(stat -c '%u' -- "$ENV_FILE")" == "$(id -u)" ]] || { echo "assistant: $ENV_FILE must be owned by the deploy user to be updated" >&2; exit 1; }
env_mode=$(stat -c '%a' -- "$ENV_FILE")

candidate=$(mktemp "$(dirname -- "$ENV_FILE")/.env.assistant.XXXXXX")
trap 'rm -f -- "$candidate"' EXIT
chmod 600 "$candidate"
grep -v -E '^(ASTRANULL_ASSISTANT_ENABLED|ASTRANULL_ASSISTANT_TENANTS|ASTRANULL_ASSISTANT_RUNNER_TOKEN|ASTRANULL_ASSISTANT_MODEL|ASTRANULL_ASSISTANT_RUNNER_BACKEND)=' -- "$ENV_FILE" > "$candidate" || true
{
  printf 'ASTRANULL_ASSISTANT_ENABLED=%s\n' "$ASSISTANT_ENABLED"
  printf 'ASTRANULL_ASSISTANT_TENANTS=%s\n' "$ASSISTANT_TENANTS"
  printf 'ASTRANULL_ASSISTANT_RUNNER_TOKEN=%s\n' "$RUNNER_TOKEN"
  printf 'ASTRANULL_ASSISTANT_MODEL=%s\n' "$ASSISTANT_MODEL"
  printf 'ASTRANULL_ASSISTANT_RUNNER_BACKEND=%s\n' "$ASSISTANT_BACKEND"
} >> "$candidate"
unset RUNNER_TOKEN
chmod "$env_mode" "$candidate"
mv -f -- "$candidate" "$ENV_FILE"
trap - EXIT
validate_env_source

printf '{"status":"assistant_configured","enabled":%s,"tenants":"%s","model":"%s","backend":"%s"}\n' \
  "$([[ "$ASSISTANT_ENABLED" == 1 ]] && echo true || echo false)" "$ASSISTANT_TENANTS" "$ASSISTANT_MODEL" "$ASSISTANT_BACKEND"
