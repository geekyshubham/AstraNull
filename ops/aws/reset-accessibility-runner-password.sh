#!/usr/bin/env bash
# Host wrapper for the fixed accessibility runner password reset on the AWS control plane.
# Arguments (all nonsecret; the password itself never appears here, on argv, in a file,
# or in any host variable):
#   1. requested exact 40-character release SHA
#   2. expected sha256 of scripts/reset-accessibility-runner-password.mjs as built
#   3. transferred exact deploy.sh path (SHA/run/attempt-bound /tmp path)
#   4. transferred exact release-state.sh path (SHA/run/attempt-bound /tmp path)
# stdin is preserved untouched through every check and is inherited by the bounded
# `docker exec -i` that runs the Node operator as uid/gid 10001.
set -euo pipefail

REQUESTED_SHA=${1:-}
OPERATOR_SHA256=${2:-}
DEPLOY_LIB_PATH=${3:-}
RELEASE_STATE_LIB_PATH=${4:-}
(( $# == 4 )) || { echo 'reset: unexpected arguments; exact release SHA, operator sha256, deploy.sh path, and release-state.sh path are required' >&2; exit 1; }
OPERATOR_CONTAINER_PATH=scripts/reset-accessibility-runner-password.mjs
RESET_SNAPSHOT_CLEANUP_PENDING=0

[[ "$REQUESTED_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo 'reset: exact 40-char release SHA required' >&2; exit 1; }
[[ "$OPERATOR_SHA256" =~ ^[0-9a-f]{64}$ ]] || { echo 'reset: exact operator sha256 required' >&2; exit 1; }
# The transferred paths must embed the requested release SHA itself, not merely any
# 40-hex SHA: a stale file from another release can never pass this boundary.
[[ "$DEPLOY_LIB_PATH" =~ ^/tmp/astranull-deploy-${REQUESTED_SHA}-[0-9]+-[0-9]+\.sh$ ]] || {
  echo 'reset: transferred deploy.sh path is not bound to the requested release SHA' >&2
  exit 1
}
[[ "$RELEASE_STATE_LIB_PATH" =~ ^/tmp/astranull-release-state-${REQUESTED_SHA}-[0-9]+-[0-9]+\.sh$ ]] || {
  echo 'reset: transferred release-state.sh path is not bound to the requested release SHA' >&2
  exit 1
}
[[ -f "$DEPLOY_LIB_PATH" && ! -L "$DEPLOY_LIB_PATH" ]] || {
  echo 'reset: transferred deploy.sh is missing, non-regular, or symlinked' >&2
  exit 1
}
[[ -f "$RELEASE_STATE_LIB_PATH" && ! -L "$RELEASE_STATE_LIB_PATH" ]] || {
  echo 'reset: transferred release-state.sh is missing, non-regular, or symlinked' >&2
  exit 1
}

# Reuse the exact deploy-path helpers: the deploy lock, the private env snapshot, the
# bounded Compose wrapper, and the canonical release-state bundle functions. deploy.sh
# has a safe main guard, so sourcing it performs no release work.
export ASTRANULL_RELEASE_STATE_LIB=$RELEASE_STATE_LIB_PATH
# shellcheck source=ops/aws/deploy.sh
source "$DEPLOY_LIB_PATH"

reset_cleanup() {
  if (( RESET_SNAPSHOT_CLEANUP_PENDING )); then
    if cleanup_compose_snapshots; then
      RESET_SNAPSHOT_CLEANUP_PENDING=0
    else
      echo 'reset: CRITICAL: private environment snapshot cleanup failed; immediate operator cleanup is required' >&2
    fi
  fi
}
trap reset_cleanup EXIT

acquire_deploy_lock
cd "$ROOT"
[[ -z $(git status --porcelain --untracked-files=all) ]] || { echo 'reset: /opt/astranull worktree has tracked or untracked changes' >&2; exit 1; }
[[ "$(git rev-parse HEAD)" == "$REQUESTED_SHA" ]] || { echo 'reset: worktree HEAD does not match the requested release SHA' >&2; exit 1; }
timeout -k 10 60 git fetch --prune origin main
[[ "$(git rev-parse origin/main)" == "$REQUESTED_SHA" ]] || { echo 'reset: origin/main moved past the requested release SHA' >&2; exit 1; }

# Only the deployed canonical control-plane release may run the operator.
release_bundle_load "$CURRENT_RELEASE_BUNDLE_FILE" || { echo 'reset: canonical current release state is missing or invalid' >&2; exit 1; }
[[ "$release_bundle_control_tag" == "$REQUESTED_SHA" ]] || { echo 'reset: deployed control-plane release tag does not match the requested SHA' >&2; exit 1; }

ACTIVE_COMPOSE_FILE="$ROOT/$COMPOSE_REPO_PATH"
export ASTRANULL_CONTROL_PLANE_IMAGE_ID=$release_bundle_control_image_id
export ASTRANULL_CORE_WORKER_IMAGE_ID=$release_bundle_core_image_id
if [[ "$release_bundle_connector_enabled" == 1 ]]; then
  export ASTRANULL_CONNECTOR_WORKER_IMAGE_ID=$release_bundle_connector_image_id
else
  # Inspection-only Compose model resolution: no connector workload is created or inspected here.
  export ASTRANULL_CONNECTOR_WORKER_IMAGE_ID=$release_bundle_core_image_id
fi

RESET_SNAPSHOT_CLEANUP_PENDING=1
snapshot_env_file

release_runtime_service_matches_id control-plane "$release_bundle_control_image_id" || {
  echo 'reset: running control-plane does not uniquely match the canonical immutable image ID' >&2
  exit 1
}
control_cid=$(compose_timeout 30 ps -q control-plane) || { echo 'reset: could not resolve the running control-plane container' >&2; exit 1; }
[[ -n "$control_cid" && "$control_cid" != *$'\n'* ]] || { echo 'reset: control-plane does not have exactly one running container' >&2; exit 1; }

# The environment snapshot exists only to make the Compose inspection calls above safe.
# It is cleaned and verified absent before any mutation, and the checked cleanup above
# covers every pre-exec failure path.
if cleanup_compose_snapshots; then
  RESET_SNAPSHOT_CLEANUP_PENDING=0
else
  echo 'reset: CRITICAL: could not clean the private environment snapshot before mutation' >&2
  exit 1
fi

# The operator inside the running container must be byte-identical to the requested
# release build. The host never reads the password, so stdin is untouched by this check.
container_operator_sha256=$(timeout -k 5 30 docker exec "$control_cid" sha256sum "$OPERATOR_CONTAINER_PATH" | awk '{print $1}') || {
  echo 'reset: could not hash the accessibility operator inside the running control-plane container' >&2
  exit 1
}
[[ "$container_operator_sha256" == "$OPERATOR_SHA256" ]] || {
  echo 'reset: in-container accessibility operator does not match the requested release operator' >&2
  exit 1
}

# The control-plane process must run as uid/gid 10001 and inherit the enforced runtime
# database role. The URL is validated inside the container and is never printed or stored.
if ! timeout -k 5 30 docker exec "$control_cid" sh -c '
    [ "$(id -u)" = 10001 ] || exit 91
    [ "$(id -g)" = 10001 ] || exit 92
    url=${ASTRANULL_DATABASE_URL-}
    case "$url" in
      postgresql://astranull_app:*) ;;
      *) exit 93 ;;
    esac
    userinfo=${url#postgresql://}
    userinfo=${userinfo%%@*}
    [ "${userinfo%%:*}" = astranull_app ] || exit 93
    [ "${ASTRANULL_ENFORCE_DATABASE_ROLE-}" = 1 ] || exit 94
  '; then
  echo 'reset: control-plane process posture verification failed; refusing to run the operator' >&2
  exit 1
fi

# Replace this shell with the bounded operator exec. stdin (the framed password stream)
# is passed through untouched; fd 9 keeps the deployment lock held until exit.
exec timeout -k 30 600 docker exec -i --user 10001:10001 "$control_cid" \
  node "$OPERATOR_CONTAINER_PATH"
