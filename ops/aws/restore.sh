#!/usr/bin/env bash
set -euo pipefail

ROOT=/opt/astranull
COMPOSE_FILE="$ROOT/ops/aws/docker-compose.yml"
ENV_FILE="$ROOT/ops/aws/.env"
BACKUP_DIR=/opt/astranull-backups
if [[ ${BASH_SOURCE[0]} != "$0" && -n ${ASTRANULL_TEST_BACKUP_DIR:-} ]]; then
  BACKUP_DIR=$ASTRANULL_TEST_BACKUP_DIR
fi
DEPLOY_LOCK_FILE="$BACKUP_DIR/deploy.lock"
ENV_SNAPSHOT=''
COMPOSE_SNAPSHOT_FILE="$BACKUP_DIR/.astranull-compose-source.restore.$$"
COMPOSE_SNAPSHOT_OWNED=0
COMPOSE_RENDER_FILE="$BACKUP_DIR/.astranull-compose-render.restore.$$"
COMPOSE_RENDER_OWNED=0
DEPLOY_STATE_DIR="$BACKUP_DIR/deploy-state"
CONTROL_PLANE_IMAGE_TAG_FILE="$DEPLOY_STATE_DIR/control-plane-image-tag"
CORE_WORKER_IMAGE_STATE_FILE="$DEPLOY_STATE_DIR/core-worker-image-state"
CONNECTOR_IMAGE_STATE_FILE="$DEPLOY_STATE_DIR/connector-image-state"
RELEASE_VALIDATOR_IMAGE_STATE_FILE="$DEPLOY_STATE_DIR/release-validator-image-state"
STATE_LOG_PREFIX=restore

load_release_state_library() {
  local candidate=${ASTRANULL_RELEASE_STATE_LIB:-}
  if [[ -z "$candidate" ]]; then
    if [[ -f "$ROOT/ops/aws/release-state.sh" && ! -L "$ROOT/ops/aws/release-state.sh" ]]; then
      candidate="$ROOT/ops/aws/release-state.sh"
    else
      candidate="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/release-state.sh"
    fi
  fi
  [[ -f "$candidate" && ! -L "$candidate" ]] || {
    echo "restore: missing or unsafe release-state helper $candidate" >&2
    return 1
  }
  # shellcheck source=ops/aws/release-state.sh
  source "$candidate"
}

MANIFEST=''
BACKUP=''
plain_host=''
expected_plaintext_sha256=''
succeeded=0
outage_started=0
control_plane_tag=''
control_plane_image_id=''
core_worker_tag=''
core_worker_image_id=''
connector_mode='disabled'
connector_tag=''
connector_image_id=''
connector_enabled=0
connector_candidate_image_id=''
release_validator_tag=''
release_validator_image_id=''

private_file_mode() {
  stat -c '%a' -- "$1" 2>/dev/null || stat -f '%Lp' "$1"
}

cleanup_compose_render_checked() {
  local failed=0
  ((COMPOSE_RENDER_OWNED)) || return 0
  if [[ -e "$COMPOSE_RENDER_FILE" || -L "$COMPOSE_RENDER_FILE" ]]; then
    if ! rm -f -- "$COMPOSE_RENDER_FILE"; then echo "restore: WARNING: could not delete private Compose render $COMPOSE_RENDER_FILE" >&2; failed=1; fi
  fi
  if [[ -e "$COMPOSE_RENDER_FILE" || -L "$COMPOSE_RENDER_FILE" ]]; then
    echo "restore: CRITICAL: private Compose render still exists at $COMPOSE_RENDER_FILE; immediate operator cleanup is required" >&2
    failed=1
  else
    COMPOSE_RENDER_OWNED=0
  fi
  ((failed == 0))
}

create_compose_render_file() {
  ((COMPOSE_RENDER_OWNED == 0)) || { echo 'restore: refusing to replace an active private Compose render' >&2; return 1; }
  [[ ! -e "$COMPOSE_RENDER_FILE" && ! -L "$COMPOSE_RENDER_FILE" ]] || { echo "restore: refusing pre-existing Compose render path $COMPOSE_RENDER_FILE" >&2; return 1; }
  COMPOSE_RENDER_OWNED=1
  if ! (umask 077; set -o noclobber; : > "$COMPOSE_RENDER_FILE") 2>/dev/null; then
    COMPOSE_RENDER_OWNED=0
    echo "restore: could not exclusively create private Compose render $COMPOSE_RENDER_FILE" >&2
    return 1
  fi
  if ! chmod 600 "$COMPOSE_RENDER_FILE"; then
    echo 'restore: could not set private Compose render mode 0600' >&2
    cleanup_compose_render_checked || return 125
    return 1
  fi
  if [[ ! -f "$COMPOSE_RENDER_FILE" || -L "$COMPOSE_RENDER_FILE" \
    || "$(private_file_mode "$COMPOSE_RENDER_FILE")" != 600 ]]; then
    echo 'restore: private Compose render is not a regular mode-0600 file' >&2
    cleanup_compose_render_checked || return 125
    return 1
  fi
}

validate_env_source() {
  local env_mode env_owner env_links
  [[ -f "$ENV_FILE" && ! -L "$ENV_FILE" ]] || {
    echo "restore: $ENV_FILE must be a regular non-symlink file" >&2
    return 1
  }
  env_mode=$(stat -c '%a' -- "$ENV_FILE") || return
  env_owner=$(stat -c '%u' -- "$ENV_FILE") || return
  env_links=$(stat -c '%h' -- "$ENV_FILE") || return
  [[ "$env_mode" =~ ^[46]00$ ]] || {
    echo "restore: $ENV_FILE must have mode 400 or 600" >&2
    return 1
  }
  [[ "$env_owner" == 0 || "$env_owner" == "$(id -u)" ]] || {
    echo "restore: $ENV_FILE must be owned by root or the deploy user" >&2
    return 1
  }
  [[ "$env_links" == 1 ]] || {
    echo "restore: $ENV_FILE must not have additional hard links" >&2
    return 1
  }
}

snapshot_compose_file() {
  local before after
  ((COMPOSE_SNAPSHOT_OWNED == 0)) || { echo 'restore: refusing to replace an active immutable Compose snapshot' >&2; return 1; }
  [[ -f "$COMPOSE_FILE" && ! -L "$COMPOSE_FILE" ]] || { echo "restore: checked-out Compose file is missing or unsafe: $COMPOSE_FILE" >&2; return 1; }
  [[ ! -e "$COMPOSE_SNAPSHOT_FILE" && ! -L "$COMPOSE_SNAPSHOT_FILE" ]] || { echo "restore: refusing pre-existing Compose snapshot path $COMPOSE_SNAPSHOT_FILE" >&2; return 1; }
  before=$(stat -c '%d:%i:%s:%Y:%Z' -- "$COMPOSE_FILE") || return
  COMPOSE_SNAPSHOT_OWNED=1
  if ! (umask 077; set -o noclobber; : > "$COMPOSE_SNAPSHOT_FILE") 2>/dev/null; then
    COMPOSE_SNAPSHOT_OWNED=0
    echo "restore: could not exclusively create immutable Compose snapshot $COMPOSE_SNAPSHOT_FILE" >&2
    return 1
  fi
  chmod 600 "$COMPOSE_SNAPSHOT_FILE" || return
  cat -- "$COMPOSE_FILE" > "$COMPOSE_SNAPSHOT_FILE" || return
  after=$(stat -c '%d:%i:%s:%Y:%Z' -- "$COMPOSE_FILE") || return
  [[ "$before" == "$after" && -f "$COMPOSE_SNAPSHOT_FILE" && ! -L "$COMPOSE_SNAPSHOT_FILE" && "$(private_file_mode "$COMPOSE_SNAPSHOT_FILE")" == 600 ]] || {
    echo 'restore: checked-out Compose file changed while it was being snapshotted or the snapshot is unsafe' >&2
    return 1
  }
}

cleanup_compose_snapshot_checked() {
  local failed=0
  ((COMPOSE_SNAPSHOT_OWNED)) || return 0
  if [[ -e "$COMPOSE_SNAPSHOT_FILE" || -L "$COMPOSE_SNAPSHOT_FILE" ]]; then
    if ! rm -f -- "$COMPOSE_SNAPSHOT_FILE"; then echo "restore: WARNING: could not delete immutable Compose snapshot $COMPOSE_SNAPSHOT_FILE" >&2; failed=1; fi
  fi
  if [[ -e "$COMPOSE_SNAPSHOT_FILE" || -L "$COMPOSE_SNAPSHOT_FILE" ]]; then
    echo "restore: CRITICAL: immutable Compose snapshot still exists at $COMPOSE_SNAPSHOT_FILE; immediate operator cleanup is required" >&2
    failed=1
  else
    COMPOSE_SNAPSHOT_OWNED=0
  fi
  ((failed == 0))
}

snapshot_env_file() {
  local before after snapshot
  [[ -z ${ENV_SNAPSHOT:-} ]] || {
    echo 'restore: refusing to replace an existing environment snapshot' >&2
    return 1
  }
  validate_env_source || return
  before=$(stat -c '%d:%i:%s:%Y:%Z' -- "$ENV_FILE") || return
  snapshot=$(mktemp "$BACKUP_DIR/.astranull-env.restore.XXXXXX")
  ENV_SNAPSHOT=$snapshot
  chmod 600 "$ENV_SNAPSHOT"
  cat -- "$ENV_FILE" > "$ENV_SNAPSHOT"
  after=$(stat -c '%d:%i:%s:%Y:%Z' -- "$ENV_FILE") || return
  [[ "$before" == "$after" && -f "$ENV_SNAPSHOT" && ! -L "$ENV_SNAPSHOT" \
    && "$(stat -c '%a' -- "$ENV_SNAPSHOT")" == 600 ]] || {
    echo "restore: $ENV_FILE changed while it was being snapshotted or the snapshot is unsafe" >&2
    return 1
  }
}

cleanup_env_snapshot_checked() {
  local failed=0
  [[ -n ${ENV_SNAPSHOT:-} ]] || return 0
  if ! rm -f -- "$ENV_SNAPSHOT"; then
    echo "restore: WARNING: could not delete private environment snapshot $ENV_SNAPSHOT" >&2
    failed=1
  fi
  if [[ -e "$ENV_SNAPSHOT" || -L "$ENV_SNAPSHOT" ]]; then
    echo "restore: CRITICAL: private environment snapshot still exists at $ENV_SNAPSHOT; immediate operator cleanup is required" >&2
    failed=1
  else
    ENV_SNAPSHOT=''
  fi
  ((failed == 0))
}

compose_timeout() {
  local duration=$1
  shift
  [[ -n ${ENV_SNAPSHOT:-} && -f "$ENV_SNAPSHOT" && ! -L "$ENV_SNAPSHOT" \
    && "$(stat -c '%a' -- "$ENV_SNAPSHOT")" == 600 ]] || {
    echo 'restore: refusing Compose call without the private mode-0600 environment snapshot' >&2
    return 1
  }
  [[ "$COMPOSE_SNAPSHOT_OWNED" == 1 && -f "$COMPOSE_SNAPSHOT_FILE" && ! -L "$COMPOSE_SNAPSHOT_FILE" && "$(private_file_mode "$COMPOSE_SNAPSHOT_FILE")" == 600 ]] || {
    echo 'restore: refusing Compose call without the immutable mode-0600 Compose snapshot' >&2
    return 1
  }
  timeout -k 30 "$duration" docker compose --project-directory "$ROOT/ops/aws" \
    -f "$COMPOSE_SNAPSHOT_FILE" --env-file "$ENV_SNAPSHOT" "$@"
}

export_compose_image_ids() {
  local control_plane_id=$1 core_worker_id=$2 connector_worker_id=$3 image_id
  for image_id in "$control_plane_id" "$core_worker_id" "$connector_worker_id"; do
    [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
      echo "restore: refusing to export invalid Compose image ID $image_id" >&2
      return 1
    }
  done
  export ASTRANULL_CONTROL_PLANE_IMAGE_ID="$control_plane_id"
  export ASTRANULL_CORE_WORKER_IMAGE_ID="$core_worker_id"
  export ASTRANULL_CONNECTOR_WORKER_IMAGE_ID="$connector_worker_id"
}

verify_named_container_absent() {
  local expected_name=$1 names name filter
  [[ "$expected_name" =~ ^astranull-(deploy|restore)-[a-z0-9-]+-[0-9]+$ ]] || {
    echo "restore: refusing unsafe exact container name $expected_name" >&2
    return 1
  }
  filter="name=^${expected_name}\$"
  names=$(timeout -k 5 30 docker container ls -a --filter "$filter" --format '{{.Names}}') || {
    echo "restore: could not enumerate containers while checking exact name $expected_name" >&2
    return 1
  }
  while IFS= read -r name; do
    [[ -z "$name" || "$name" != "$expected_name" ]] || {
      echo "restore: container with exact name $expected_name still exists" >&2
      return 1
    }
  done <<< "$names"
}

remove_named_container_checked() {
  local name=$1 failed=0
  if ! timeout -k 5 30 docker rm -f -- "$name" >/dev/null 2>&1; then
    echo "restore: cleanup docker rm -f failed for exact container $name" >&2
    failed=1
  fi
  if ! verify_named_container_absent "$name"; then
    echo "restore: cleanup could not verify exact container $name absent" >&2
    failed=1
  fi
  ((failed == 0))
}

operation_container_names() {
  local names name filter expected_regex
  filter="name=^astranull-restore-[a-z0-9-]+-$$\$"
  expected_regex="^astranull-restore-[a-z0-9-]+-$$\$"
  names=$(timeout -k 5 30 docker container ls -a --filter "$filter" --format '{{.Names}}') || {
    echo 'restore: could not enumerate this restore operation container namespace' >&2
    return 1
  }
  while IFS= read -r name; do
    [[ -n "$name" && "$name" =~ $expected_regex ]] || continue
    printf '%s\n' "$name"
  done <<< "$names"
}

cleanup_active_operation_containers_checked() {
  local names survivors name failed=0
  if names=$(operation_container_names); then
    while IFS= read -r name; do
      [[ -n "$name" ]] || continue
      if ! remove_named_container_checked "$name"; then failed=1; fi
    done <<< "$names"
  else
    failed=1
  fi
  if survivors=$(operation_container_names); then
    if [[ -n "$survivors" ]]; then
      while IFS= read -r name; do
        [[ -n "$name" ]] || continue
        echo "restore: CRITICAL: operation container still exists after parent cleanup: $name" >&2
      done <<< "$survivors"
      failed=1
    fi
  else
    failed=1
  fi
  ((failed == 0))
}

all_release_operation_container_names() {
  local names name count=0
  names=$(timeout -k 5 30 docker container ls -a --format '{{.Names}}') || {
    echo 'restore: could not enumerate stale release operation containers' >&2
    return 1
  }
  while IFS= read -r name; do
    [[ "$name" =~ ^astranull-(deploy|restore)-[a-z0-9-]+-[0-9]+$ ]] || continue
    count=$((count + 1))
    ((count <= 256)) || {
      echo 'restore: more than 256 stale release operation containers require operator cleanup' >&2
      return 1
    }
    printf '%s\n' "$name"
  done <<< "$names"
}

cleanup_stale_operation_containers_checked() {
  local names survivors name failed=0
  if names=$(all_release_operation_container_names); then
    while IFS= read -r name; do
      [[ -n "$name" ]] || continue
      remove_named_container_checked "$name" || failed=1
    done <<< "$names"
  else
    failed=1
  fi
  survivors=$(all_release_operation_container_names) || failed=1
  if [[ -n ${survivors:-} ]]; then
    echo "restore: CRITICAL: stale release operation containers remain: ${survivors//$'\n'/,}" >&2
    failed=1
  fi
  ((failed == 0))
}

compose_ops_run() {
  local duration=$1 purpose=$2 name run_rc=0 cleanup_rc=0
  shift 2
  [[ "$purpose" =~ ^[a-z0-9-]+$ ]] || {
    echo 'restore: invalid Compose ops run purpose' >&2
    return 1
  }
  name="astranull-restore-${purpose}-$$"
  verify_named_container_absent "$name" || {
    echo "restore: refusing to replace pre-existing exact ops container $name" >&2
    return 1
  }
  if compose_timeout "$duration" --profile ops run --name "$name" --no-deps "$@"; then
    run_rc=0
  else
    run_rc=$?
  fi
  if remove_named_container_checked "$name"; then
    cleanup_rc=0
  else
    cleanup_rc=$?
  fi
  if ((cleanup_rc != 0)); then
    echo "restore: Compose ops cleanup failed for $purpose ($name)" >&2
    return 125
  fi
  return "$run_rc"
}

run_control_plane_node() {
  local image_id=$1 name="astranull-restore-release-node-$$" run_rc=0 cleanup_rc=0
  shift
  [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo 'restore: release Node runner requires an immutable local image ID' >&2
    return 1
  }
  verify_named_container_absent "$name" || return
  if timeout -k 5 30 docker run --name "$name" --network none --read-only \
    --user 10001:10001 -i "$image_id" node "$@"; then
    run_rc=0
  else
    run_rc=$?
  fi
  if remove_named_container_checked "$name"; then
    cleanup_rc=0
  else
    cleanup_rc=$?
  fi
  if ((cleanup_rc != 0)); then
    echo "restore: isolated release Node runner cleanup failed for $name" >&2
    return 125
  fi
  return "$run_rc"
}

validate_compose() {
  local image_id=$1 result_variable=$2 validator_output=''
  local resolved_mode='' rc=0 cleanup_rc=0
  [[ "$result_variable" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]] || { echo 'restore: validate_compose requires a safe result variable name' >&2; return 1; }
  create_compose_render_file || return
  if compose_timeout 30 --profile ops config --format json > "$COMPOSE_RENDER_FILE"; then :; else rc=$?; echo 'restore: Compose JSON render failed' >&2; fi
  if ((rc == 0)) && [[ ! -s "$COMPOSE_RENDER_FILE" ]]; then echo 'restore: Compose JSON render was empty' >&2; rc=1; fi
  if ((rc == 0)); then
    if validator_output=$(run_control_plane_node "$image_id" scripts/validate-aws-compose-secrets.mjs --print-connector-mode < "$COMPOSE_RENDER_FILE"); then
      case "$validator_output" in
        enabled|disabled) resolved_mode=$validator_output ;;
        *) echo 'restore: current release-image Compose validator returned an unexpected result' >&2; rc=1 ;;
      esac
    else
      rc=$?
      echo 'restore: current release-image Compose validation failed' >&2
    fi
  fi
  if cleanup_compose_render_checked; then cleanup_rc=0; else cleanup_rc=125; fi
  ((cleanup_rc == 0)) || return "$cleanup_rc"
  ((rc == 0)) || return "$rc"
  printf -v "$result_variable" '%s' "$resolved_mode"
}

read_control_plane_image_tag() {
  local tag
  [[ -f "$CONTROL_PLANE_IMAGE_TAG_FILE" && ! -L "$CONTROL_PLANE_IMAGE_TAG_FILE" ]] || {
    echo "restore: missing or invalid persisted control-plane state $CONTROL_PLANE_IMAGE_TAG_FILE" >&2
    return 1
  }
  IFS= read -r tag < "$CONTROL_PLANE_IMAGE_TAG_FILE"
  [[ "$tag" =~ ^[0-9a-f]{40}$ ]] || {
    echo 'restore: persisted control-plane image tag is not an exact SHA' >&2
    return 1
  }
  printf '%s\n' "$tag"
}

read_control_plane_image_id() {
  local image_id line_count
  [[ -f "$CONTROL_PLANE_IMAGE_TAG_FILE" && ! -L "$CONTROL_PLANE_IMAGE_TAG_FILE" ]] || {
    echo "restore: missing or invalid persisted control-plane state $CONTROL_PLANE_IMAGE_TAG_FILE" >&2
    return 1
  }
  line_count=$(awk 'END { print NR }' "$CONTROL_PLANE_IMAGE_TAG_FILE")
  [[ "$line_count" == 2 ]] || {
    echo 'restore: persisted control-plane state must contain exactly a tag and image ID' >&2
    return 1
  }
  image_id=$(sed -n '2p' "$CONTROL_PLANE_IMAGE_TAG_FILE")
  [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo 'restore: persisted control-plane image ID is invalid' >&2
    return 1
  }
  printf '%s\n' "$image_id"
}

core_worker_image_state_exists() {
  [[ -e "$CORE_WORKER_IMAGE_STATE_FILE" || -L "$CORE_WORKER_IMAGE_STATE_FILE" ]]
}

read_core_worker_image_tag() {
  local tag
  [[ -f "$CORE_WORKER_IMAGE_STATE_FILE" && ! -L "$CORE_WORKER_IMAGE_STATE_FILE" ]] || {
    echo "restore: missing or invalid persisted core/ops worker state $CORE_WORKER_IMAGE_STATE_FILE" >&2
    return 1
  }
  [[ "$(awk 'END { print NR }' "$CORE_WORKER_IMAGE_STATE_FILE")" == 2 ]] || {
    echo 'restore: persisted core/ops worker state must contain exactly a tag and image ID' >&2
    return 1
  }
  IFS= read -r tag < "$CORE_WORKER_IMAGE_STATE_FILE"
  [[ "$tag" =~ ^[0-9a-f]{40}$ ]] || {
    echo 'restore: persisted core/ops worker tag is not an exact SHA' >&2
    return 1
  }
  printf '%s\n' "$tag"
}

read_core_worker_image_id() {
  local image_id
  [[ -f "$CORE_WORKER_IMAGE_STATE_FILE" && ! -L "$CORE_WORKER_IMAGE_STATE_FILE" ]] || return 1
  [[ "$(awk 'END { print NR }' "$CORE_WORKER_IMAGE_STATE_FILE")" == 2 ]] || return 1
  image_id=$(sed -n '2p' "$CORE_WORKER_IMAGE_STATE_FILE")
  [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo 'restore: persisted core/ops worker image ID is invalid' >&2
    return 1
  }
  printf '%s\n' "$image_id"
}

assert_image_identities_compatible() {
  local left_name=$1 left_tag=$2 left_image_id=$3
  local right_name=$4 right_tag=$5 right_image_id=$6
  if [[ "$left_tag" == "$right_tag" && "$left_image_id" != "$right_image_id" ]]; then
    echo "restore: $left_name and $right_name assign tag $left_tag to different image IDs" >&2
    return 1
  fi
}

connector_image_state_exists() {
  [[ -e "$CONNECTOR_IMAGE_STATE_FILE" || -L "$CONNECTOR_IMAGE_STATE_FILE" ]]
}

read_connector_image_tag() {
  local tag
  [[ -f "$CONNECTOR_IMAGE_STATE_FILE" && ! -L "$CONNECTOR_IMAGE_STATE_FILE" ]] || {
    echo "restore: invalid persisted connector state $CONNECTOR_IMAGE_STATE_FILE" >&2
    return 1
  }
  [[ "$(awk 'END { print NR }' "$CONNECTOR_IMAGE_STATE_FILE")" == 2 ]] || {
    echo 'restore: persisted connector state must contain exactly a tag and image ID' >&2
    return 1
  }
  IFS= read -r tag < "$CONNECTOR_IMAGE_STATE_FILE"
  [[ "$tag" =~ ^[0-9a-f]{40}$ ]] || {
    echo 'restore: persisted connector tag is not an exact SHA' >&2
    return 1
  }
  printf '%s\n' "$tag"
}

read_connector_image_id() {
  local image_id
  [[ -f "$CONNECTOR_IMAGE_STATE_FILE" && ! -L "$CONNECTOR_IMAGE_STATE_FILE" ]] || return 1
  [[ "$(awk 'END { print NR }' "$CONNECTOR_IMAGE_STATE_FILE")" == 2 ]] || return 1
  image_id=$(sed -n '2p' "$CONNECTOR_IMAGE_STATE_FILE")
  [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo 'restore: persisted connector image ID is invalid' >&2
    return 1
  }
  printf '%s\n' "$image_id"
}

release_validator_image_state_exists() {
  [[ -e "$RELEASE_VALIDATOR_IMAGE_STATE_FILE" || -L "$RELEASE_VALIDATOR_IMAGE_STATE_FILE" ]]
}

read_release_validator_image_tag() {
  local tag
  [[ -f "$RELEASE_VALIDATOR_IMAGE_STATE_FILE" && ! -L "$RELEASE_VALIDATOR_IMAGE_STATE_FILE" ]] || {
    echo "restore: missing or invalid release validator state $RELEASE_VALIDATOR_IMAGE_STATE_FILE" >&2
    return 1
  }
  [[ "$(awk 'END { print NR }' "$RELEASE_VALIDATOR_IMAGE_STATE_FILE")" == 2 ]] || {
    echo 'restore: release validator state must contain exactly a tag and image ID' >&2
    return 1
  }
  IFS= read -r tag < "$RELEASE_VALIDATOR_IMAGE_STATE_FILE" || return 1
  [[ "$tag" =~ ^[0-9a-f]{40}$ ]] || {
    echo 'restore: persisted release validator tag is not an exact SHA' >&2
    return 1
  }
  printf '%s\n' "$tag"
}

read_release_validator_image_id() {
  local image_id
  [[ -f "$RELEASE_VALIDATOR_IMAGE_STATE_FILE" && ! -L "$RELEASE_VALIDATOR_IMAGE_STATE_FILE" ]] || {
    echo "restore: missing or invalid release validator state $RELEASE_VALIDATOR_IMAGE_STATE_FILE" >&2
    return 1
  }
  [[ "$(awk 'END { print NR }' "$RELEASE_VALIDATOR_IMAGE_STATE_FILE")" == 2 ]] || {
    echo 'restore: release validator state must contain exactly a tag and image ID' >&2
    return 1
  }
  image_id=$(sed -n '2p' "$RELEASE_VALIDATOR_IMAGE_STATE_FILE") || return 1
  [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo 'restore: persisted release validator image ID is invalid' >&2
    return 1
  }
  printf '%s\n' "$image_id"
}

image_id_for_ref() {
  timeout -k 5 30 docker image inspect --format '{{.Id}}' "$1"
}

rebind_release_validator_image_tag() {
  local ref available_image_id rebound_image_id
  ref="astranull-release-validator:$release_validator_tag"
  available_image_id=$(image_id_for_ref "$release_validator_image_id") || {
    echo "restore: release validator image $release_validator_image_id is unavailable" >&2
    return 1
  }
  [[ "$available_image_id" == "$release_validator_image_id" ]] || {
    echo 'restore: release validator image resolved to an unexpected identity' >&2
    return 1
  }
  if ! timeout -k 5 30 docker image tag "$release_validator_image_id" "$ref"; then
    echo "restore: could not rebind $ref to its durable validator identity" >&2
    return 1
  fi
  rebound_image_id=$(image_id_for_ref "$ref") || return 1
  [[ "$rebound_image_id" == "$release_validator_image_id" ]] || {
    echo "restore: rebound release validator tag $release_validator_tag has the wrong image identity" >&2
    return 1
  }
}

load_release_validator_image_identity() {
  release_validator_image_state_exists || {
    echo "restore: current release validator state is required before destructive restore: $RELEASE_VALIDATOR_IMAGE_STATE_FILE" >&2
    return 1
  }
  release_validator_tag=$(read_release_validator_image_tag) || return
  release_validator_image_id=$(read_release_validator_image_id) || return
  rebind_release_validator_image_tag
}

rebind_control_plane_image_tag() {
  local ref available_image_id rebound_image_id
  ref="astranull-control-plane:$control_plane_tag"
  available_image_id=$(image_id_for_ref "$control_plane_image_id") || {
    echo "restore: expected control-plane image $control_plane_image_id is unavailable" >&2
    return 1
  }
  [[ "$available_image_id" == "$control_plane_image_id" ]] || {
    echo 'restore: expected control-plane image resolved to an unexpected identity' >&2
    return 1
  }
  timeout -k 5 30 docker image tag "$control_plane_image_id" "$ref" || {
    echo "restore: could not rebind $ref to its expected image identity" >&2
    return 1
  }
  rebound_image_id=$(image_id_for_ref "$ref") || return 1
  [[ "$rebound_image_id" == "$control_plane_image_id" ]] || {
    echo "restore: rebound control-plane tag $control_plane_tag has the wrong image identity" >&2
    return 1
  }
}

rebind_core_worker_image_tag() {
  local ref available_image_id rebound_image_id
  ref="astranull-control-plane:$core_worker_tag"
  available_image_id=$(image_id_for_ref "$core_worker_image_id") || {
    echo "restore: expected core/ops worker image $core_worker_image_id is unavailable" >&2
    return 1
  }
  [[ "$available_image_id" == "$core_worker_image_id" ]] || {
    echo 'restore: expected core/ops worker image resolved to an unexpected identity' >&2
    return 1
  }
  timeout -k 5 30 docker image tag "$core_worker_image_id" "$ref" || {
    echo "restore: could not rebind $ref to its expected core/ops worker identity" >&2
    return 1
  }
  rebound_image_id=$(image_id_for_ref "$ref") || return 1
  [[ "$rebound_image_id" == "$core_worker_image_id" ]] || {
    echo "restore: rebound core/ops worker tag $core_worker_tag has the wrong image identity" >&2
    return 1
  }
}

rebind_connector_image_tag() {
  local ref available_image_id rebound_image_id
  ref="astranull-control-plane:$connector_tag"
  available_image_id=$(image_id_for_ref "$connector_image_id") || {
    echo "restore: expected connector image $connector_image_id is unavailable" >&2
    return 1
  }
  [[ "$available_image_id" == "$connector_image_id" ]] || return 1
  timeout -k 5 30 docker image tag "$connector_image_id" "$ref" || {
    echo "restore: could not rebind $ref to its expected connector identity" >&2
    return 1
  }
  rebound_image_id=$(image_id_for_ref "$ref") || return 1
  [[ "$rebound_image_id" == "$connector_image_id" ]] || {
    echo "restore: rebound connector tag $connector_tag has the wrong image identity" >&2
    return 1
  }
}

connector_image_supports_split_mode() {
  run_control_plane_node "$connector_image_id" --input-type=module -e '
    import("./scripts/connector-poll-runner.mjs")
      .then(({ parseConnectorPollRunnerArgs }) => {
        const parsed = parseConnectorPollRunnerArgs(["node", "runner", "--queue-only"]);
        if (parsed?.queueOnly !== true) process.exit(1);
      })
      .catch(() => process.exit(1));
  '
}

load_restore_image_identity() {
  control_plane_tag=$(read_control_plane_image_tag)
  control_plane_image_id=$(read_control_plane_image_id)
  core_worker_image_state_exists || {
    echo "restore: required persisted core/ops worker state is missing: $CORE_WORKER_IMAGE_STATE_FILE" >&2
    return 1
  }
  core_worker_tag=$(read_core_worker_image_tag)
  core_worker_image_id=$(read_core_worker_image_id)
  assert_image_identities_compatible \
    control-plane "$control_plane_tag" "$control_plane_image_id" \
    core/ops-worker "$core_worker_tag" "$core_worker_image_id" || return

  # Resolve immutable IDs themselves and repair both mutable tags before Compose can
  # use either identity for a runtime service or restore/migration one-shot.
  rebind_control_plane_image_tag || return
  rebind_core_worker_image_tag || return

  connector_enabled=0
  connector_mode='disabled'
  connector_tag=''
  connector_image_id=''
  connector_candidate_image_id=$core_worker_image_id
  if [[ -f "$CONNECTOR_IMAGE_STATE_FILE" && ! -L "$CONNECTOR_IMAGE_STATE_FILE" \
    && "$(awk 'END { print NR }' "$CONNECTOR_IMAGE_STATE_FILE")" == 2 ]]; then
    local candidate
    candidate=$(sed -n '2p' "$CONNECTOR_IMAGE_STATE_FILE")
    if [[ "$candidate" =~ ^sha256:[0-9a-f]{64}$ ]]; then
      connector_candidate_image_id=$candidate
    fi
  fi
  export_compose_image_ids "$control_plane_image_id" "$core_worker_image_id" \
    "$connector_candidate_image_id" || return
  export ASTRANULL_IMAGE_TAG="$core_worker_tag"
  export ASTRANULL_CONTROL_PLANE_IMAGE_TAG="$control_plane_tag"
  export ASTRANULL_WORKER_IMAGE_TAG="$core_worker_tag"
  export ASTRANULL_CONNECTOR_WORKER_IMAGE_TAG="$core_worker_tag"
}

load_restore_connector_intent() {
  if canonical_release_bundle_exists; then
    release_bundle_load "$CURRENT_RELEASE_BUNDLE_FILE" || return
    if [[ ( "$connector_mode" == enabled && "$release_bundle_connector_enabled" != 1 ) \
      || ( "$connector_mode" == disabled && "$release_bundle_connector_enabled" != 0 ) ]]; then
      echo 'restore: rendered connector mode disagrees with canonical current release state' >&2
      return 1
    fi
  fi
  case "$connector_mode" in
    disabled)
      # Configuration is authoritative. A stale connector state file is deliberately
      # ignored and connector containers are removed by the verified shutdown path.
      connector_enabled=0
      connector_tag=''
      connector_image_id=''
      export ASTRANULL_CONNECTOR_WORKER_IMAGE_TAG="$core_worker_tag"
      export_compose_image_ids "$control_plane_image_id" "$core_worker_image_id" \
        "$core_worker_image_id" || return
      stop_remove_services connector-poll-scheduler connector-poll-runner || return
      ;;
    enabled)
      connector_image_state_exists || {
        echo "restore: connectors are enabled but persisted connector state is missing: $CONNECTOR_IMAGE_STATE_FILE" >&2
        return 1
      }
      connector_tag=$(read_connector_image_tag)
      connector_image_id=$(read_connector_image_id)
      assert_image_identities_compatible \
        control-plane "$control_plane_tag" "$control_plane_image_id" \
        connector "$connector_tag" "$connector_image_id" || return
      assert_image_identities_compatible \
        core/ops-worker "$core_worker_tag" "$core_worker_image_id" \
        connector "$connector_tag" "$connector_image_id" || return
      rebind_connector_image_tag || return
      connector_image_supports_split_mode || {
        echo 'restore: persisted connector image does not support split scheduler mode' >&2
        return 1
      }
      connector_enabled=1
      export ASTRANULL_CONNECTOR_WORKER_IMAGE_TAG="$connector_tag"
      export_compose_image_ids "$control_plane_image_id" "$core_worker_image_id" \
        "$connector_image_id" || return
      ;;
    *)
      echo 'restore: rendered connector release mode is invalid' >&2
      return 1
      ;;
  esac
}

verify_service_image_tag() {
  local service=$1 release_tag=$2 expected_image_id=$3
  local cid image_ref container_image_id
  cid=$(compose_timeout 30 ps -q "$service")
  [[ -n "$cid" ]] || {
    echo "restore: $service has no running container" >&2
    return 1
  }
  image_ref=$(timeout -k 5 30 docker inspect --format '{{.Config.Image}}' "$cid")
  container_image_id=$(timeout -k 5 30 docker inspect --format '{{.Image}}' "$cid")
  [[ "$image_ref" == "$expected_image_id" ]] || {
    echo "restore: $service Config.Image $image_ref does not equal exact release ID $expected_image_id (label $release_tag)" >&2
    return 1
  }
  [[ "$container_image_id" == "$expected_image_id" ]] || {
    echo "restore: $service .Image $container_image_id does not equal exact release ID $expected_image_id" >&2
    return 1
  }
}

verify_running_control_plane_state() {
  local cid
  cid=$(compose_timeout 30 ps -q control-plane)
  [[ -z "$cid" ]] || verify_service_image_tag control-plane "$control_plane_tag" "$control_plane_image_id"
}

verify_running_core_worker_state() {
  local service cid
  for service in probe-worker password-recovery-worker test-policy-runner; do
    cid=$(compose_timeout 30 ps -q "$service") || return 1
    [[ -z "$cid" ]] || verify_service_image_tag "$service" "$core_worker_tag" "$core_worker_image_id" || return
  done
}

verify_running_connector_state() {
  local service cid
  if (( ! connector_enabled )); then
    verify_services_absent connector-poll-scheduler connector-poll-runner
    return
  fi
  for service in connector-poll-scheduler connector-poll-runner; do
    cid=$(compose_timeout 30 ps -q "$service") || return 1
    [[ -z "$cid" ]] || verify_service_image_tag "$service" "$connector_tag" "$connector_image_id" || return
  done
}

verify_restored_image_identity() {
  local service
  verify_service_image_tag control-plane "$control_plane_tag" "$control_plane_image_id" || return
  for service in probe-worker password-recovery-worker test-policy-runner; do
    verify_service_image_tag "$service" "$core_worker_tag" "$core_worker_image_id" || return
  done
  if ((connector_enabled)); then
    for service in connector-poll-scheduler connector-poll-runner; do
      verify_service_image_tag "$service" "$connector_tag" "$connector_image_id" || return
    done
  fi
}

check_postgres() {
  compose_timeout 30 exec -T postgres pg_isready -U astranull -d astranull >/dev/null
}

check_control_plane() {
  compose_timeout 30 exec -T control-plane node -e \
    "Promise.all(['/health','/ready'].map(p=>fetch('http://127.0.0.1:8080'+p,{signal:AbortSignal.timeout(10000)}).then(r=>{if(!r.ok)throw Error(p+' '+r.status)}))).catch(e=>{console.error(e.message);process.exit(1)})" \
    || return
  curl --fail --silent --show-error --max-time 20 --retry 8 --retry-delay 3 --retry-connrefused --retry-all-errors https://astranull.site/health >/dev/null \
    || return
}

check_service_health() {
  local service=$1 cid health
  cid=$(compose_timeout 30 ps -q "$service")
  [[ -n "$cid" ]] || { echo "restore: $service has no container" >&2; return 1; }
  health=$(timeout -k 5 30 docker inspect --format '{{.State.Health.Status}}' "$cid")
  [[ "$health" == healthy ]] || { echo "restore: $service health is $health" >&2; return 1; }
}

check_core_workers() {
  local service
  for service in probe-worker password-recovery-worker test-policy-runner; do
    check_service_health "$service" || return
  done
}

check_connector_workers() {
  check_service_health connector-poll-scheduler || return
  check_service_health connector-poll-runner
}

verify_services_absent() {
  local service cid failed=0
  for service in "$@"; do
    if ! cid=$(compose_timeout 30 ps --all -q "$service"); then
      echo "restore: could not verify container absence for $service" >&2
      failed=1
    elif [[ -n "${cid//[[:space:]]/}" ]]; then
      echo "restore: $service still has container(s): ${cid//$'\n'/,}" >&2
      failed=1
    fi
  done
  ((failed == 0))
}

stop_remove_services() {
  local services=("$@")
  ((${#services[@]} > 0)) || return 0
  if ! compose_timeout 120 stop "${services[@]}" >/dev/null 2>&1; then
    echo "restore: bounded stop failed for ${services[*]}; attempting kill fallback" >&2
    if ! compose_timeout 120 kill "${services[@]}" >/dev/null 2>&1; then
      echo "restore: kill fallback reported failure for ${services[*]}; removal and verification will decide the outcome" >&2
    fi
  fi
  if ! compose_timeout 120 rm -f "${services[@]}" >/dev/null 2>&1; then
    echo "restore: container removal reported failure for ${services[*]}; verifying every service" >&2
  fi
  verify_services_absent "${services[@]}"
}

restore_plaintext_file_security() {
  local candidate=$1 phase=$2 mode owner links
  [[ -f "$candidate" && ! -L "$candidate" ]] || {
    echo "restore: plaintext archive is not a regular non-symlink file during $phase" >&2
    return 1
  }
  mode=$(private_file_mode "$candidate") || return
  owner=$(stat -c '%u' -- "$candidate" 2>/dev/null || stat -f '%u' "$candidate") || return
  links=$(stat -c '%h' -- "$candidate" 2>/dev/null || stat -f '%l' "$candidate") || return
  if [[ "$links" != 1 ]]; then
    echo "restore: CRITICAL: plaintext archive link count is $links during $phase; possible hard-link exposure requires incident escalation" >&2
    return 1
  fi
  [[ "$mode" == 600 && "$owner" == "$(id -u)" ]] || {
    echo "restore: plaintext archive must be mode 0600 and owned by the restore user during $phase" >&2
    return 1
  }
}

ensure_restore_backup_dir_secure() {
  local mode owner
  [[ -d "$BACKUP_DIR" && ! -L "$BACKUP_DIR" ]] || {
    echo "restore: backup directory is missing, non-directory, or symlinked: $BACKUP_DIR" >&2
    return 1
  }
  chmod 700 "$BACKUP_DIR" || return
  mode=$(private_file_mode "$BACKUP_DIR") || return
  owner=$(stat -c '%u' -- "$BACKUP_DIR" 2>/dev/null || stat -f '%u' "$BACKUP_DIR") || return
  [[ "$mode" == 700 && "$owner" == "$(id -u)" ]] || {
    echo 'restore: backup directory must be mode 0700 and owned by the restore user' >&2
    return 1
  }
}

acquire_deploy_lock() {
  local mode owner links
  ensure_restore_backup_dir_secure || return
  if [[ ! -e "$DEPLOY_LOCK_FILE" && ! -L "$DEPLOY_LOCK_FILE" ]]; then
    (umask 077; set -o noclobber; : > "$DEPLOY_LOCK_FILE") 2>/dev/null || true
  fi
  [[ -f "$DEPLOY_LOCK_FILE" && ! -L "$DEPLOY_LOCK_FILE" ]] || {
    echo "restore: refusing unsafe deployment lock path $DEPLOY_LOCK_FILE" >&2
    return 1
  }
  chmod 600 "$DEPLOY_LOCK_FILE" || return
  mode=$(private_file_mode "$DEPLOY_LOCK_FILE") || return
  owner=$(stat -c '%u' -- "$DEPLOY_LOCK_FILE" 2>/dev/null || stat -f '%u' "$DEPLOY_LOCK_FILE") || return
  links=$(stat -c '%h' -- "$DEPLOY_LOCK_FILE" 2>/dev/null || stat -f '%l' "$DEPLOY_LOCK_FILE") || return
  [[ "$mode" == 600 && "$owner" == "$(id -u)" && "$links" == 1 ]] || {
    echo 'restore: deployment lock must be mode 0600, singly linked, and owned by the restore user' >&2
    return 1
  }
  exec 9>>"$DEPLOY_LOCK_FILE"
  flock -n 9 || { echo 'restore: deployment or another restore is active' >&2; return 1; }
  python3 - "$DEPLOY_LOCK_FILE" <<'PY'
import os, stat, sys
path_stat = os.stat(sys.argv[1], follow_symlinks=False)
fd_stat = os.fstat(9)
if (path_stat.st_dev, path_stat.st_ino) != (fd_stat.st_dev, fd_stat.st_ino):
    raise SystemExit('restore: deployment lock pathname changed while locking')
if not stat.S_ISREG(fd_stat.st_mode) or stat.S_IMODE(fd_stat.st_mode) != 0o600 or fd_stat.st_nlink != 1:
    raise SystemExit('restore: locked deployment inode is unsafe')
if fd_stat.st_uid != os.getuid():
    raise SystemExit('restore: locked deployment inode has the wrong owner')
PY
}

is_release_workspace_scratch_name() {
  local name=${1##*/} LC_ALL=C
  [[ "$name" =~ ^\.astranull-env\.(deploy|restore)\.[A-Za-z0-9]{6}$ \
    || "$name" =~ ^\.astranull-build-iid\.[A-Za-z0-9]{6}$ \
    || "$name" =~ ^\.astranull-compose\.(previous|target)\.[A-Za-z0-9]{6}\.yml$ \
    || "$name" =~ ^\.astranull-compose-render\.(deploy|restore)\.[1-9][0-9]*$ \
    || "$name" =~ ^\.astranull-compose-source\.restore\.[1-9][0-9]*$ ]]
}

is_plaintext_scratch_name() {
  local name=${1##*/} LC_ALL=C
  [[ "$name" =~ ^\.astranull-plaintext\.(deploy|restore)\.[A-Za-z0-9]{6}$ ]]
}

cleanup_stale_release_workspace() {
  local candidate mode owner links failed=0 stale=()
  ensure_restore_backup_dir_secure || return
  shopt -s nullglob
  stale=("$BACKUP_DIR"/.astranull-env.deploy.* "$BACKUP_DIR"/.astranull-env.restore.* \
    "$BACKUP_DIR"/.astranull-compose-render.deploy.* "$BACKUP_DIR"/.astranull-compose-render.restore.* \
    "$BACKUP_DIR"/.astranull-compose-source.restore.* "$BACKUP_DIR"/.astranull-compose.previous.*.yml \
    "$BACKUP_DIR"/.astranull-compose.target.*.yml "$BACKUP_DIR"/.astranull-build-iid.*)
  shopt -u nullglob
  for candidate in ${stale[@]+"${stale[@]}"}; do
    is_release_workspace_scratch_name "$candidate" || continue
    if [[ -f "$candidate" && ! -L "$candidate" ]]; then
      mode=$(private_file_mode "$candidate") || mode=''
      owner=$(stat -c '%u' -- "$candidate" 2>/dev/null || stat -f '%u' "$candidate") || owner=''
      links=$(stat -c '%h' -- "$candidate" 2>/dev/null || stat -f '%l' "$candidate") || links=''
      if [[ "$mode" != 600 || "$owner" != "$(id -u)" || "$links" != 1 ]]; then
        echo "restore: CRITICAL: stale private release workspace is unsafe: $candidate" >&2
        failed=1
      fi
    else
      echo "restore: CRITICAL: stale private release workspace is non-regular or symlinked: $candidate" >&2
      failed=1
    fi
    if ! rm -f -- "$candidate"; then failed=1; fi
    if [[ -e "$candidate" || -L "$candidate" ]]; then
      echo "restore: stale private release workspace remains after cleanup: $candidate" >&2
      failed=1
    fi
  done
  ((failed == 0))
}

cleanup_stale_plaintext_archives() {
  local candidate failed=0 stale=()
  ensure_restore_backup_dir_secure || return
  shopt -s nullglob
  stale=("$BACKUP_DIR"/.astranull-plaintext.deploy.* "$BACKUP_DIR"/.astranull-plaintext.restore.*)
  shopt -u nullglob
  for candidate in ${stale[@]+"${stale[@]}"}; do
    is_plaintext_scratch_name "$candidate" || continue
    delete_plaintext_checked "$candidate" || failed=1
  done
  ((failed == 0))
}

allocate_restore_plaintext_path() {
  local candidate
  ensure_restore_backup_dir_secure || return
  candidate=$(umask 077; mktemp "$BACKUP_DIR/.astranull-plaintext.restore.XXXXXX") || {
    echo 'restore: could not reserve a random private plaintext archive path' >&2
    return 1
  }
  plain_host=$candidate
  restore_plaintext_file_security "$plain_host" allocation || return
  # The decryptor opens with O_EXCL (`wx`). Remove only our checked reservation;
  # the private mode-0700 directory and random name prevent pre-creation attacks.
  rm -f -- "$plain_host" || return
  [[ ! -e "$plain_host" && ! -L "$plain_host" ]] || {
    echo "restore: reserved plaintext archive path remains before exclusive extraction: $plain_host" >&2
    return 1
  }
}

load_expected_plaintext_sha256() {
  expected_plaintext_sha256=$(run_control_plane_node "$release_validator_image_id" -e '
    let input = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", chunk => { input += chunk; });
    process.stdin.on("end", () => {
      const digest = JSON.parse(input)?.plaintext_sha256;
      if (!/^[0-9a-f]{64}$/.test(digest ?? "")) process.exit(1);
      process.stdout.write(digest);
    });
  ' < "$MANIFEST") || return
  [[ "$expected_plaintext_sha256" =~ ^[0-9a-f]{64}$ ]] || {
    echo 'restore: manifest plaintext digest is missing or invalid' >&2
    return 1
  }
}

restore_plaintext_identity() {
  stat -c '%d:%i:%s:%Y:%Z' -- "$1" 2>/dev/null \
    || stat -f '%d:%i:%z:%m:%c' "$1"
}

restore_plaintext_sha256() {
  python3 - "$1" <<'PY'
import hashlib, sys
value = hashlib.sha256()
with open(sys.argv[1], 'rb') as source:
    for chunk in iter(lambda: source.read(1024 * 1024), b''):
        value.update(chunk)
print(value.hexdigest())
PY
}

validate_plaintext_archive() {
  local archive_host=$1 archive_name before after digest
  archive_name=${archive_host##*/}
  restore_plaintext_file_security "$archive_host" 'before structural parse' || return
  [[ -s "$archive_host" ]] || { echo 'restore: extracted plaintext archive is empty' >&2; return 1; }
  [[ "$expected_plaintext_sha256" =~ ^[0-9a-f]{64}$ ]] || {
    echo 'restore: authenticated plaintext digest is unavailable' >&2
    return 1
  }
  before=$(restore_plaintext_identity "$archive_host") || return
  digest=$(restore_plaintext_sha256 "$archive_host") || return
  after=$(restore_plaintext_identity "$archive_host") || return
  [[ "$before" == "$after" && "$digest" == "$expected_plaintext_sha256" ]] || {
    echo 'restore: plaintext archive identity changed or digest no longer matches its authenticated manifest' >&2
    return 1
  }
  compose_ops_run 60 pg-restore-list \
    -u "$(id -u):$(id -g)" -v "$BACKUP_DIR:/backup:ro" backup-dump \
    sh -eu -c 'exec pg_restore --list "$1" >/dev/null' sh "/backup/$archive_name" || return
  restore_plaintext_file_security "$archive_host" 'after structural parse' || return
  [[ "$(restore_plaintext_identity "$archive_host")" == "$after" ]] || {
    echo 'restore: plaintext archive identity changed during structural parse' >&2
    return 1
  }
}

delete_plaintext_checked() {
  local candidate=${1:-} failed=0
  [[ -n "$candidate" ]] || return 0
  if [[ -e "$candidate" || -L "$candidate" ]]; then
    if ! restore_plaintext_file_security "$candidate" 'before checked deletion'; then failed=1; fi
    if ! rm -f -- "$candidate"; then
      echo "restore: WARNING: plaintext deletion command failed for $candidate" >&2
      failed=1
    fi
  fi
  if [[ -e "$candidate" || -L "$candidate" ]]; then
    echo "restore: CRITICAL: plaintext backup still exists at $candidate; immediate operator escalation is required" >&2
    failed=1
  fi
  ((failed == 0))
}

start_core_stack() {
  stop_remove_services caddy control-plane probe-worker password-recovery-worker \
    test-policy-runner connector-poll-scheduler connector-poll-runner || return
  compose_timeout 300 up -d --wait --wait-timeout 240 \
    postgres control-plane probe-worker password-recovery-worker test-policy-runner caddy
}

start_connector_workers() {
  compose_timeout 300 up -d --no-deps --wait --wait-timeout 240 \
    connector-poll-scheduler connector-poll-runner
}

migrate_restore_legacy_bundle_if_needed() {
  canonical_release_bundle_exists && return 0
  if ((connector_enabled)); then
    write_pending_release_bundle \
      "$control_plane_tag" "$control_plane_image_id" \
      "$core_worker_tag" "$core_worker_image_id" \
      "$release_validator_tag" "$release_validator_image_id" \
      1 "$connector_tag" "$connector_image_id" || return
  else
    write_pending_release_bundle \
      "$control_plane_tag" "$control_plane_image_id" \
      "$core_worker_tag" "$core_worker_image_id" \
      "$release_validator_tag" "$release_validator_image_id" \
      0 '' '' || return
  fi
  release_runtime_matches_bundle_file "$PENDING_RELEASE_BUNDLE_FILE" || {
    echo 'restore: legacy runtime does not match its proposed canonical release bundle' >&2
    return 1
  }
  release_runtime_health_for_bundle_file "$PENDING_RELEASE_BUNDLE_FILE" || return
  promote_pending_release_bundle
}

cleanup() {
  local rc=$? plaintext_cleanup_failed=0 cleanup_failed=0
  trap - EXIT ERR
  trap '' HUP INT TERM
  set +e
  if ! cleanup_active_operation_containers_checked; then
    cleanup_failed=1
    rc=125
    echo 'restore: CRITICAL: parent cleanup could not remove and verify every exact operation container; immediate operator intervention is required' >&2
  fi
  if ! cleanup_compose_render_checked; then
    cleanup_failed=1
    rc=125
    echo 'restore: CRITICAL: parent cleanup could not remove the private Compose render; immediate operator intervention is required' >&2
  fi
  if [[ -n ${plain_host:-} ]]; then
    if delete_plaintext_checked "$plain_host"; then
      plain_host=''
    else
      plaintext_cleanup_failed=1
      rc=1
      echo 'restore: CRITICAL: EXIT cleanup could not prove plaintext absence; incident escalation is required' >&2
    fi
  fi
  if (( ! succeeded && outage_started )); then
    if stop_remove_services caddy probe-worker password-recovery-worker test-policy-runner \
      connector-poll-scheduler connector-poll-runner control-plane; then
      echo 'restore: failed; runtime containers were stopped, removed, and verified absent for operator investigation' >&2
    else
      echo 'restore: failed and runtime container shutdown could not be verified; immediate operator intervention is required' >&2
      ((rc != 0)) || rc=1
    fi
  elif (( ! succeeded )); then
    echo 'restore: preflight failed before outage; runtime services were not intentionally stopped' >&2
  fi
  if ! cleanup_compose_snapshot_checked; then
    cleanup_failed=1
    rc=125
    echo 'restore: CRITICAL: immutable Compose snapshot cleanup failed; immediate operator cleanup is required' >&2
  fi
  if ! cleanup_env_snapshot_checked; then
    cleanup_failed=1
    rc=125
    echo 'restore: CRITICAL: environment snapshot cleanup failed; immediate operator cleanup is required' >&2
  fi
  if (( ! succeeded )) && ! verify_release_state_journal_safe; then
    cleanup_failed=1
    rc=125
    echo 'restore: CRITICAL: current/pending release journal is unsafe during cleanup' >&2
  fi
  if ((succeeded)) && ! verify_release_state_settled; then
    cleanup_failed=1
    rc=125
    echo 'restore: CRITICAL: canonical release state did not settle before lock release' >&2
  fi
  ((plaintext_cleanup_failed == 0)) || rc=1
  if ((cleanup_failed)); then rc=125; fi
  exit "$rc"
}

main() {
  [[ ${1:-} == --yes ]] || { echo 'restore: destructive restore requires --yes' >&2; exit 2; }
  MANIFEST=${2:-}
  BACKUP=${3:-}
  [[ -f "$MANIFEST" && -f "$BACKUP" ]] || { echo 'restore: manifest and backup files are required' >&2; exit 2; }
  MANIFEST=$(realpath "$MANIFEST")
  BACKUP=$(realpath "$BACKUP")
  [[ "$MANIFEST" == "$BACKUP_DIR"/*.dump.enc.manifest.json ]] || { echo 'restore: manifest must be an encrypted backup manifest in the backup directory' >&2; exit 2; }
  [[ "$BACKUP" == "$BACKUP_DIR"/*.dump.enc ]] || { echo 'restore: backup must be an encrypted dump in the backup directory' >&2; exit 2; }
  [[ "$MANIFEST" == "$BACKUP.manifest.json" ]] || { echo 'restore: manifest does not belong to backup' >&2; exit 2; }

  acquire_deploy_lock
  cd "$ROOT"
  validate_env_source
  [[ -f "$COMPOSE_FILE" && ! -L "$COMPOSE_FILE" ]] || {
    echo "restore: checked-out Compose file is missing or unsafe: $COMPOSE_FILE" >&2
    exit 1
  }
  [[ -z $(git status --porcelain --untracked-files=all) ]] || {
    echo 'restore: repository has tracked or untracked changes; current orchestration SHA is not exact' >&2
    exit 1
  }

  succeeded=0
  outage_started=0
  trap cleanup EXIT
  trap 'exit 130' HUP INT TERM
  cleanup_stale_operation_containers_checked
  cleanup_stale_release_workspace
  cleanup_stale_plaintext_archives
  snapshot_env_file
  snapshot_compose_file
  if pending_release_bundle_exists; then
    release_bundle_load "$PENDING_RELEASE_BUNDLE_FILE"
    if [[ "$release_bundle_connector_enabled" == 1 ]]; then
      export_compose_image_ids "$release_bundle_control_image_id" \
        "$release_bundle_core_image_id" "$release_bundle_connector_image_id"
    else
      export_compose_image_ids "$release_bundle_control_image_id" \
        "$release_bundle_core_image_id" "$release_bundle_core_image_id"
    fi
  elif canonical_release_bundle_exists; then
    release_bundle_load "$CURRENT_RELEASE_BUNDLE_FILE"
    if [[ "$release_bundle_connector_enabled" == 1 ]]; then
      export_compose_image_ids "$release_bundle_control_image_id" \
        "$release_bundle_core_image_id" "$release_bundle_connector_image_id"
    else
      export_compose_image_ids "$release_bundle_control_image_id" \
        "$release_bundle_core_image_id" "$release_bundle_core_image_id"
    fi
  fi
  reconcile_pending_release_bundle
  load_restore_image_identity
  load_release_validator_image_identity
  assert_image_identities_compatible \
    release-validator "$release_validator_tag" "$release_validator_image_id" \
    control-plane "$control_plane_tag" "$control_plane_image_id"
  assert_image_identities_compatible \
    release-validator "$release_validator_tag" "$release_validator_image_id" \
    core/ops-worker "$core_worker_tag" "$core_worker_image_id"

  validate_compose "$release_validator_image_id" connector_mode
  load_restore_connector_intent
  # Any running release must agree with all durable identities before archive work.
  verify_running_control_plane_state
  verify_running_core_worker_state
  verify_running_connector_state
  migrate_restore_legacy_bundle_if_needed

  # Authenticate, extract mode-0600 plaintext, and ask PostgreSQL itself to parse the
  # complete custom archive before any runtime is stopped. EXIT always removes it.
  load_expected_plaintext_sha256
  allocate_restore_plaintext_path
  compose_ops_run 180 backup-decrypt \
    -u "$(id -u):$(id -g)" -v "$BACKUP_DIR:/backup" backup \
    node scripts/postgres-restore-drill.mjs \
    --manifest "/backup/${MANIFEST##*/}" --backup "/backup/${BACKUP##*/}" \
    --extract "/backup/${plain_host##*/}" --yes --out /tmp/restore-verification.json
  validate_plaintext_archive "$plain_host"

  outage_started=1
  stop_remove_services caddy probe-worker password-recovery-worker test-policy-runner \
    connector-poll-scheduler connector-poll-runner control-plane
  validate_plaintext_archive "$plain_host"

  # pg_restore --clean only removes objects named by the archive, so objects introduced
  # after an older backup survive and produce a hybrid schema. Both destructive commands
  # run in PID-scoped named one-shots; no destructive process is exec'd into postgres.
  compose_ops_run 90 restore-db-recreate -T restore-db \
    sh -eu -c 'exec timeout -k 10 75 psql --no-psqlrc --dbname="$ASTRANULL_MAINTENANCE_DATABASE_URL" -v ON_ERROR_STOP=1' <<'SQL'
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE datname = 'astranull' AND pid <> pg_backend_pid();
DROP DATABASE IF EXISTS astranull WITH (FORCE);
CREATE DATABASE astranull WITH OWNER astranull TEMPLATE template0;
SQL

  validate_plaintext_archive "$plain_host"
  compose_ops_run 600 restore-db-archive \
    -T -u "$(id -u):$(id -g)" -v "$BACKUP_DIR:/backup:ro" restore-db \
    sh -eu -c 'exec timeout -k 30 540 pg_restore \
      --dbname="$ASTRANULL_RESTORE_DATABASE_URL" \
      --single-transaction --exit-on-error --no-owner --no-acl "$1"' \
    sh "/backup/${plain_host##*/}"
  delete_plaintext_checked "$plain_host"
  plain_host=''
  compose_ops_run 180 migrate migrate
  start_core_stack
  check_control_plane
  check_core_workers
  if ((connector_enabled)); then
    start_connector_workers
    check_connector_workers
  else
    verify_services_absent connector-poll-scheduler connector-poll-runner
  fi
  verify_restored_image_identity
  [[ "$(read_control_plane_image_tag)" == "$control_plane_tag" \
    && "$(read_control_plane_image_id)" == "$control_plane_image_id" ]] || {
    echo 'restore: persisted control-plane state changed during restore' >&2
    return 1
  }
  [[ "$(read_core_worker_image_tag)" == "$core_worker_tag" \
    && "$(read_core_worker_image_id)" == "$core_worker_image_id" ]] || {
    echo 'restore: persisted core/ops worker state changed during restore' >&2
    return 1
  }
  [[ "$(read_release_validator_image_tag)" == "$release_validator_tag" \
    && "$(read_release_validator_image_id)" == "$release_validator_image_id" ]] || {
    echo 'restore: persisted release validator state changed during restore' >&2
    return 1
  }
  if ((connector_enabled)); then
    [[ "$(read_connector_image_tag)" == "$connector_tag" \
      && "$(read_connector_image_id)" == "$connector_image_id" ]] || {
      echo 'restore: persisted connector state changed during restore' >&2
      return 1
    }
  fi

  succeeded=1
  echo "restore: ok backup=$BACKUP control_plane=astranull-control-plane:$control_plane_tag@$control_plane_image_id core_ops_workers=astranull-control-plane:$core_worker_tag@$core_worker_image_id release_validator=astranull-release-validator:$release_validator_tag@$release_validator_image_id connector_enabled=$connector_enabled connector_image=${connector_image_id:-disabled}"
}

load_release_state_library

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
