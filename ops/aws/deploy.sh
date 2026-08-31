#!/usr/bin/env bash
set -euo pipefail

ROOT=/opt/astranull
COMPOSE_REPO_PATH=ops/aws/docker-compose.yml
ENV_FILE="$ROOT/ops/aws/.env"
BACKUP_DIR=/opt/astranull-backups
if [[ ${BASH_SOURCE[0]} != "$0" && -n ${ASTRANULL_TEST_BACKUP_DIR:-} ]]; then
  BACKUP_DIR=$ASTRANULL_TEST_BACKUP_DIR
fi
DEPLOY_LOCK_FILE="$BACKUP_DIR/deploy.lock"
ENV_SNAPSHOT=''
COMPOSE_RENDER_FILE="$BACKUP_DIR/.astranull-compose-render.deploy.$$"
COMPOSE_RENDER_OWNED=0
DEPLOY_STATE_DIR="$BACKUP_DIR/deploy-state"
CONTROL_PLANE_IMAGE_TAG_FILE="$DEPLOY_STATE_DIR/control-plane-image-tag"
CORE_WORKER_IMAGE_STATE_FILE="$DEPLOY_STATE_DIR/core-worker-image-state"
CONNECTOR_IMAGE_STATE_FILE="$DEPLOY_STATE_DIR/connector-image-state"
RELEASE_VALIDATOR_IMAGE_STATE_FILE="$DEPLOY_STATE_DIR/release-validator-image-state"
STATE_LOG_PREFIX=deploy

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
    echo "deploy: missing or unsafe release-state helper $candidate" >&2
    return 1
  }
  # shellcheck source=ops/aws/release-state.sh
  source "$candidate"
}

MODE=deploy
SHA=''
previous=''
previous_control_plane_tag=''
previous_control_plane_image_id=''
previous_core_worker_tag=''
previous_core_worker_image_id=''
previous_connector_tag=''
previous_connector_image_id=''
previous_connector_enabled=0
previous_release_validator_tag=''
previous_release_validator_image_id=''
had_current_release=0
previous_compose=''
target_compose=''
ACTIVE_COMPOSE_FILE=''
plain_host=''
backup=''
activated=0
migration_started=0
finished=0
built_control_plane_image_id=''
requested_image_id=''
fresh_bootstrap=0
bridged_control_plane_tag=''
bridged_control_plane_image_id=''
bridged_core_worker_tag=''
bridged_core_worker_image_id=''
validated_connector_mode=''
release_validator_tag=''
release_validator_image_id=''

private_file_mode() {
  stat -c '%a' -- "$1" 2>/dev/null || stat -f '%Lp' "$1"
}

cleanup_compose_render_checked() {
  local failed=0
  ((COMPOSE_RENDER_OWNED)) || return 0
  if [[ -e "$COMPOSE_RENDER_FILE" || -L "$COMPOSE_RENDER_FILE" ]]; then
    if ! rm -f -- "$COMPOSE_RENDER_FILE"; then echo "deploy: WARNING: could not delete private Compose render $COMPOSE_RENDER_FILE" >&2; failed=1; fi
  fi
  if [[ -e "$COMPOSE_RENDER_FILE" || -L "$COMPOSE_RENDER_FILE" ]]; then
    echo "deploy: CRITICAL: private Compose render still exists at $COMPOSE_RENDER_FILE; immediate operator cleanup is required" >&2
    failed=1
  else
    COMPOSE_RENDER_OWNED=0
  fi
  ((failed == 0))
}

create_compose_render_file() {
  ((COMPOSE_RENDER_OWNED == 0)) || { echo 'deploy: refusing to replace an active private Compose render' >&2; return 1; }
  [[ ! -e "$COMPOSE_RENDER_FILE" && ! -L "$COMPOSE_RENDER_FILE" ]] || { echo "deploy: refusing pre-existing Compose render path $COMPOSE_RENDER_FILE" >&2; return 1; }
  COMPOSE_RENDER_OWNED=1
  if ! (umask 077; set -o noclobber; : > "$COMPOSE_RENDER_FILE") 2>/dev/null; then
    COMPOSE_RENDER_OWNED=0
    echo "deploy: could not exclusively create private Compose render $COMPOSE_RENDER_FILE" >&2
    return 1
  fi
  if ! chmod 600 "$COMPOSE_RENDER_FILE"; then
    echo 'deploy: could not set private Compose render mode 0600' >&2
    cleanup_compose_render_checked || return 125
    return 1
  fi
  if [[ ! -f "$COMPOSE_RENDER_FILE" || -L "$COMPOSE_RENDER_FILE" \
    || "$(private_file_mode "$COMPOSE_RENDER_FILE")" != 600 ]]; then
    echo 'deploy: private Compose render is not a regular mode-0600 file' >&2
    cleanup_compose_render_checked || return 125
    return 1
  fi
}

cleanup_compose_snapshots() {
  local failed=0
  if ! cleanup_compose_render_checked; then failed=1; fi
  [[ -z ${previous_compose:-} ]] || rm -f -- "$previous_compose"
  [[ -z ${target_compose:-} ]] || rm -f -- "$target_compose"
  if [[ -n ${ENV_SNAPSHOT:-} ]]; then
    if ! rm -f -- "$ENV_SNAPSHOT"; then
      echo "deploy: WARNING: could not delete private environment snapshot $ENV_SNAPSHOT" >&2
      failed=1
    fi
    if [[ -e "$ENV_SNAPSHOT" || -L "$ENV_SNAPSHOT" ]]; then
      echo "deploy: CRITICAL: private environment snapshot still exists at $ENV_SNAPSHOT; immediate operator cleanup is required" >&2
      failed=1
    else
      ENV_SNAPSHOT=''
    fi
  fi
  ((failed == 0))
}

validate_env_source() {
  local env_mode env_owner env_links
  [[ -f "$ENV_FILE" && ! -L "$ENV_FILE" ]] || {
    echo "deploy: $ENV_FILE must be a regular non-symlink file" >&2
    return 1
  }
  env_mode=$(stat -c '%a' -- "$ENV_FILE") || return
  env_owner=$(stat -c '%u' -- "$ENV_FILE") || return
  env_links=$(stat -c '%h' -- "$ENV_FILE") || return
  [[ "$env_mode" =~ ^[46]00$ ]] || {
    echo "deploy: $ENV_FILE must have mode 400 or 600" >&2
    return 1
  }
  [[ "$env_owner" == 0 || "$env_owner" == "$(id -u)" ]] || {
    echo "deploy: $ENV_FILE must be owned by root or the deploy user" >&2
    return 1
  }
  [[ "$env_links" == 1 ]] || {
    echo "deploy: $ENV_FILE must not have additional hard links" >&2
    return 1
  }
}

snapshot_env_file() {
  local before after snapshot
  [[ -z ${ENV_SNAPSHOT:-} ]] || {
    echo 'deploy: refusing to replace an existing environment snapshot' >&2
    return 1
  }
  validate_env_source || return
  before=$(stat -c '%d:%i:%s:%Y:%Z' -- "$ENV_FILE") || return
  snapshot=$(mktemp "$BACKUP_DIR/.astranull-env.deploy.XXXXXX")
  ENV_SNAPSHOT=$snapshot
  chmod 600 "$ENV_SNAPSHOT"
  cat -- "$ENV_FILE" > "$ENV_SNAPSHOT"
  after=$(stat -c '%d:%i:%s:%Y:%Z' -- "$ENV_FILE") || return
  [[ "$before" == "$after" && -f "$ENV_SNAPSHOT" && ! -L "$ENV_SNAPSHOT" \
    && "$(stat -c '%a' -- "$ENV_SNAPSHOT")" == 600 ]] || {
    echo "deploy: $ENV_FILE changed while it was being snapshotted or the snapshot is unsafe" >&2
    return 1
  }
}

compose_timeout() {
  local duration=$1
  shift
  [[ -n ${ENV_SNAPSHOT:-} && -f "$ENV_SNAPSHOT" && ! -L "$ENV_SNAPSHOT" \
    && "$(stat -c '%a' -- "$ENV_SNAPSHOT")" == 600 ]] || {
    echo 'deploy: refusing Compose call without the private mode-0600 environment snapshot' >&2
    return 1
  }
  timeout -k 30 "$duration" docker compose --project-directory "$ROOT/ops/aws" \
    -f "$ACTIVE_COMPOSE_FILE" --env-file "$ENV_SNAPSHOT" "$@"
}

export_compose_image_ids() {
  local control_plane_id=$1 core_worker_id=$2 connector_worker_id=$3 image_id
  for image_id in "$control_plane_id" "$core_worker_id" "$connector_worker_id"; do
    [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
      echo "deploy: refusing to export invalid Compose image ID $image_id" >&2
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
    echo "deploy: refusing unsafe exact container name $expected_name" >&2
    return 1
  }
  filter="name=^${expected_name}\$"
  names=$(timeout -k 5 30 docker container ls -a --filter "$filter" --format '{{.Names}}') || {
    echo "deploy: could not enumerate containers while checking exact name $expected_name" >&2
    return 1
  }
  while IFS= read -r name; do
    [[ -z "$name" || "$name" != "$expected_name" ]] || {
      echo "deploy: container with exact name $expected_name still exists" >&2
      return 1
    }
  done <<< "$names"
}

remove_named_container_checked() {
  local name=$1 failed=0
  if ! timeout -k 5 30 docker rm -f -- "$name" >/dev/null 2>&1; then
    echo "deploy: cleanup docker rm -f failed for exact container $name" >&2
    failed=1
  fi
  if ! verify_named_container_absent "$name"; then
    echo "deploy: cleanup could not verify exact container $name absent" >&2
    failed=1
  fi
  ((failed == 0))
}

operation_container_names() {
  local names name filter expected_regex
  filter="name=^astranull-deploy-[a-z0-9-]+-$$\$"
  expected_regex="^astranull-deploy-[a-z0-9-]+-$$\$"
  names=$(timeout -k 5 30 docker container ls -a --filter "$filter" --format '{{.Names}}') || {
    echo 'deploy: could not enumerate this deployment operation container namespace' >&2
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
        echo "deploy: CRITICAL: operation container still exists after parent cleanup: $name" >&2
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
    echo 'deploy: could not enumerate stale release operation containers' >&2
    return 1
  }
  while IFS= read -r name; do
    [[ "$name" =~ ^astranull-(deploy|restore)-[a-z0-9-]+-[0-9]+$ ]] || continue
    count=$((count + 1))
    ((count <= 256)) || {
      echo 'deploy: more than 256 stale release operation containers require operator cleanup' >&2
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
    echo "deploy: CRITICAL: stale release operation containers remain: ${survivors//$'\n'/,}" >&2
    failed=1
  fi
  ((failed == 0))
}

compose_ops_run() {
  local duration=$1 purpose=$2 name run_rc=0 cleanup_rc=0
  shift 2
  [[ "$purpose" =~ ^[a-z0-9-]+$ ]] || {
    echo 'deploy: invalid Compose ops run purpose' >&2
    return 1
  }
  name="astranull-deploy-${purpose}-$$"
  verify_named_container_absent "$name" || {
    echo "deploy: refusing to replace pre-existing exact ops container $name" >&2
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
    echo "deploy: Compose ops cleanup failed for $purpose ($name)" >&2
    return 125
  fi
  return "$run_rc"
}

run_control_plane_node() {
  local image_id=$1 name="astranull-deploy-release-node-$$" run_rc=0 cleanup_rc=0
  shift
  [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo 'deploy: release Node runner requires an immutable local image ID' >&2
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
    echo "deploy: isolated release Node runner cleanup failed for $name" >&2
    return 125
  fi
  return "$run_rc"
}

validate_compose() {
  local image_id=$1 result_variable=$2 validator_output=''
  local resolved_mode='' rc=0 cleanup_rc=0
  [[ "$result_variable" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]] || { echo 'deploy: validate_compose requires a safe result variable name' >&2; return 1; }
  create_compose_render_file || return
  if compose_timeout 30 --profile ops config --format json > "$COMPOSE_RENDER_FILE"; then :; else rc=$?; echo 'deploy: Compose JSON render failed' >&2; fi
  if ((rc == 0)) && [[ ! -s "$COMPOSE_RENDER_FILE" ]]; then echo 'deploy: Compose JSON render was empty' >&2; rc=1; fi
  if ((rc == 0)); then
    if validator_output=$(run_control_plane_node "$image_id" scripts/validate-aws-compose-secrets.mjs --print-connector-mode < "$COMPOSE_RENDER_FILE"); then
      case "$validator_output" in
        enabled|disabled) resolved_mode=$validator_output ;;
        *) echo 'deploy: current release-image Compose validator returned an unexpected result' >&2; rc=1 ;;
      esac
    else
      rc=$?
      echo 'deploy: current release-image Compose validation failed' >&2
    fi
  fi
  if cleanup_compose_render_checked; then cleanup_rc=0; else cleanup_rc=125; fi
  ((cleanup_rc == 0)) || return "$cleanup_rc"
  ((rc == 0)) || return "$rc"
  printf -v "$result_variable" '%s' "$resolved_mode"
}

postgres_volume_name() {
  local image_id=$1
  compose_timeout 30 config --format json \
    | run_control_plane_node "$image_id" -e '
      let input = "";
      process.stdin.setEncoding("utf8");
      process.stdin.on("data", (chunk) => { input += chunk; });
      process.stdin.on("end", () => {
        const name = JSON.parse(input)?.volumes?.pgdata?.name;
        if (typeof name !== "string" || name.length === 0) process.exit(1);
        process.stdout.write(name);
      });
    '
}

docker_volume_exists() {
  local listed volume
  listed=$(timeout -k 5 30 docker volume ls --quiet --filter "name=^${1}$") || return 2
  while IFS= read -r volume; do
    [[ "$volume" != "$1" ]] || return 0
  done <<< "$listed"
  return 1
}

check_postgres() {
  compose_timeout 30 exec -T postgres pg_isready -U astranull -d astranull >/dev/null
}

ensure_postgres_ready_for_backup() {
  local image_id=$1 postgres_cid volume_name volume_status
  postgres_cid=$(compose_timeout 30 ps --all -q postgres)
  if [[ -z "$postgres_cid" ]]; then
    volume_name=$(postgres_volume_name "$image_id")
    if docker_volume_exists "$volume_name"; then
      if (( ! release_state_preactivation_pending )); then
        echo "deploy: postgres data volume $volume_name exists without a service container; refusing target-compose bootstrap before backup" >&2
        return 1
      fi
      echo 'deploy: resuming journaled first-boot Postgres from its existing volume' >&2
    else
      volume_status=$?
      if ((volume_status != 1)); then
        echo "deploy: could not verify whether postgres data volume $volume_name exists; refusing bootstrap" >&2
        return 1
      fi
    fi

    # No container and no data volume is the only bootstrap case. Existing hosts never
    # run target `up` before their pre-migration backup.
    echo 'deploy: fresh host detected; starting postgres before initial backup' >&2
    compose_timeout 180 up -d --no-deps --wait --wait-timeout 120 postgres
    postgres_cid=$(compose_timeout 30 ps --all -q postgres)
    [[ -n "$postgres_cid" ]] || {
      echo 'deploy: postgres bootstrap did not create a service container' >&2
      return 1
    }
  fi
  check_postgres
}

control_plane_state_exists() {
  [[ -e "$CONTROL_PLANE_IMAGE_TAG_FILE" || -L "$CONTROL_PLANE_IMAGE_TAG_FILE" ]]
}

read_control_plane_image_tag() {
  local tag
  [[ -f "$CONTROL_PLANE_IMAGE_TAG_FILE" && ! -L "$CONTROL_PLANE_IMAGE_TAG_FILE" ]] || {
    echo "deploy: missing or invalid control-plane state file $CONTROL_PLANE_IMAGE_TAG_FILE" >&2
    return 1
  }
  [[ "$(awk 'END { print NR }' "$CONTROL_PLANE_IMAGE_TAG_FILE")" == 2 ]] || {
    echo 'deploy: persisted control-plane state must contain exactly a tag and image ID' >&2
    return 1
  }
  IFS= read -r tag < "$CONTROL_PLANE_IMAGE_TAG_FILE"
  [[ "$tag" =~ ^[0-9a-f]{40}$ ]] || {
    echo 'deploy: persisted control-plane image tag is not an exact SHA' >&2
    return 1
  }
  printf '%s\n' "$tag"
}

read_control_plane_image_id() {
  local image_id
  [[ -f "$CONTROL_PLANE_IMAGE_TAG_FILE" && ! -L "$CONTROL_PLANE_IMAGE_TAG_FILE" ]] || {
    echo "deploy: missing or invalid control-plane state file $CONTROL_PLANE_IMAGE_TAG_FILE" >&2
    return 1
  }
  [[ "$(awk 'END { print NR }' "$CONTROL_PLANE_IMAGE_TAG_FILE")" == 2 ]] || {
    echo 'deploy: persisted control-plane state must contain exactly a tag and image ID' >&2
    return 1
  }
  image_id=$(sed -n '2p' "$CONTROL_PLANE_IMAGE_TAG_FILE")
  [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo 'deploy: persisted control-plane image ID is invalid' >&2
    return 1
  }
  printf '%s\n' "$image_id"
}

cleanup_image_state_temp_checked() {
  local temporary=${1:-} label=${2:-image-state} failed=0
  [[ -n "$temporary" ]] || return 0
  if [[ -e "$temporary" || -L "$temporary" ]]; then
    if ! rm -f -- "$temporary"; then
      echo "deploy: WARNING: could not remove temporary $label file $temporary" >&2
      failed=1
    fi
  fi
  if [[ -e "$temporary" || -L "$temporary" ]]; then
    echo "deploy: CRITICAL: temporary $label file still exists at $temporary" >&2
    failed=1
  fi
  ((failed == 0))
}

persist_image_state_atomic() {
  local label=$1 destination=$2 tag=$3 image_id=$4 temporary='' mode actual_tag actual_image_id line_count
  [[ "$tag" =~ ^[0-9a-f]{40}$ && "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo "deploy: refusing to persist an invalid $label image identity" >&2
    return 1
  }
  [[ ! -L "$DEPLOY_STATE_DIR" ]] || {
    echo "deploy: refusing symlinked deployment state directory $DEPLOY_STATE_DIR" >&2
    return 1
  }
  if ! mkdir -p -- "$DEPLOY_STATE_DIR"; then
    echo "deploy: could not create deployment state directory for $label" >&2
    return 1
  fi
  [[ -d "$DEPLOY_STATE_DIR" && ! -L "$DEPLOY_STATE_DIR" ]] || {
    echo "deploy: deployment state path is not a regular directory for $label" >&2
    return 1
  }
  if ! chmod 700 "$DEPLOY_STATE_DIR"; then
    echo "deploy: could not set deployment state directory mode for $label" >&2
    return 1
  fi
  mode=$(private_file_mode "$DEPLOY_STATE_DIR") || {
    echo "deploy: could not inspect deployment state directory mode for $label" >&2
    return 1
  }
  [[ "$mode" == 700 ]] || {
    echo "deploy: deployment state directory is not mode 0700 for $label" >&2
    return 1
  }
  if [[ -e "$destination" || -L "$destination" ]]; then
    [[ -f "$destination" && ! -L "$destination" ]] || {
      echo "deploy: refusing to replace invalid $label state file $destination" >&2
      return 1
    }
  fi
  if ! temporary=$(umask 077; mktemp "$DEPLOY_STATE_DIR/.${destination##*/}.XXXXXX"); then
    echo "deploy: could not create temporary $label state file" >&2
    if ! cleanup_image_state_temp_checked "$temporary" "$label"; then return 125; fi
    return 1
  fi
  [[ -f "$temporary" && ! -L "$temporary" ]] || {
    echo "deploy: temporary $label state path is unsafe" >&2
    if ! cleanup_image_state_temp_checked "$temporary" "$label"; then return 125; fi
    return 1
  }
  if ! printf '%s\n%s\n' "$tag" "$image_id" > "$temporary"; then
    echo "deploy: could not write temporary $label state" >&2
    if ! cleanup_image_state_temp_checked "$temporary" "$label"; then return 125; fi
    return 1
  fi
  if ! chmod 600 "$temporary"; then
    echo "deploy: could not set temporary $label state mode" >&2
    if ! cleanup_image_state_temp_checked "$temporary" "$label"; then return 125; fi
    return 1
  fi
  mode=$(private_file_mode "$temporary") || {
    echo "deploy: could not inspect temporary $label state mode" >&2
    if ! cleanup_image_state_temp_checked "$temporary" "$label"; then return 125; fi
    return 1
  }
  line_count=$(awk 'END { print NR }' "$temporary") || {
    echo "deploy: could not inspect temporary $label state contents" >&2
    if ! cleanup_image_state_temp_checked "$temporary" "$label"; then return 125; fi
    return 1
  }
  IFS= read -r actual_tag < "$temporary" || {
    echo "deploy: could not read temporary $label state tag" >&2
    if ! cleanup_image_state_temp_checked "$temporary" "$label"; then return 125; fi
    return 1
  }
  actual_image_id=$(sed -n '2p' "$temporary") || {
    echo "deploy: could not read temporary $label state image ID" >&2
    if ! cleanup_image_state_temp_checked "$temporary" "$label"; then return 125; fi
    return 1
  }
  [[ "$mode" == 600 && "$line_count" == 2 && "$actual_tag" == "$tag" \
    && "$actual_image_id" == "$image_id" ]] || {
    echo "deploy: temporary $label state failed exact content or mode verification" >&2
    if ! cleanup_image_state_temp_checked "$temporary" "$label"; then return 125; fi
    return 1
  }
  if ! mv -f -- "$temporary" "$destination"; then
    echo "deploy: could not atomically install $label state" >&2
    if ! cleanup_image_state_temp_checked "$temporary" "$label"; then return 125; fi
    return 1
  fi
  if [[ -e "$temporary" || -L "$temporary" ]]; then
    echo "deploy: atomic install for $label did not consume its temporary file" >&2
    if ! cleanup_image_state_temp_checked "$temporary" "$label"; then return 125; fi
    return 1
  fi
  temporary=''
  if [[ ! -f "$destination" || -L "$destination" ]]; then
    echo "deploy: installed $label state is missing or unsafe" >&2
    if ! cleanup_image_state_temp_checked "$temporary" "$label"; then return 125; fi
    return 1
  fi
  mode=$(private_file_mode "$destination") || {
    echo "deploy: could not inspect installed $label state mode" >&2
    return 1
  }
  line_count=$(awk 'END { print NR }' "$destination") || {
    echo "deploy: could not inspect installed $label state contents" >&2
    return 1
  }
  IFS= read -r actual_tag < "$destination" || return 1
  actual_image_id=$(sed -n '2p' "$destination") || return 1
  [[ "$mode" == 600 && "$line_count" == 2 && "$actual_tag" == "$tag" \
    && "$actual_image_id" == "$image_id" ]] || {
    echo "deploy: installed $label state failed exact content or mode verification" >&2
    return 1
  }
}

persist_control_plane_image_state() {
  local tag=$1 image_id=$2
  [[ "$tag" =~ ^[0-9a-f]{40}$ ]] || {
    echo 'deploy: refusing to persist a non-SHA control-plane image tag' >&2
    return 1
  }
  [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo 'deploy: refusing to persist an invalid control-plane image ID' >&2
    return 1
  }
  persist_image_state_atomic control-plane "$CONTROL_PLANE_IMAGE_TAG_FILE" "$tag" "$image_id"
}

core_worker_image_state_exists() {
  [[ -e "$CORE_WORKER_IMAGE_STATE_FILE" || -L "$CORE_WORKER_IMAGE_STATE_FILE" ]]
}

read_core_worker_image_tag() {
  local tag line_count
  [[ -f "$CORE_WORKER_IMAGE_STATE_FILE" && ! -L "$CORE_WORKER_IMAGE_STATE_FILE" ]] || {
    echo "deploy: missing or invalid core/ops worker state file $CORE_WORKER_IMAGE_STATE_FILE" >&2
    return 1
  }
  line_count=$(awk 'END { print NR }' "$CORE_WORKER_IMAGE_STATE_FILE")
  [[ "$line_count" == 2 ]] || {
    echo 'deploy: persisted core/ops worker state must contain exactly a tag and image ID' >&2
    return 1
  }
  IFS= read -r tag < "$CORE_WORKER_IMAGE_STATE_FILE"
  [[ "$tag" =~ ^[0-9a-f]{40}$ ]] || {
    echo 'deploy: persisted core/ops worker image tag is not an exact SHA' >&2
    return 1
  }
  printf '%s\n' "$tag"
}

read_core_worker_image_id() {
  local image_id
  [[ -f "$CORE_WORKER_IMAGE_STATE_FILE" && ! -L "$CORE_WORKER_IMAGE_STATE_FILE" ]] || {
    echo "deploy: missing or invalid core/ops worker state file $CORE_WORKER_IMAGE_STATE_FILE" >&2
    return 1
  }
  [[ "$(awk 'END { print NR }' "$CORE_WORKER_IMAGE_STATE_FILE")" == 2 ]] || {
    echo 'deploy: persisted core/ops worker state must contain exactly a tag and image ID' >&2
    return 1
  }
  image_id=$(sed -n '2p' "$CORE_WORKER_IMAGE_STATE_FILE")
  [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo 'deploy: persisted core/ops worker image ID is invalid' >&2
    return 1
  }
  printf '%s\n' "$image_id"
}

persist_core_worker_image_state() {
  local tag=$1 image_id=$2
  [[ "$tag" =~ ^[0-9a-f]{40}$ && "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo 'deploy: refusing to persist an invalid core/ops worker image identity' >&2
    return 1
  }
  persist_image_state_atomic core/ops-worker "$CORE_WORKER_IMAGE_STATE_FILE" "$tag" "$image_id"
}

assert_image_identities_compatible() {
  local left_name=$1 left_tag=$2 left_image_id=$3
  local right_name=$4 right_tag=$5 right_image_id=$6
  if [[ "$left_tag" == "$right_tag" && "$left_image_id" != "$right_image_id" ]]; then
    echo "deploy: $left_name and $right_name assign tag $left_tag to different image IDs" >&2
    return 1
  fi
}

connector_image_state_exists() {
  [[ -e "$CONNECTOR_IMAGE_STATE_FILE" || -L "$CONNECTOR_IMAGE_STATE_FILE" ]]
}

read_connector_image_tag() {
  local tag line_count
  [[ -f "$CONNECTOR_IMAGE_STATE_FILE" && ! -L "$CONNECTOR_IMAGE_STATE_FILE" ]] || {
    echo "deploy: missing or invalid connector state file $CONNECTOR_IMAGE_STATE_FILE" >&2
    return 1
  }
  line_count=$(awk 'END { print NR }' "$CONNECTOR_IMAGE_STATE_FILE")
  [[ "$line_count" == 2 ]] || {
    echo 'deploy: persisted connector state must contain exactly a tag and image ID' >&2
    return 1
  }
  IFS= read -r tag < "$CONNECTOR_IMAGE_STATE_FILE"
  [[ "$tag" =~ ^[0-9a-f]{40}$ ]] || {
    echo 'deploy: persisted connector image tag is not an exact SHA' >&2
    return 1
  }
  printf '%s\n' "$tag"
}

read_connector_image_id() {
  local image_id
  [[ -f "$CONNECTOR_IMAGE_STATE_FILE" && ! -L "$CONNECTOR_IMAGE_STATE_FILE" ]] || {
    echo "deploy: missing or invalid connector state file $CONNECTOR_IMAGE_STATE_FILE" >&2
    return 1
  }
  [[ "$(awk 'END { print NR }' "$CONNECTOR_IMAGE_STATE_FILE")" == 2 ]] || {
    echo 'deploy: persisted connector state must contain exactly a tag and image ID' >&2
    return 1
  }
  image_id=$(sed -n '2p' "$CONNECTOR_IMAGE_STATE_FILE")
  [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo 'deploy: persisted connector image ID is invalid' >&2
    return 1
  }
  printf '%s\n' "$image_id"
}

persist_connector_image_state() {
  local tag=$1 image_id=$2
  [[ "$tag" =~ ^[0-9a-f]{40}$ && "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo 'deploy: refusing to persist an invalid connector image identity' >&2
    return 1
  }
  persist_image_state_atomic connector "$CONNECTOR_IMAGE_STATE_FILE" "$tag" "$image_id"
}

clear_connector_image_state() {
  if [[ -e "$CONNECTOR_IMAGE_STATE_FILE" || -L "$CONNECTOR_IMAGE_STATE_FILE" ]]; then
    [[ -f "$CONNECTOR_IMAGE_STATE_FILE" && ! -L "$CONNECTOR_IMAGE_STATE_FILE" ]] || {
      echo "deploy: refusing to remove invalid connector state file $CONNECTOR_IMAGE_STATE_FILE" >&2
      return 1
    }
    if ! rm -f -- "$CONNECTOR_IMAGE_STATE_FILE"; then
      echo "deploy: could not remove connector state file $CONNECTOR_IMAGE_STATE_FILE" >&2
      return 1
    fi
  fi
  [[ ! -e "$CONNECTOR_IMAGE_STATE_FILE" && ! -L "$CONNECTOR_IMAGE_STATE_FILE" ]] || {
    echo "deploy: connector state file still exists after removal: $CONNECTOR_IMAGE_STATE_FILE" >&2
    return 1
  }
}

release_validator_image_state_exists() {
  [[ -e "$RELEASE_VALIDATOR_IMAGE_STATE_FILE" || -L "$RELEASE_VALIDATOR_IMAGE_STATE_FILE" ]]
}

read_release_validator_image_tag() {
  local tag
  [[ -f "$RELEASE_VALIDATOR_IMAGE_STATE_FILE" && ! -L "$RELEASE_VALIDATOR_IMAGE_STATE_FILE" ]] || {
    echo "deploy: missing or invalid release validator state $RELEASE_VALIDATOR_IMAGE_STATE_FILE" >&2
    return 1
  }
  [[ "$(awk 'END { print NR }' "$RELEASE_VALIDATOR_IMAGE_STATE_FILE")" == 2 ]] || {
    echo 'deploy: release validator state must contain exactly a tag and image ID' >&2
    return 1
  }
  IFS= read -r tag < "$RELEASE_VALIDATOR_IMAGE_STATE_FILE" || return 1
  [[ "$tag" =~ ^[0-9a-f]{40}$ ]] || {
    echo 'deploy: persisted release validator tag is not an exact SHA' >&2
    return 1
  }
  printf '%s\n' "$tag"
}

read_release_validator_image_id() {
  local image_id
  [[ -f "$RELEASE_VALIDATOR_IMAGE_STATE_FILE" && ! -L "$RELEASE_VALIDATOR_IMAGE_STATE_FILE" ]] || {
    echo "deploy: missing or invalid release validator state $RELEASE_VALIDATOR_IMAGE_STATE_FILE" >&2
    return 1
  }
  [[ "$(awk 'END { print NR }' "$RELEASE_VALIDATOR_IMAGE_STATE_FILE")" == 2 ]] || {
    echo 'deploy: release validator state must contain exactly a tag and image ID' >&2
    return 1
  }
  image_id=$(sed -n '2p' "$RELEASE_VALIDATOR_IMAGE_STATE_FILE") || return 1
  [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo 'deploy: persisted release validator image ID is invalid' >&2
    return 1
  }
  printf '%s\n' "$image_id"
}

persist_release_validator_image_state() {
  local tag=$1 image_id=$2
  [[ "$tag" =~ ^[0-9a-f]{40}$ && "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo 'deploy: refusing to persist an invalid release validator image identity' >&2
    return 1
  }
  persist_image_state_atomic release-validator "$RELEASE_VALIDATOR_IMAGE_STATE_FILE" "$tag" "$image_id"
}

image_id_for_ref() {
  timeout -k 5 30 docker image inspect --format '{{.Id}}' "$1"
}

rebind_release_validator_image_tag() {
  local tag=$1 expected_image_id=$2 ref available_image_id rebound_image_id
  ref="astranull-release-validator:$tag"
  [[ "$tag" =~ ^[0-9a-f]{40}$ && "$expected_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo 'deploy: refusing to rebind an invalid release validator identity' >&2
    return 1
  }
  available_image_id=$(image_id_for_ref "$expected_image_id") || {
    echo "deploy: release validator image $expected_image_id is unavailable" >&2
    return 1
  }
  [[ "$available_image_id" == "$expected_image_id" ]] || {
    echo 'deploy: release validator image resolved to an unexpected identity' >&2
    return 1
  }
  if ! timeout -k 5 30 docker image tag "$expected_image_id" "$ref"; then
    echo "deploy: could not rebind $ref to its durable validator identity" >&2
    return 1
  fi
  rebound_image_id=$(image_id_for_ref "$ref") || return 1
  [[ "$rebound_image_id" == "$expected_image_id" ]] || {
    echo "deploy: rebound release validator tag $tag has the wrong image identity" >&2
    return 1
  }
}

load_release_validator_image_identity() {
  release_validator_image_state_exists || {
    echo "deploy: explicit rollback requires current release validator state: $RELEASE_VALIDATOR_IMAGE_STATE_FILE" >&2
    return 1
  }
  release_validator_tag=$(read_release_validator_image_tag) || return
  release_validator_image_id=$(read_release_validator_image_id) || return
  rebind_release_validator_image_tag "$release_validator_tag" "$release_validator_image_id"
}

rebind_control_plane_image_tag() {
  local tag=$1 expected_image_id=$2 ref available_image_id rebound_image_id
  ref="astranull-control-plane:$tag"
  [[ "$tag" =~ ^[0-9a-f]{40}$ && "$expected_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo 'deploy: refusing to rebind an invalid control-plane image identity' >&2
    return 1
  }
  available_image_id=$(image_id_for_ref "$expected_image_id") || {
    echo "deploy: preserved control-plane image $expected_image_id is unavailable" >&2
    return 1
  }
  [[ "$available_image_id" == "$expected_image_id" ]] || {
    echo 'deploy: preserved control-plane image resolved to an unexpected identity' >&2
    return 1
  }
  timeout -k 5 30 docker image tag "$expected_image_id" "$ref" || {
    echo "deploy: could not rebind $ref to its preserved image identity" >&2
    return 1
  }
  rebound_image_id=$(image_id_for_ref "$ref") || return 1
  [[ "$rebound_image_id" == "$expected_image_id" ]] || {
    echo "deploy: rebound control-plane tag $tag does not resolve to its preserved image" >&2
    return 1
  }
}

rebind_core_worker_image_tag() {
  local tag=$1 expected_image_id=$2 ref available_image_id rebound_image_id
  ref="astranull-control-plane:$tag"
  [[ "$tag" =~ ^[0-9a-f]{40}$ && "$expected_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo 'deploy: refusing to rebind an invalid core/ops worker image identity' >&2
    return 1
  }
  available_image_id=$(image_id_for_ref "$expected_image_id") || {
    echo "deploy: preserved core/ops worker image $expected_image_id is unavailable" >&2
    return 1
  }
  [[ "$available_image_id" == "$expected_image_id" ]] || {
    echo 'deploy: preserved core/ops worker image resolved to an unexpected identity' >&2
    return 1
  }
  timeout -k 5 30 docker image tag "$expected_image_id" "$ref" || {
    echo "deploy: could not rebind $ref to its preserved core/ops worker identity" >&2
    return 1
  }
  rebound_image_id=$(image_id_for_ref "$ref") || return 1
  [[ "$rebound_image_id" == "$expected_image_id" ]] || {
    echo "deploy: rebound core/ops worker tag $tag does not resolve to its preserved image" >&2
    return 1
  }
}

inspect_running_control_core_fleet() {
  local service running_cid all_cids image_ref image_tag actual_image_id
  local service_count=0
  bridged_control_plane_tag=''
  bridged_control_plane_image_id=''
  bridged_core_worker_tag=''
  bridged_core_worker_image_id=''

  for service in control-plane probe-worker password-recovery-worker test-policy-runner; do
    running_cid=$(compose_timeout 30 ps -q "$service") || return 1
    all_cids=$(compose_timeout 30 ps --all -q "$service") || return 1
    if [[ -z "$running_cid" ]]; then
      [[ -z "$all_cids" ]] || {
        echo "deploy: $service has only stopped container state; exact persisted identity is required" >&2
        return 1
      }
      continue
    fi
    [[ "$running_cid" != *$'\n'* && "$all_cids" == "$running_cid" ]] || {
      echo "deploy: legacy $service does not have exactly one running container" >&2
      return 1
    }
    service_count=$((service_count + 1))
    image_ref=$(timeout -k 5 30 docker inspect --format '{{.Config.Image}}' "$running_cid") || return 1
    actual_image_id=$(timeout -k 5 30 docker inspect --format '{{.Image}}' "$running_cid") || return 1
    [[ "$image_ref" =~ ^astranull-control-plane:([0-9a-f]{40})$ ]] || {
      echo "deploy: legacy $service does not use an exact-SHA Config.Image" >&2
      return 1
    }
    image_tag=${BASH_REMATCH[1]}
    [[ "$actual_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
      echo "deploy: legacy $service has an invalid immutable image ID" >&2
      return 1
    }

    if [[ "$service" == control-plane ]]; then
      bridged_control_plane_tag=$image_tag
      bridged_control_plane_image_id=$actual_image_id
    elif [[ -z "$bridged_core_worker_tag" ]]; then
      bridged_core_worker_tag=$image_tag
      bridged_core_worker_image_id=$actual_image_id
    elif [[ "$image_tag" != "$bridged_core_worker_tag" \
      || "$actual_image_id" != "$bridged_core_worker_image_id" ]]; then
      echo 'deploy: legacy core workers do not share one exact Config.Image and immutable image ID' >&2
      return 1
    fi
  done

  ((service_count > 0)) || return 2
  [[ "$service_count" == 4 ]] || {
    echo 'deploy: legacy control/core release is incomplete; all four services must be running' >&2
    return 1
  }
  assert_image_identities_compatible \
    legacy-control-plane "$bridged_control_plane_tag" "$bridged_control_plane_image_id" \
    legacy-core/ops-worker "$bridged_core_worker_tag" "$bridged_core_worker_image_id"
}

verify_previous_runtime_containers() {
  local service cid image_ref actual_image_id expected_tag expected_image_id
  for service in control-plane probe-worker password-recovery-worker test-policy-runner; do
    cid=$(compose_timeout 30 ps --all -q "$service") || return 1
    [[ -z "$cid" ]] && continue
    [[ "$cid" != *$'\n'* ]] || {
      echo "deploy: $service resolved to multiple containers" >&2
      return 1
    }
    if [[ "$service" == control-plane ]]; then
      expected_tag=$previous_control_plane_tag
      expected_image_id=$previous_control_plane_image_id
    else
      expected_tag=$previous_core_worker_tag
      expected_image_id=$previous_core_worker_image_id
    fi
    image_ref=$(timeout -k 5 30 docker inspect --format '{{.Config.Image}}' "$cid") || return 1
    actual_image_id=$(timeout -k 5 30 docker inspect --format '{{.Image}}' "$cid") || return 1
    # Observation-only compatibility: a pre-ID Compose container may retain its exact
    # SHA tag in Config.Image after the first candidate persisted immutable state. The
    # running .Image must still equal that state. This never selects an execution image;
    # every current Compose service remains bound to raw IDs.
    [[ ( "$image_ref" == "$expected_image_id" \
        || "$image_ref" == "astranull-control-plane:$expected_tag" ) \
      && "$actual_image_id" == "$expected_image_id" ]] || {
      echo "deploy: persisted or observation-compatible legacy image state does not match $service" >&2
      return 1
    }
  done
}

assert_resumable_first_boot_pending() {
  local requested_sha=$1 requested_id=$2
  ((release_state_preactivation_pending)) || return 1
  release_bundle_load "$PENDING_RELEASE_BUNDLE_FILE" || return
  [[ "$release_bundle_control_tag" == "$requested_sha" \
    && "$release_bundle_control_image_id" == "$requested_id" \
    && "$release_bundle_core_tag" == "$requested_sha" \
    && "$release_bundle_core_image_id" == "$requested_id" \
    && "$release_bundle_validator_tag" == "$requested_sha" \
    && "$release_bundle_validator_image_id" == "$requested_id" ]] || {
    echo 'deploy: resumable first-boot journal does not match the exact requested release' >&2
    return 1
  }
  if [[ "$release_bundle_connector_enabled" == 1 ]]; then
    [[ "$release_bundle_connector_tag" == "$requested_sha" \
      && "$release_bundle_connector_image_id" == "$requested_id" ]] || {
      echo 'deploy: resumable first-boot connector identity does not match the requested release' >&2
      return 1
    }
  fi
  verify_services_absent caddy control-plane probe-worker password-recovery-worker \
    test-policy-runner connector-poll-scheduler connector-poll-runner
}

assert_genuinely_fresh_host() {
  local validator_image_id=$1 postgres_cid volume_name volume_status
  verify_services_absent caddy control-plane probe-worker password-recovery-worker \
    test-policy-runner connector-poll-scheduler connector-poll-runner || {
    echo 'deploy: host has runtime container state but no complete exact release state' >&2
    return 1
  }
  postgres_cid=$(compose_timeout 30 ps --all -q postgres) || return 1
  [[ -z "$postgres_cid" ]] || {
    echo 'deploy: stopped or initialized host has a Postgres container but no exact runtime state' >&2
    return 1
  }
  volume_name=$(postgres_volume_name "$validator_image_id") || return 1
  if docker_volume_exists "$volume_name"; then
    echo "deploy: stopped or initialized host has Postgres data volume $volume_name but no exact runtime state" >&2
    return 1
  else
    volume_status=$?
    ((volume_status == 1)) || {
      echo "deploy: could not verify whether Postgres data volume $volume_name exists" >&2
      return 1
    }
  fi
}

prepare_previous_release_images() {
  local requested_sha=$1 control_state=0 legacy_control_state=0 core_state=0 bridge_rc line_count legacy_tag
  local used_legacy_runtime_bridge=0
  if canonical_release_bundle_exists; then
    release_bundle_load "$CURRENT_RELEASE_BUNDLE_FILE" || return
    control_state=1
    core_state=1
  elif control_plane_state_exists; then
    [[ -f "$CONTROL_PLANE_IMAGE_TAG_FILE" && ! -L "$CONTROL_PLANE_IMAGE_TAG_FILE" ]] || {
      echo "deploy: invalid control-plane state file $CONTROL_PLANE_IMAGE_TAG_FILE" >&2
      return 1
    }
    line_count=$(awk 'END { print NR }' "$CONTROL_PLANE_IMAGE_TAG_FILE")
    if [[ "$line_count" == 2 ]]; then
      control_state=1
    elif [[ "$line_count" == 1 ]]; then
      IFS= read -r legacy_tag < "$CONTROL_PLANE_IMAGE_TAG_FILE"
      [[ "$legacy_tag" =~ ^[0-9a-f]{40}$ ]] || {
        echo 'deploy: legacy control-plane state does not contain an exact-SHA tag' >&2
        return 1
      }
      legacy_control_state=1
    else
      echo 'deploy: persisted control-plane state must contain a legacy tag or exact tag and image ID' >&2
      return 1
    fi
  fi
  if ! canonical_release_bundle_exists && core_worker_image_state_exists; then core_state=1; fi
  previous_control_plane_tag=''
  previous_control_plane_image_id=''
  previous_core_worker_tag=''
  previous_core_worker_image_id=''
  fresh_bootstrap=0

  if ((control_state && core_state)); then
    previous_control_plane_tag=$(read_control_plane_image_tag) || return
    previous_control_plane_image_id=$(read_control_plane_image_id) || return
    previous_core_worker_tag=$(read_core_worker_image_tag) || return
    previous_core_worker_image_id=$(read_core_worker_image_id) || return
  elif inspect_running_control_core_fleet; then
    used_legacy_runtime_bridge=1
    if ((control_state)); then
      previous_control_plane_tag=$(read_control_plane_image_tag) || return
      previous_control_plane_image_id=$(read_control_plane_image_id) || return
      [[ "$previous_control_plane_tag" == "$bridged_control_plane_tag" \
        && "$previous_control_plane_image_id" == "$bridged_control_plane_image_id" ]] || {
        echo 'deploy: persisted control-plane state disagrees with the complete running legacy fleet' >&2
        return 1
      }
    else
      previous_control_plane_tag=$bridged_control_plane_tag
      previous_control_plane_image_id=$bridged_control_plane_image_id
    fi
    if ((core_state)); then
      previous_core_worker_tag=$(read_core_worker_image_tag) || return
      previous_core_worker_image_id=$(read_core_worker_image_id) || return
      [[ "$previous_core_worker_tag" == "$bridged_core_worker_tag" \
        && "$previous_core_worker_image_id" == "$bridged_core_worker_image_id" ]] || {
        echo 'deploy: persisted core/ops state disagrees with the complete running legacy fleet' >&2
        return 1
      }
    else
      previous_core_worker_tag=$bridged_core_worker_tag
      previous_core_worker_image_id=$bridged_core_worker_image_id
    fi
  else
    bridge_rc=$?
    ((bridge_rc == 2)) || return "$bridge_rc"
    ((control_state == 0 && legacy_control_state == 0 && core_state == 0)) || {
      echo 'deploy: stopped non-fresh host lacks complete exact control/core state' >&2
      return 1
    }
    connector_image_state_exists && {
      echo 'deploy: connector state exists without exact control/core state; refusing first-boot initialization' >&2
      return 1
    }
    ensure_requested_control_plane_image "$requested_sha" || return
    if ((release_state_preactivation_pending)); then
      assert_resumable_first_boot_pending "$requested_sha" "$requested_image_id" || return
    else
      assert_genuinely_fresh_host "$requested_image_id" || return
    fi
    previous_control_plane_tag=$requested_sha
    previous_control_plane_image_id=$requested_image_id
    previous_core_worker_tag=$requested_sha
    previous_core_worker_image_id=$requested_image_id
    fresh_bootstrap=1
  fi

  assert_image_identities_compatible \
    control-plane "$previous_control_plane_tag" "$previous_control_plane_image_id" \
    core/ops-worker "$previous_core_worker_tag" "$previous_core_worker_image_id" || return
  rebind_control_plane_image_tag "$previous_control_plane_tag" "$previous_control_plane_image_id" || return
  rebind_core_worker_image_tag "$previous_core_worker_tag" "$previous_core_worker_image_id" || return
  # inspect_running_control_core_fleet already proved the one permitted tag-based legacy
  # bridge. Persisted and newly activated releases must pass the exact-ID verifier.
  ((used_legacy_runtime_bridge)) || verify_previous_runtime_containers || return
  # Compatibility files are projections only. Never create or advance them before a
  # canonical current bundle exists; this keeps first boot recoverable across SIGKILL.
  if canonical_release_bundle_exists; then
    regenerate_release_state_projections
  fi
}

rebind_connector_image_tag() {
  local tag=$1 expected_image_id=$2 ref available_image_id rebound_image_id
  ref="astranull-control-plane:$tag"
  [[ "$tag" =~ ^[0-9a-f]{40}$ && "$expected_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo 'deploy: refusing to rebind an invalid connector image identity' >&2
    return 1
  }
  available_image_id=$(image_id_for_ref "$expected_image_id") || {
    echo "deploy: preserved connector image $expected_image_id is unavailable" >&2
    return 1
  }
  [[ "$available_image_id" == "$expected_image_id" ]] || return 1
  timeout -k 5 30 docker image tag "$expected_image_id" "$ref" || {
    echo "deploy: could not rebind $ref to its preserved connector identity" >&2
    return 1
  }
  rebound_image_id=$(image_id_for_ref "$ref") || return 1
  [[ "$rebound_image_id" == "$expected_image_id" ]] || {
    echo "deploy: rebound connector tag $tag does not resolve to its preserved image" >&2
    return 1
  }
}

connector_image_supports_split_mode() {
  local image_id=$1
  run_control_plane_node "$image_id" --input-type=module -e '
    import("./scripts/connector-poll-runner.mjs")
      .then(({ parseConnectorPollRunnerArgs }) => {
        const parsed = parseConnectorPollRunnerArgs(["node", "runner", "--queue-only"]);
        if (parsed?.queueOnly !== true) process.exit(1);
      })
      .catch(() => process.exit(1));
  '
}

prepare_previous_connector_image() {
  local service cid image_ref actual_image_id container_count=0
  previous_connector_enabled=0
  previous_connector_tag=''
  previous_connector_image_id=''
  connector_image_state_exists || return 0

  previous_connector_tag=$(read_connector_image_tag)
  previous_connector_image_id=$(read_connector_image_id)
  assert_image_identities_compatible \
    control-plane "$previous_control_plane_tag" "$previous_control_plane_image_id" \
    connector "$previous_connector_tag" "$previous_connector_image_id" || return
  assert_image_identities_compatible \
    core/ops-worker "$previous_core_worker_tag" "$previous_core_worker_image_id" \
    connector "$previous_connector_tag" "$previous_connector_image_id" || return
  rebind_connector_image_tag "$previous_connector_tag" "$previous_connector_image_id" || return
  connector_image_supports_split_mode "$previous_connector_image_id" || {
    echo 'deploy: persisted connector image does not support split scheduler mode' >&2
    return 1
  }

  for service in connector-poll-scheduler connector-poll-runner; do
    cid=$(compose_timeout 30 ps --all -q "$service") || return 1
    [[ -z "$cid" ]] && continue
    container_count=$((container_count + 1))
    image_ref=$(timeout -k 5 30 docker inspect --format '{{.Config.Image}}' "$cid") || return 1
    actual_image_id=$(timeout -k 5 30 docker inspect --format '{{.Image}}' "$cid") || return 1
    [[ "$image_ref" == "$previous_connector_image_id" \
      && "$actual_image_id" == "$previous_connector_image_id" ]] || {
      echo "deploy: persisted connector state does not match $service" >&2
      return 1
    }
  done
  [[ "$container_count" == 0 || "$container_count" == 2 ]] || {
    echo 'deploy: persisted connector release has only one connector container' >&2
    return 1
  }
  previous_connector_enabled=1
}

capture_canonical_previous_release() {
  release_bundle_load "$CURRENT_RELEASE_BUNDLE_FILE" || return
  [[ "$release_bundle_control_tag" == "$previous_control_plane_tag" \
    && "$release_bundle_control_image_id" == "$previous_control_plane_image_id" \
    && "$release_bundle_core_tag" == "$previous_core_worker_tag" \
    && "$release_bundle_core_image_id" == "$previous_core_worker_image_id" ]] || {
    echo 'deploy: canonical current bundle disagrees with prepared previous control/core identity' >&2
    return 1
  }
  previous_release_validator_tag=$release_bundle_validator_tag
  previous_release_validator_image_id=$release_bundle_validator_image_id
  previous_connector_enabled=$release_bundle_connector_enabled
  previous_connector_tag=$release_bundle_connector_tag
  previous_connector_image_id=$release_bundle_connector_image_id
  had_current_release=1
}

prepare_canonical_current_release() {
  local candidate_validator_tag=$1 candidate_validator_id=$2 connector_enabled connector_tag connector_id
  if canonical_release_bundle_exists; then
    capture_canonical_previous_release
    return
  fi
  if ((fresh_bootstrap)); then
    had_current_release=0
    previous_release_validator_tag=''
    previous_release_validator_image_id=''
    previous_connector_enabled=0
    previous_connector_tag=''
    previous_connector_image_id=''
    return 0
  fi

  # Legacy migration is observation-only: derive connector intent from the complete
  # legacy state/runtime, journal one candidate bundle, verify health/raw IDs, promote,
  # then regenerate the old two-line files strictly as compatibility projections.
  if connector_image_state_exists; then
    prepare_previous_connector_image || return
  else
    previous_connector_enabled=0
    previous_connector_tag=''
    previous_connector_image_id=''
  fi
  connector_enabled=$previous_connector_enabled
  connector_tag=$previous_connector_tag
  connector_id=$previous_connector_image_id
  write_pending_release_bundle \
    "$previous_control_plane_tag" "$previous_control_plane_image_id" \
    "$previous_core_worker_tag" "$previous_core_worker_image_id" \
    "$candidate_validator_tag" "$candidate_validator_id" \
    "$connector_enabled" "$connector_tag" "$connector_id" || return
  if ! release_runtime_matches_bundle_file_for_legacy_migration "$PENDING_RELEASE_BUNDLE_FILE" \
    || ! release_runtime_health_for_bundle_file "$PENDING_RELEASE_BUNDLE_FILE"; then
    echo 'deploy: complete legacy release does not match its proposed canonical bundle' >&2
    return 1
  fi
  promote_pending_release_bundle || return
  capture_canonical_previous_release
}

assert_target_image_identity_compatible() {
  local target_tag=$1 target_image_id=$2
  assert_image_identities_compatible \
    previous-control-plane "$previous_control_plane_tag" "$previous_control_plane_image_id" \
    target "$target_tag" "$target_image_id" || return
  assert_image_identities_compatible \
    previous-core/ops-worker "$previous_core_worker_tag" "$previous_core_worker_image_id" \
    target "$target_tag" "$target_image_id" || return
  if ((previous_connector_enabled)); then
    assert_image_identities_compatible \
      previous-connector "$previous_connector_tag" "$previous_connector_image_id" \
      target "$target_tag" "$target_image_id" || return
  fi
}

build_control_plane_from_commit() {
  local commit=$1 iid_file image_id tagged_image_id
  [[ "$commit" =~ ^[0-9a-f]{40}$ ]] || {
    echo 'deploy: refusing to build a non-SHA release identity' >&2
    return 1
  }
  iid_file=$(mktemp "$BACKUP_DIR/.astranull-build-iid.XXXXXX")
  # --iidfile is the identity source. The exact-SHA tag is verified afterward but is
  # never consulted to derive the immutable image ID.
  if ! timeout -k 10 120 git archive "$commit" \
    | timeout -k 30 480 docker build --iidfile "$iid_file" \
      -f ops/aws/Dockerfile -t "astranull-control-plane:$commit" -; then
    rm -f -- "$iid_file"
    return 1
  fi
  [[ -f "$iid_file" && ! -L "$iid_file" \
    && "$(awk 'END { print NR }' "$iid_file")" == 1 ]] || {
    rm -f -- "$iid_file"
    echo 'deploy: exact-archive build did not produce one immutable image ID' >&2
    return 1
  }
  IFS= read -r image_id < "$iid_file"
  rm -f -- "$iid_file"
  [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo 'deploy: exact-archive build returned an invalid immutable image ID' >&2
    return 1
  }
  tagged_image_id=$(image_id_for_ref "astranull-control-plane:$commit") || return 1
  [[ "$tagged_image_id" == "$image_id" ]] || {
    echo 'deploy: exact-SHA tag changed before build identity verification' >&2
    return 1
  }
  built_control_plane_image_id=$image_id
}

ensure_requested_control_plane_image() {
  local commit=$1
  if [[ -n "$requested_image_id" ]]; then
    [[ "$commit" == "$SHA" && "$requested_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
    return 0
  fi
  build_control_plane_from_commit "$commit" || return
  requested_image_id=$built_control_plane_image_id
}

verify_service_image_tag() {
  local service=$1 release_tag=$2 expected_image_id=$3
  local cid image_ref container_image_id
  cid=$(compose_timeout 30 ps -q "$service")
  [[ -n "$cid" ]] || {
    echo "deploy: $service has no container" >&2
    return 1
  }
  image_ref=$(timeout -k 5 30 docker inspect --format '{{.Config.Image}}' "$cid")
  container_image_id=$(timeout -k 5 30 docker inspect --format '{{.Image}}' "$cid")
  [[ "$image_ref" == "$expected_image_id" ]] || {
    echo "deploy: $service Config.Image $image_ref does not equal exact release ID $expected_image_id (label $release_tag)" >&2
    return 1
  }
  [[ "$container_image_id" == "$expected_image_id" ]] || {
    echo "deploy: $service .Image $container_image_id does not equal exact release ID $expected_image_id" >&2
    return 1
  }
}

verify_control_plane_image_tag() {
  verify_service_image_tag control-plane "$1" "${2:-}"
}

verify_workers_image_tag() {
  local expected=$1 expected_image_id=$2 service
  for service in probe-worker password-recovery-worker test-policy-runner; do
    verify_service_image_tag "$service" "$expected" "$expected_image_id" || return
  done
}

verify_connector_workers_image_tag() {
  local expected=$1 expected_image_id=$2 service
  for service in connector-poll-scheduler connector-poll-runner; do
    verify_service_image_tag "$service" "$expected" "$expected_image_id" || return
  done
}

check_control_plane() {
  compose_timeout 30 exec -T control-plane node -e "Promise.all(['/health','/ready'].map(p=>fetch('http://127.0.0.1:8080'+p,{signal:AbortSignal.timeout(10000)}).then(r=>{if(!r.ok)throw Error(p+' '+r.status)}))).catch(e=>{console.error(e.message);process.exit(1)})" \
    || return
  curl --fail --silent --show-error --max-time 20 --retry 8 --retry-delay 3 --retry-connrefused --retry-all-errors https://astranull.site/health >/dev/null \
    || return
}

check_service_health() {
  local service=$1 cid health
  cid=$(compose_timeout 30 ps -q "$service")
  [[ -n "$cid" ]] || { echo "deploy: $service has no container" >&2; return 1; }
  health=$(timeout -k 5 30 docker inspect --format '{{.State.Health.Status}}' "$cid")
  [[ "$health" == healthy ]] || { echo "deploy: $service health is $health" >&2; return 1; }
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
      echo "deploy: could not verify container absence for $service" >&2
      failed=1
    elif [[ -n "${cid//[[:space:]]/}" ]]; then
      echo "deploy: $service still has container(s): ${cid//$'\n'/,}" >&2
      failed=1
    fi
  done
  ((failed == 0))
}

stop_remove_services() {
  local services=("$@")
  ((${#services[@]} > 0)) || return 0
  if ! compose_timeout 120 stop "${services[@]}" >/dev/null 2>&1; then
    echo "deploy: bounded stop failed for ${services[*]}; attempting kill fallback" >&2
    if ! compose_timeout 120 kill "${services[@]}" >/dev/null 2>&1; then
      echo "deploy: kill fallback reported failure for ${services[*]}; removal and verification will decide the outcome" >&2
    fi
  fi
  if ! compose_timeout 120 rm -f "${services[@]}" >/dev/null 2>&1; then
    echo "deploy: container removal reported failure for ${services[*]}; verifying every service" >&2
  fi
  verify_services_absent "${services[@]}"
}

stop_connector_workers() {
  stop_remove_services connector-poll-scheduler connector-poll-runner
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

fail_closed_runtime() {
  stop_remove_services caddy probe-worker password-recovery-worker test-policy-runner \
    connector-poll-scheduler connector-poll-runner control-plane
}

backup_file_owner() {
  stat -c '%u' -- "$1" 2>/dev/null || stat -f '%u' "$1"
}

backup_file_links() {
  stat -c '%h' -- "$1" 2>/dev/null || stat -f '%l' "$1"
}

ensure_backup_dir_secure() {
  local mode owner
  [[ ! -L "$BACKUP_DIR" ]] || { echo "deploy: refusing symlinked backup directory $BACKUP_DIR" >&2; return 1; }
  mkdir -p -- "$BACKUP_DIR" || return
  [[ -d "$BACKUP_DIR" && ! -L "$BACKUP_DIR" ]] || { echo 'deploy: backup path is not a regular directory' >&2; return 1; }
  chmod 700 "$BACKUP_DIR" || return
  mode=$(private_file_mode "$BACKUP_DIR") || return
  owner=$(backup_file_owner "$BACKUP_DIR") || return
  [[ "$mode" == 700 && "$owner" == "$(id -u)" ]] || {
    echo 'deploy: backup directory must be mode 0700 and owned by the deploy user' >&2
    return 1
  }
}

acquire_deploy_lock() {
  local mode owner links
  ensure_backup_dir_secure || return
  if [[ ! -e "$DEPLOY_LOCK_FILE" && ! -L "$DEPLOY_LOCK_FILE" ]]; then
    (umask 077; set -o noclobber; : > "$DEPLOY_LOCK_FILE") 2>/dev/null || true
  fi
  [[ -f "$DEPLOY_LOCK_FILE" && ! -L "$DEPLOY_LOCK_FILE" ]] || {
    echo "deploy: refusing unsafe deployment lock path $DEPLOY_LOCK_FILE" >&2
    return 1
  }
  chmod 600 "$DEPLOY_LOCK_FILE" || return
  mode=$(private_file_mode "$DEPLOY_LOCK_FILE") || return
  owner=$(backup_file_owner "$DEPLOY_LOCK_FILE") || return
  links=$(backup_file_links "$DEPLOY_LOCK_FILE") || return
  [[ "$mode" == 600 && "$owner" == "$(id -u)" && "$links" == 1 ]] || {
    echo 'deploy: deployment lock must be mode 0600, singly linked, and owned by the deploy user' >&2
    return 1
  }
  exec 9>>"$DEPLOY_LOCK_FILE"
  flock -n 9 || { echo 'deploy: another deployment or restore is active' >&2; return 1; }
  python3 - "$DEPLOY_LOCK_FILE" <<'PY'
import os, stat, sys
path_stat = os.stat(sys.argv[1], follow_symlinks=False)
fd_stat = os.fstat(9)
if (path_stat.st_dev, path_stat.st_ino) != (fd_stat.st_dev, fd_stat.st_ino):
    raise SystemExit('deploy: deployment lock pathname changed while locking')
if not stat.S_ISREG(fd_stat.st_mode) or stat.S_IMODE(fd_stat.st_mode) != 0o600 or fd_stat.st_nlink != 1:
    raise SystemExit('deploy: locked deployment inode is unsafe')
if fd_stat.st_uid != os.getuid():
    raise SystemExit('deploy: locked deployment inode has the wrong owner')
PY
}

cleanup_stale_release_workspace() {
  local candidate mode owner links failed=0 stale=()
  ensure_backup_dir_secure || return
  shopt -s nullglob
  stale=("$BACKUP_DIR"/.astranull-env.deploy.* "$BACKUP_DIR"/.astranull-env.restore.* \
    "$BACKUP_DIR"/.astranull-compose-render.deploy.* "$BACKUP_DIR"/.astranull-compose-render.restore.* \
    "$BACKUP_DIR"/.astranull-compose-source.restore.* "$BACKUP_DIR"/.astranull-compose.previous.*.yml \
    "$BACKUP_DIR"/.astranull-compose.target.*.yml "$BACKUP_DIR"/.astranull-build-iid.*)
  shopt -u nullglob
  for candidate in ${stale[@]+"${stale[@]}"}; do
    if [[ -f "$candidate" && ! -L "$candidate" ]]; then
      mode=$(private_file_mode "$candidate") || mode=''
      owner=$(backup_file_owner "$candidate") || owner=''
      links=$(backup_file_links "$candidate") || links=''
      if [[ "$mode" != 600 || "$owner" != "$(id -u)" || "$links" != 1 ]]; then
        echo "deploy: CRITICAL: stale private release workspace is unsafe: $candidate" >&2
        failed=1
      fi
    else
      echo "deploy: CRITICAL: stale private release workspace is non-regular or symlinked: $candidate" >&2
      failed=1
    fi
    remove_backup_file_checked "$candidate" 'stale private release workspace' || failed=1
  done
  ((failed == 0))
}

validate_plaintext_file_security() {
  local candidate=$1 phase=$2 require_data=${3:-0} mode owner links
  [[ -f "$candidate" && ! -L "$candidate" ]] || {
    echo "deploy: plaintext backup is not a regular non-symlink file during $phase" >&2
    return 1
  }
  mode=$(private_file_mode "$candidate") || return
  owner=$(backup_file_owner "$candidate") || return
  links=$(backup_file_links "$candidate") || return
  if [[ "$links" != 1 ]]; then
    echo "deploy: CRITICAL: plaintext backup link count is $links during $phase; possible hard-link exposure requires incident escalation" >&2
    return 1
  fi
  [[ "$mode" == 600 && "$owner" == "$(id -u)" ]] || {
    echo "deploy: plaintext backup must be mode 0600 and owned by the deploy user during $phase" >&2
    return 1
  }
  if ((require_data)) && [[ ! -s "$candidate" ]]; then
    echo "deploy: plaintext backup is empty during $phase" >&2
    return 1
  fi
}

allocate_plaintext_backup() {
  local candidate
  ensure_backup_dir_secure || return
  candidate=$(umask 077; mktemp "$BACKUP_DIR/.astranull-plaintext.deploy.XXXXXX") || {
    echo 'deploy: could not exclusively allocate a random plaintext backup path' >&2
    return 1
  }
  plain_host=$candidate
  validate_plaintext_file_security "$plain_host" allocation 0
}

remove_backup_file_checked() {
  local candidate=$1 label=$2
  if [[ -e "$candidate" || -L "$candidate" ]]; then
    rm -f -- "$candidate" || { echo "deploy: could not remove $label $candidate" >&2; return 1; }
  fi
  [[ ! -e "$candidate" && ! -L "$candidate" ]] || {
    echo "deploy: $label remains after cleanup: $candidate" >&2
    return 1
  }
}

cleanup_backup_orphans() {
  local partial plaintext artifact manifest failed=0
  local partials=() plaintexts=() artifacts=() manifests=()
  ensure_backup_dir_secure || return
  shopt -s nullglob
  partials=("$BACKUP_DIR"/.postgres-*.partial-*)
  plaintexts=("$BACKUP_DIR"/.astranull-plaintext.deploy.* "$BACKUP_DIR"/.astranull-plaintext.restore.*)
  artifacts=("$BACKUP_DIR"/*.dump.enc)
  manifests=("$BACKUP_DIR"/*.dump.enc.manifest.json)
  shopt -u nullglob
  for partial in ${partials[@]+"${partials[@]}"}; do
    remove_backup_file_checked "$partial" 'stale private backup partial' || failed=1
  done
  for plaintext in ${plaintexts[@]+"${plaintexts[@]}"}; do
    delete_plaintext_checked "$plaintext" || failed=1
  done
  for artifact in ${artifacts[@]+"${artifacts[@]}"}; do
    manifest="$artifact.manifest.json"
    if [[ ! -f "$artifact" || -L "$artifact" || ! -f "$manifest" || -L "$manifest" ]]; then
      remove_backup_file_checked "$artifact" 'unmatched encrypted backup artifact' || failed=1
      if [[ -e "$manifest" || -L "$manifest" ]]; then
        remove_backup_file_checked "$manifest" 'unmatched backup manifest' || failed=1
      fi
    fi
  done
  for manifest in ${manifests[@]+"${manifests[@]}"}; do
    artifact=${manifest%.manifest.json}
    if [[ ! -f "$manifest" || -L "$manifest" || ! -f "$artifact" || -L "$artifact" ]]; then
      remove_backup_file_checked "$manifest" 'unmatched backup manifest' || failed=1
      if [[ -e "$artifact" || -L "$artifact" ]]; then
        remove_backup_file_checked "$artifact" 'unmatched encrypted backup artifact' || failed=1
      fi
    fi
  done
  ((failed == 0))
}

list_valid_backup_artifacts() {
  compose_ops_run 600 backup-inventory \
    -u "$(id -u):$(id -g)" -v "$BACKUP_DIR:/backup:ro" backup \
    node --input-type=module -e '
      import crypto from "node:crypto";
      import { createReadStream } from "node:fs";
      import { lstat, readFile, readdir } from "node:fs/promises";
      import { validatePostgresBackupManifestFields } from "./scripts/postgres-backup.mjs";
      const root = "/backup";
      const artifacts = (await readdir(root))
        .filter(name => !name.startsWith(".") && name.endsWith(".dump.enc"))
        .sort();
      if (artifacts.length > 64) throw new Error("backup inventory exceeds bounded maximum 64");
      for (const name of artifacts) {
        if (!/^postgres-[A-Za-z0-9-]+-[0-9a-f]{12}\.dump\.enc$/.test(name)) {
          throw new Error(`unsafe backup artifact name: ${JSON.stringify(name)}`);
        }
        const artifactPath = `${root}/${name}`;
        const manifestPath = `${artifactPath}.manifest.json`;
        const artifactStat = await lstat(artifactPath);
        const manifestStat = await lstat(manifestPath);
        if (!artifactStat.isFile() || artifactStat.isSymbolicLink() || artifactStat.nlink !== 1
          || !manifestStat.isFile() || manifestStat.isSymbolicLink() || manifestStat.nlink !== 1
          || manifestStat.size < 1 || manifestStat.size > 65536) {
          throw new Error(`unsafe or incomplete backup pair: ${name}`);
        }
        const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
        validatePostgresBackupManifestFields(manifest);
        if (manifest.backup_file !== name || manifest.bytes !== artifactStat.size) {
          throw new Error(`backup manifest identity/size mismatch: ${name}`);
        }
        const hash = crypto.createHash("sha256");
        for await (const chunk of createReadStream(artifactPath)) hash.update(chunk);
        if (hash.digest("hex") !== manifest.sha256) {
          throw new Error(`backup encrypted digest mismatch: ${name}`);
        }
        process.stdout.write(`${name}\n`);
      }
    '
}

prune_backups() {
  local complete=() artifact_name artifact old failed=0 valid_artifacts
  valid_artifacts=$(list_valid_backup_artifacts) || return
  while IFS= read -r artifact_name; do
    [[ -n "$artifact_name" ]] || continue
    [[ "$artifact_name" =~ ^postgres-[A-Za-z0-9-]+-[0-9a-f]{12}\.dump\.enc$ ]] || {
      echo "deploy: backup inventory returned an unsafe artifact name: $artifact_name" >&2
      return 1
    }
    artifact="$BACKUP_DIR/$artifact_name"
    [[ -f "$artifact" && ! -L "$artifact" && -f "$artifact.manifest.json" && ! -L "$artifact.manifest.json" ]] || {
      echo "deploy: validated backup pair changed before retention: $artifact_name" >&2
      return 1
    }
    complete+=("$artifact")
  done <<< "$valid_artifacts"
  if ((${#complete[@]} > 10)); then
    while IFS= read -r old; do
      [[ -n "$old" ]] || continue
      remove_backup_file_checked "$old.manifest.json" 'expired backup completion manifest' || failed=1
      remove_backup_file_checked "$old" 'expired encrypted backup artifact' || failed=1
    done < <(printf '%s\n' "${complete[@]}" | sort -r | tail -n +11)
  fi
  ((failed == 0))
}

validate_plaintext_archive() {
  local archive_host=$1 archive_name
  archive_name=${archive_host##*/}
  validate_plaintext_file_security "$archive_host" 'before structural parse' 1 || return
  compose_ops_run 60 pg-restore-list \
    -u "$(id -u):$(id -g)" -v "$BACKUP_DIR:/backup:ro" backup-dump \
    sh -eu -c 'exec pg_restore --list "$1" >/dev/null' sh "/backup/$archive_name"
}

delete_plaintext_checked() {
  local candidate=${1:-} failed=0
  [[ -n "$candidate" ]] || return 0
  if [[ -e "$candidate" || -L "$candidate" ]]; then
    if ! validate_plaintext_file_security "$candidate" 'before checked deletion' 0; then failed=1; fi
    if ! rm -f -- "$candidate"; then
      echo "deploy: WARNING: plaintext deletion command failed for $candidate" >&2
      failed=1
    fi
  fi
  if [[ -e "$candidate" || -L "$candidate" ]]; then
    echo "deploy: CRITICAL: plaintext backup still exists at $candidate; immediate operator escalation is required" >&2
    failed=1
  fi
  ((failed == 0))
}

backup_database() {
  local backup_output backup_container_path plain_name
  cleanup_backup_orphans
  allocate_plaintext_backup
  plain_name=${plain_host##*/}
  compose_ops_run 90 backup-role-bootstrap backup-role-bootstrap
  validate_plaintext_file_security "$plain_host" 'before pg_dump' 0
  compose_ops_run 180 pg-dump \
    -u "$(id -u):$(id -g)" -v "$BACKUP_DIR:/backup" backup-dump \
    sh -eu -c 'umask 077; exec pg_dump --format=custom --no-owner --no-acl --dbname="$ASTRANULL_BACKUP_DATABASE_URL" --file="$1"' \
    sh "/backup/$plain_name"
  validate_plaintext_file_security "$plain_host" 'after pg_dump' 1
  validate_plaintext_archive "$plain_host"
  validate_plaintext_file_security "$plain_host" 'before encryption' 1
  backup_output=$(compose_ops_run 180 backup-encrypt \
    -u "$(id -u):$(id -g)" -v "$BACKUP_DIR:/backup" backup \
    node scripts/postgres-backup.mjs \
    --input "/backup/$plain_name" --out /backup --label "predeploy-${previous:0:12}" \
    --database-host postgres --database-port 5432 --database-name astranull)
  delete_plaintext_checked "$plain_host"
  plain_host=''
  backup_container_path=$(printf '%s\n' "$backup_output" | sed -n 's/^  backup: //p' | tail -1)
  [[ "$backup_container_path" == /backup/*.dump.enc ]]
  backup="$BACKUP_DIR/${backup_container_path##*/}"
  [[ -f "$backup" && ! -L "$backup" && -s "$backup" \
    && -f "$backup.manifest.json" && ! -L "$backup.manifest.json" \
    && -s "$backup.manifest.json" ]]
  chmod 600 "$backup" "$backup.manifest.json"
  cleanup_backup_orphans
  compose_ops_run 180 backup-validate \
    -u "$(id -u):$(id -g)" -v "$BACKUP_DIR:/backup:ro" backup \
    node scripts/postgres-restore-drill.mjs \
    --manifest "/backup/${backup##*/}.manifest.json" --backup "/backup/${backup##*/}" --validate-only
  prune_backups
}

release_bundle_tags() {
  local file=$1
  release_bundle_load "$file" || return
  printf '%s\n' "$release_bundle_control_tag" "$release_bundle_core_tag" "$release_bundle_validator_tag"
  [[ "$release_bundle_connector_enabled" != 1 ]] || printf '%s\n' "$release_bundle_connector_tag"
}

running_release_tag_refs() {
  local cids cid ref
  cids=$(timeout -k 5 30 docker container ls -q) || return
  while IFS= read -r cid; do
    [[ -n "$cid" ]] || continue
    ref=$(timeout -k 5 30 docker inspect --format '{{.Config.Image}}' "$cid") || return
    [[ "$ref" =~ ^astranull-(control-plane|release-validator):([0-9a-f]{40})$ ]] || continue
    printf '%s\n' "${BASH_REMATCH[2]}"
  done <<< "$cids"
}

release_tag_is_preserved() {
  local candidate=$1 preserved
  while IFS= read -r preserved; do
    [[ -z "$preserved" || "$candidate" != "$preserved" ]] || return 0
  done <<< "$2"
  return 1
}

bounded_prune_release_images() {
  local listed ref tag preserved='' scan_count=0 remaining_count=0 failed=0 image_id repo_tags
  local obsolete_ids=''
  canonical_release_bundle_exists || { echo 'deploy: cannot prune release tags without canonical current state' >&2; return 1; }
  preserved=$(release_bundle_tags "$CURRENT_RELEASE_BUNDLE_FILE") || return
  if pending_release_bundle_exists; then
    preserved+=$'\n'"$(release_bundle_tags "$PENDING_RELEASE_BUNDLE_FILE")" || return
  fi
  preserved+=$'\n'"$(running_release_tag_refs)" || return
  listed=$(timeout -k 5 30 docker image ls --format '{{.Repository}}:{{.Tag}}') || {
    echo 'deploy: could not enumerate local image tags for bounded cleanup' >&2
    return 1
  }
  while IFS= read -r ref; do
    [[ "$ref" =~ ^astranull-(control-plane|release-validator):([0-9a-f]{40})$ ]] || continue
    scan_count=$((scan_count + 1))
    ((scan_count <= 256)) || {
      echo 'deploy: more than 256 exact-SHA AstraNull tags require explicit operator cleanup' >&2
      return 1
    }
    tag=${BASH_REMATCH[2]}
    release_tag_is_preserved "$tag" "$preserved" && continue
    image_id=$(image_id_for_ref "$ref") || { echo "deploy: could not resolve obsolete release tag $ref" >&2; failed=1; continue; }
    if ! timeout -k 5 30 docker image rm "$ref" >/dev/null; then
      echo "deploy: failed to remove obsolete exact-SHA release tag $ref" >&2
      failed=1
      continue
    fi
    if timeout -k 5 30 docker image inspect "$ref" >/dev/null 2>&1; then
      echo "deploy: obsolete exact-SHA release tag still resolves after removal: $ref" >&2
      failed=1
    fi
    obsolete_ids+="${obsolete_ids:+$'\n'}$image_id"
  done <<< "$listed"
  ((failed == 0)) || return 1

  listed=$(timeout -k 5 30 docker image ls --format '{{.Repository}}:{{.Tag}}') || return
  while IFS= read -r ref; do
    [[ "$ref" =~ ^astranull-(control-plane|release-validator):([0-9a-f]{40})$ ]] || continue
    tag=${BASH_REMATCH[2]}
    release_tag_is_preserved "$tag" "$preserved" || {
      echo "deploy: obsolete exact-SHA release tag survived bounded cleanup: $ref" >&2
      return 1
    }
    remaining_count=$((remaining_count + 1))
  done <<< "$listed"
  ((remaining_count <= 11)) || {
    echo "deploy: exact-SHA release tag count $remaining_count exceeds documented bound 11" >&2
    return 1
  }

  # Prune only dangling IDs that were reached through removed AstraNull tags. A global
  # docker image prune could delete unrelated repositories and is deliberately forbidden.
  while IFS= read -r image_id; do
    [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || continue
    repo_tags=$(timeout -k 5 30 docker image inspect --format '{{json .RepoTags}}' "$image_id" 2>/dev/null) || continue
    case "$repo_tags" in
      '[]'|'null')
        if ! timeout -k 5 30 docker image rm "$image_id" >/dev/null; then
          echo "deploy: failed to prune dangling AstraNull release image $image_id" >&2
          return 1
        fi
        ;;
    esac
  done <<< "$obsolete_ids"
}

rollback_on_error() {
  local rc=${1:-1} rollback_compose rollback_checkout_tag rollback_connector_image_id
  local rollback_validator_tag rollback_validator_image_id cleanup_failed=0
  ((rc != 0)) || rc=1
  trap - ERR EXIT
  trap '' HUP INT TERM
  set +e
  if ! cleanup_active_operation_containers_checked; then
    cleanup_failed=1
    rc=125
    echo 'deploy: CRITICAL: parent cleanup could not remove and verify every exact operation container; immediate operator intervention is required' >&2
  fi
  if ! cleanup_compose_render_checked; then
    cleanup_failed=1
    rc=125
    echo 'deploy: CRITICAL: parent cleanup could not remove the private Compose render; immediate operator intervention is required' >&2
  fi

  if ((activated)); then
    if [[ "$MODE" == rollback ]]; then
      rollback_compose=$previous_compose
      rollback_checkout_tag=$previous
      rollback_validator_tag=$previous_release_validator_tag
      rollback_validator_image_id=$previous_release_validator_image_id
    else
      # Retain target Compose for forward-compatible schema/orchestration, but restore
      # every runtime image to its exact durable predeploy identity. Its validator must
      # remain the target validator because it is the authority for target Compose.
      rollback_compose=$target_compose
      rollback_checkout_tag=$SHA
      rollback_validator_tag=$release_validator_tag
      rollback_validator_image_id=$release_validator_image_id
    fi
  else
    rollback_compose=$previous_compose
    rollback_checkout_tag=$previous
  fi
  ACTIVE_COMPOSE_FILE=$rollback_compose

  if [[ -n ${plain_host:-} ]]; then
    if delete_plaintext_checked "$plain_host"; then
      plain_host=''
    else
      rc=1
      echo 'deploy: CRITICAL: automatic cleanup could not prove plaintext absence; incident escalation is required' >&2
    fi
  fi

  if ((activated)); then
    if (( ! had_current_release )); then
      if fail_closed_runtime; then
        echo "deploy: first activation failed with no prior canonical release; runtime containers were stopped, removed, and verified absent; encrypted database backup is $backup" >&2
      else
        echo "deploy: first activation failed with no prior canonical release and runtime shutdown could not be verified; immediate operator intervention is required; encrypted database backup is $backup" >&2
      fi
    else
      local rollback_failed=0 connector_rollback_enabled=0
      export ASTRANULL_IMAGE_TAG="$previous_core_worker_tag"
      export ASTRANULL_CONTROL_PLANE_IMAGE_TAG="$previous_control_plane_tag"
      export ASTRANULL_WORKER_IMAGE_TAG="$previous_core_worker_tag"
      export ASTRANULL_CONNECTOR_WORKER_IMAGE_TAG="$previous_core_worker_tag"

      rollback_connector_image_id=$previous_core_worker_image_id
      if [[ "$validated_connector_mode" == enabled ]] && ((previous_connector_enabled)); then
        if rebind_connector_image_tag "$previous_connector_tag" "$previous_connector_image_id" \
          && connector_image_supports_split_mode "$previous_connector_image_id"; then
          export ASTRANULL_CONNECTOR_WORKER_IMAGE_TAG="$previous_connector_tag"
          rollback_connector_image_id=$previous_connector_image_id
          connector_rollback_enabled=1
        else
          echo 'deploy: previous connector image is unavailable or incompatible with connector-enabled rollback Compose' >&2
          rollback_failed=1
        fi
      elif [[ "$validated_connector_mode" == enabled ]]; then
        echo 'deploy: connector-enabled rollback Compose has no prior connector identity; refusing mismatched rollback state' >&2
        rollback_failed=1
      elif ((previous_connector_enabled)); then
        echo "deploy: prior connector state ignored because validated release connector mode is ${validated_connector_mode:-unvalidated}; connector egress will remain stopped" >&2
      fi

      if (( ! rollback_failed && connector_rollback_enabled )); then
        write_pending_release_bundle \
          "$previous_control_plane_tag" "$previous_control_plane_image_id" \
          "$previous_core_worker_tag" "$previous_core_worker_image_id" \
          "$rollback_validator_tag" "$rollback_validator_image_id" \
          1 "$previous_connector_tag" "$previous_connector_image_id" || rollback_failed=1
      elif (( ! rollback_failed )); then
        write_pending_release_bundle \
          "$previous_control_plane_tag" "$previous_control_plane_image_id" \
          "$previous_core_worker_tag" "$previous_core_worker_image_id" \
          "$rollback_validator_tag" "$rollback_validator_image_id" \
          0 '' '' || rollback_failed=1
      fi

      if (( ! rollback_failed )); then
        if ! export_compose_image_ids "$previous_control_plane_image_id" \
          "$previous_core_worker_image_id" "$rollback_connector_image_id"; then
          rollback_failed=1
        elif ! git checkout -q --detach "$rollback_checkout_tag"; then
          echo "deploy: automatic hybrid rollback could not restore orchestration checkout $rollback_checkout_tag; encrypted database backup is $backup" >&2
          rollback_failed=1
        elif ! rebind_control_plane_image_tag "$previous_control_plane_tag" "$previous_control_plane_image_id"; then
          echo "deploy: automatic hybrid rollback could not rebind the preserved control-plane image; encrypted database backup is $backup" >&2
          rollback_failed=1
        elif ! rebind_core_worker_image_tag "$previous_core_worker_tag" "$previous_core_worker_image_id"; then
          echo "deploy: automatic hybrid rollback could not rebind the preserved core/ops worker image; encrypted database backup is $backup" >&2
          rollback_failed=1
        elif ! start_core_stack || ! check_control_plane || ! check_core_workers; then
          echo "deploy: hybrid rollback core stack failed health checks; encrypted database backup is $backup" >&2
          rollback_failed=1
        elif ! verify_control_plane_image_tag "$previous_control_plane_tag" "$previous_control_plane_image_id" \
          || ! verify_workers_image_tag "$previous_core_worker_tag" "$previous_core_worker_image_id"; then
          echo "deploy: hybrid rollback core image identity could not be verified; encrypted database backup is $backup" >&2
          rollback_failed=1
        fi
      fi

      if (( ! rollback_failed && connector_rollback_enabled )); then
        if ! start_connector_workers || ! check_connector_workers \
          || ! verify_connector_workers_image_tag "$previous_connector_tag" "$previous_connector_image_id"; then
          echo 'deploy: connector rollback failed; stopping the entire runtime fail-closed' >&2
          rollback_failed=1
        fi
      fi

      if (( ! rollback_failed )); then
        promote_pending_release_bundle || rollback_failed=1
      fi

      if ((rollback_failed)); then
        if fail_closed_runtime; then
          if pending_release_bundle_exists; then
            release_state_durable_remove "$PENDING_RELEASE_BUNDLE_FILE" 'failed rollback pending release-image bundle' || cleanup_failed=1
          fi
          regenerate_release_state_projections || cleanup_failed=1
          echo "deploy: automatic rollback failed; runtime containers were stopped, removed, and verified absent; encrypted database backup is $backup" >&2
        else
          echo "deploy: automatic rollback failed and runtime shutdown could not be verified; immediate operator intervention is required; encrypted database backup is $backup" >&2
        fi
      else
        echo "deploy: automatic hybrid rollback restored control-plane $previous_control_plane_tag@$previous_control_plane_image_id and core/ops workers $previous_core_worker_tag@$previous_core_worker_image_id with orchestration checkout $rollback_checkout_tag; connector_enabled=$connector_rollback_enabled; database was not downgraded; encrypted backup is $backup" >&2
      fi
    fi
  else
    if [[ -n "$previous_control_plane_tag" && -n "$previous_control_plane_image_id" ]] \
      && ! rebind_control_plane_image_tag "$previous_control_plane_tag" "$previous_control_plane_image_id"; then
      echo 'deploy: failed before service activation and could not restore the preserved control-plane tag identity' >&2
    fi
    if [[ -n "$previous_core_worker_tag" && -n "$previous_core_worker_image_id" ]] \
      && ! rebind_core_worker_image_tag "$previous_core_worker_tag" "$previous_core_worker_image_id"; then
      echo 'deploy: failed before service activation and could not restore the preserved core/ops worker tag identity' >&2
    fi
    if ((previous_connector_enabled)) \
      && ! rebind_connector_image_tag "$previous_connector_tag" "$previous_connector_image_id"; then
      echo 'deploy: failed before service activation and could not restore the preserved connector tag identity' >&2
    fi
    if git checkout -q --detach "$previous"; then
      echo "deploy: failed before service activation; restored checkout $previous" >&2
    else
      echo "deploy: failed before service activation and could not restore checkout $previous" >&2
    fi
    if ((migration_started)); then
      echo "deploy: a migration was attempted and was not downgraded; encrypted backup is $backup" >&2
    fi
  fi
  if ! verify_release_state_journal_safe; then
    cleanup_failed=1
    rc=125
    echo 'deploy: CRITICAL: current/pending release journal is unsafe during rollback cleanup' >&2
  fi
  if ! cleanup_backup_orphans; then
    cleanup_failed=1
    rc=125
    echo 'deploy: CRITICAL: backup orphan cleanup failed during rollback/cleanup' >&2
  fi
  if ! cleanup_compose_snapshots; then
    cleanup_failed=1
    rc=125
    echo 'deploy: CRITICAL: release snapshot cleanup failed; immediate operator cleanup is required' >&2
  fi
  if ((cleanup_failed)); then rc=125; fi
  exit "$rc"
}

handle_deploy_exit() {
  local rc=$?
  if (( ! finished )); then
    ((rc != 0)) || rc=1
    rollback_on_error "$rc"
  fi
}

install_failure_traps() {
  trap 'rollback_on_error "$?"' ERR
  trap 'rollback_on_error 130' INT TERM HUP
  trap handle_deploy_exit EXIT
}

clear_failure_traps() {
  trap - ERR INT TERM HUP EXIT
}

finalize_success_cleanup() {
  local failed=0
  trap - ERR EXIT
  trap '' HUP INT TERM
  set +e
  if ! cleanup_active_operation_containers_checked; then
    echo 'deploy: CRITICAL: successful-release cleanup found an operation-container leak' >&2
    failed=1
  fi
  if [[ -n ${plain_host:-} ]]; then
    if delete_plaintext_checked "$plain_host"; then plain_host=''; else failed=1; fi
  fi
  if ! cleanup_backup_orphans; then
    echo 'deploy: CRITICAL: successful-release backup orphan cleanup failed' >&2
    failed=1
  fi
  if ! verify_release_state_settled; then
    echo 'deploy: CRITICAL: canonical release state did not settle after promotion' >&2
    failed=1
  fi
  if ! cleanup_compose_snapshots; then
    echo 'deploy: CRITICAL: release snapshot cleanup failed after activation; immediate operator cleanup is required' >&2
    failed=1
  fi
  if ! bounded_prune_release_images; then
    echo 'deploy: CRITICAL: bounded exact-SHA image cleanup failed' >&2
    failed=1
  fi
  set -e
  trap - HUP INT TERM
  ((failed == 0))
}

main() {
  MODE=deploy
  if [[ ${1:-} == --rollback ]]; then MODE=rollback; shift; fi
  SHA=${1:-}
  [[ "$SHA" =~ ^[0-9a-f]{40}$ ]] || { echo 'deploy: exact 40-char SHA required' >&2; exit 1; }

  acquire_deploy_lock
  cd "$ROOT"
  validate_env_source
  local remote_main active_control_plane_image_id validator_image_id
  local active_core_worker_tag='' active_core_worker_image_id=''
  local connector_release_enabled=0 connector_image_id=''
  [[ -z $(git status --porcelain --untracked-files=all) ]] || { echo 'deploy: repository has tracked or untracked changes' >&2; exit 1; }

  previous=$(git rev-parse HEAD)
  timeout -k 10 60 git fetch --prune origin main
  remote_main=$(git rev-parse origin/main)
  if [[ "$MODE" == deploy ]]; then
    [[ "$SHA" == "$remote_main" ]] || { echo "deploy: verified SHA is stale; origin/main is $remote_main" >&2; exit 1; }
  else
    git merge-base --is-ancestor "$SHA" "$remote_main" || { echo 'deploy: rollback SHA is not an ancestor of origin/main' >&2; exit 1; }
  fi
  git cat-file -e "$SHA^{commit}"

  previous_compose=''
  target_compose=''
  plain_host=''
  backup=''
  activated=0
  migration_started=0
  finished=0
  previous_control_plane_image_id=''
  previous_core_worker_tag=''
  previous_core_worker_image_id=''
  previous_connector_tag=''
  previous_connector_image_id=''
  previous_connector_enabled=0
  previous_release_validator_tag=''
  previous_release_validator_image_id=''
  had_current_release=0
  requested_image_id=''
  built_control_plane_image_id=''
  fresh_bootstrap=0
  validated_connector_mode=''
  release_validator_tag=''
  release_validator_image_id=''
  install_failure_traps
  cleanup_stale_operation_containers_checked
  cleanup_stale_release_workspace
  cleanup_backup_orphans

  # Keep immutable Compose inputs for both sides of the release boundary. A normal
  # release uses target_compose; previous_compose remains for pre-activation cleanup
  # and for explicit rollback's current-orchestration boundary.
  previous_compose=$(mktemp "$BACKUP_DIR/.astranull-compose.previous.XXXXXX.yml")
  target_compose=$(mktemp "$BACKUP_DIR/.astranull-compose.target.XXXXXX.yml")
  git show "$previous:$COMPOSE_REPO_PATH" > "$previous_compose"
  git show "$SHA:$COMPOSE_REPO_PATH" > "$target_compose"
  chmod 600 "$previous_compose" "$target_compose"
  ACTIVE_COMPOSE_FILE="$previous_compose"
  snapshot_env_file
  # Build once from the requested archive so even pre-validation Compose metadata calls
  # receive real local IDs; no Compose execution ever resolves an application tag.
  ensure_requested_control_plane_image "$SHA"
  export_compose_image_ids "$requested_image_id" "$requested_image_id" "$requested_image_id"
  # Use the requested Compose contract to inventory the fixed project service names.
  # Missing exact state can be bridged only from a complete running fleet; otherwise
  # first boot is initialized from the requested archive build after freshness proof.
  ACTIVE_COMPOSE_FILE="$target_compose"
  reconcile_pending_release_bundle
  prepare_previous_release_images "$SHA"

  if [[ "$MODE" == rollback ]]; then
    load_release_validator_image_identity
    # Explicit rollback retains current Compose but binds core workers and every ops
    # one-shot to the independently persisted core/ops image identity.
    ACTIVE_COMPOSE_FILE="$previous_compose"
    export ASTRANULL_IMAGE_TAG="$previous_core_worker_tag"
    export ASTRANULL_CONTROL_PLANE_IMAGE_TAG="$previous_control_plane_tag"
    export ASTRANULL_WORKER_IMAGE_TAG="$previous_core_worker_tag"
    export ASTRANULL_CONNECTOR_WORKER_IMAGE_TAG="$SHA"
    active_control_plane_image_id=$requested_image_id
    active_core_worker_tag=$previous_core_worker_tag
    active_core_worker_image_id=$previous_core_worker_image_id
    connector_image_id=$requested_image_id
    export_compose_image_ids "$active_control_plane_image_id" \
      "$active_core_worker_image_id" "$connector_image_id"
    validator_image_id=$release_validator_image_id
    assert_image_identities_compatible \
      current-release-validator "$release_validator_tag" "$release_validator_image_id" \
      current-control-plane "$previous_control_plane_tag" "$previous_control_plane_image_id"
    assert_image_identities_compatible \
      current-release-validator "$release_validator_tag" "$release_validator_image_id" \
      current-core/ops-worker "$previous_core_worker_tag" "$previous_core_worker_image_id"
    validate_compose "$validator_image_id" validated_connector_mode
    [[ "$validated_connector_mode" == enabled || "$validated_connector_mode" == disabled ]] || {
      echo 'deploy: rendered connector release mode is invalid' >&2
      return 1
    }
    prepare_canonical_current_release "$release_validator_tag" "$release_validator_image_id"
    if [[ "$validated_connector_mode" == enabled ]]; then
      prepare_previous_connector_image
    else
      previous_connector_enabled=0
    fi
    assert_target_image_identity_compatible "$SHA" "$active_control_plane_image_id"
    if [[ "$validated_connector_mode" == enabled ]]; then
      connector_image_supports_split_mode "$active_control_plane_image_id" || {
        echo "deploy: rollback image $SHA lacks split connector mode required by retained Compose" >&2
        return 1
      }
      connector_release_enabled=1
      connector_image_id=$active_control_plane_image_id
      export ASTRANULL_CONNECTOR_WORKER_IMAGE_TAG="$SHA"
    else
      connector_release_enabled=0
      connector_image_id=''
      echo 'deploy: connectors disabled by rendered configuration; connector workloads will remain absent' >&2
    fi
    backup_database
    export ASTRANULL_CONTROL_PLANE_IMAGE_TAG="$SHA"
    if ((connector_release_enabled)); then
      write_pending_release_bundle \
        "$SHA" "$active_control_plane_image_id" \
        "$active_core_worker_tag" "$active_core_worker_image_id" \
        "$release_validator_tag" "$release_validator_image_id" \
        1 "$SHA" "$connector_image_id"
    else
      write_pending_release_bundle \
        "$SHA" "$active_control_plane_image_id" \
        "$active_core_worker_tag" "$active_core_worker_image_id" \
        "$release_validator_tag" "$release_validator_image_id" \
        0 '' ''
    fi
    activated=1
    start_core_stack
    check_control_plane
    check_core_workers
    verify_control_plane_image_tag "$SHA" "$active_control_plane_image_id"
    verify_workers_image_tag "$active_core_worker_tag" "$active_core_worker_image_id"
    if ((connector_release_enabled)); then
      start_connector_workers
      check_connector_workers
      verify_connector_workers_image_tag "$SHA" "$connector_image_id"
    else
      verify_services_absent connector-poll-scheduler connector-poll-runner
    fi
    promote_pending_release_bundle
  else
    ACTIVE_COMPOSE_FILE="$target_compose"
    export ASTRANULL_IMAGE_TAG="$SHA"
    export ASTRANULL_CONTROL_PLANE_IMAGE_TAG="$SHA"
    export ASTRANULL_WORKER_IMAGE_TAG="$SHA"
    export ASTRANULL_CONNECTOR_WORKER_IMAGE_TAG="$SHA"
    # The exact-SHA build supplies the control plane, core/ops workers, validator,
    # migration/backup one-shots, and (when enabled) connector workers.
    validator_image_id=$requested_image_id
    active_control_plane_image_id=$validator_image_id
    active_core_worker_tag=$SHA
    active_core_worker_image_id=$validator_image_id
    connector_image_id=$validator_image_id
    export_compose_image_ids "$active_control_plane_image_id" \
      "$active_core_worker_image_id" "$connector_image_id"
    validate_compose "$validator_image_id" validated_connector_mode
    [[ "$validated_connector_mode" == enabled || "$validated_connector_mode" == disabled ]] || {
      echo 'deploy: rendered connector release mode is invalid' >&2
      return 1
    }
    release_validator_tag=$SHA
    release_validator_image_id=$validator_image_id
    rebind_release_validator_image_tag "$release_validator_tag" "$release_validator_image_id"
    prepare_canonical_current_release "$release_validator_tag" "$release_validator_image_id"
    if [[ "$validated_connector_mode" == enabled ]]; then
      prepare_previous_connector_image
    else
      previous_connector_enabled=0
    fi
    assert_target_image_identity_compatible "$SHA" "$validator_image_id"
    if [[ "$validated_connector_mode" == enabled ]]; then
      connector_image_supports_split_mode "$connector_image_id" || {
        echo 'deploy: target image does not support required split connector scheduler mode' >&2
        return 1
      }
      connector_release_enabled=1
    else
      connector_release_enabled=0
      connector_image_id=''
    fi
    if ((connector_release_enabled)); then
      write_pending_release_bundle \
        "$SHA" "$active_control_plane_image_id" \
        "$active_core_worker_tag" "$active_core_worker_image_id" \
        "$release_validator_tag" "$release_validator_image_id" \
        1 "$SHA" "$connector_image_id"
    else
      write_pending_release_bundle \
        "$SHA" "$active_control_plane_image_id" \
        "$active_core_worker_tag" "$active_core_worker_image_id" \
        "$release_validator_tag" "$release_validator_image_id" \
        0 '' ''
    fi
    ensure_postgres_ready_for_backup "$validator_image_id"
    backup_database
    migration_started=1
    compose_ops_run 180 migrate migrate
    activated=1
    start_core_stack
    check_control_plane
    check_core_workers
    verify_control_plane_image_tag "$SHA" "$active_control_plane_image_id"
    verify_workers_image_tag "$active_core_worker_tag" "$active_core_worker_image_id"
    if ((connector_release_enabled)); then
      start_connector_workers
      check_connector_workers
      verify_connector_workers_image_tag "$SHA" "$connector_image_id"
    else
      verify_services_absent connector-poll-scheduler connector-poll-runner
    fi
    promote_pending_release_bundle
    git checkout -q --detach "$SHA"
    [[ -z $(git status --porcelain --untracked-files=all) ]]
  fi

  finished=1
  if ! finalize_success_cleanup; then
    return 125
  fi
  activated=0

  echo "deploy: ok $SHA backup=$backup mode=$MODE control_plane=$SHA@$active_control_plane_image_id core_ops_workers=$active_core_worker_tag@$active_core_worker_image_id release_validator=$release_validator_tag@$release_validator_image_id connector_enabled=$connector_release_enabled connector_image=${connector_image_id:-disabled}"
  echo "deploy: code rollback='bash $ROOT/ops/aws/deploy.sh --rollback $previous'"
  echo 'deploy: database restore remains a separately approved locked operation; use ops/aws/restore.sh.'
}

load_release_state_library

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
