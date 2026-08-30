#!/usr/bin/env bash
set -euo pipefail

ROOT=/opt/astranull
COMPOSE_REPO_PATH=ops/aws/docker-compose.yml
ENV_FILE="$ROOT/ops/aws/.env"
BACKUP_DIR=/opt/astranull-backups
DEPLOY_STATE_DIR="$BACKUP_DIR/deploy-state"
CONTROL_PLANE_IMAGE_TAG_FILE="$DEPLOY_STATE_DIR/control-plane-image-tag"

MODE=deploy
SHA=''
previous=''
previous_control_plane_tag=''
previous_control_plane_image_id=''
previous_compose=''
target_compose=''
ACTIVE_COMPOSE_FILE=''
plain_host=''
backup=''
activated=0
migration_started=0
finished=0

cleanup_compose_snapshots() {
  [[ -z ${previous_compose:-} ]] || rm -f -- "$previous_compose"
  [[ -z ${target_compose:-} ]] || rm -f -- "$target_compose"
}

compose_timeout() {
  local duration=$1
  shift
  timeout -k 30 "$duration" docker compose --project-directory "$ROOT/ops/aws" \
    -f "$ACTIVE_COMPOSE_FILE" --env-file "$ENV_FILE" "$@"
}

validate_compose() {
  # Render once and reject missing/reused credentials without printing them.
  compose_timeout 30 --profile ops config --format json \
    | timeout -k 5 30 node scripts/validate-aws-compose-secrets.mjs
}

postgres_volume_name() {
  compose_timeout 30 config --format json \
    | timeout -k 5 30 node -e '
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
  local postgres_cid volume_name volume_status
  postgres_cid=$(compose_timeout 30 ps --all -q postgres)
  if [[ -z "$postgres_cid" ]]; then
    volume_name=$(postgres_volume_name)
    if docker_volume_exists "$volume_name"; then
      echo "deploy: postgres data volume $volume_name exists without a service container; refusing target-compose bootstrap before backup" >&2
      return 1
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
  local fallback=$1 tag
  if ! control_plane_state_exists; then
    printf '%s\n' "$fallback"
    return
  fi
  [[ -f "$CONTROL_PLANE_IMAGE_TAG_FILE" && ! -L "$CONTROL_PLANE_IMAGE_TAG_FILE" ]] || {
    echo "deploy: invalid control-plane state file $CONTROL_PLANE_IMAGE_TAG_FILE" >&2
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
  local compatibility=${1:-} image_id line_count
  [[ -f "$CONTROL_PLANE_IMAGE_TAG_FILE" && ! -L "$CONTROL_PLANE_IMAGE_TAG_FILE" ]] || {
    echo "deploy: missing or invalid control-plane state file $CONTROL_PLANE_IMAGE_TAG_FILE" >&2
    return 1
  }
  line_count=$(awk 'END { print NR }' "$CONTROL_PLANE_IMAGE_TAG_FILE")
  if [[ "$line_count" == 1 && "$compatibility" == allow-legacy-tag-only ]]; then
    # One release bridges the former tag-only record after proving it against the
    # running container (or, for a stopped stack, the still-bound local tag).
    return 0
  fi
  [[ "$line_count" == 2 ]] || {
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

persist_control_plane_image_state() {
  local tag=$1 image_id=$2 temporary
  [[ "$tag" =~ ^[0-9a-f]{40}$ ]] || {
    echo 'deploy: refusing to persist a non-SHA control-plane image tag' >&2
    return 1
  }
  [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo 'deploy: refusing to persist an invalid control-plane image ID' >&2
    return 1
  }
  mkdir -p "$DEPLOY_STATE_DIR"
  chmod 700 "$DEPLOY_STATE_DIR"
  temporary=$(mktemp "$DEPLOY_STATE_DIR/.control-plane-image-state.XXXXXX")
  printf '%s\n%s\n' "$tag" "$image_id" > "$temporary"
  chmod 600 "$temporary"
  mv -f -- "$temporary" "$CONTROL_PLANE_IMAGE_TAG_FILE"
}

image_id_for_ref() {
  timeout -k 5 30 docker image inspect --format '{{.Id}}' "$1"
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

build_control_plane_from_commit() {
  local commit=$1
  # Build only the selected immutable archive. Keeping '-' as the context is required:
  # Docker consumes the archive from stdin rather than the orchestration checkout.
  timeout -k 10 120 git archive "$commit" \
    | timeout -k 30 480 docker build -f ops/aws/Dockerfile \
      -t "astranull-control-plane:$commit" -
}

prepare_previous_control_plane_image() {
  local tag=$1 ref control_plane_cid actual_image_id tagged_image_id persisted_image_id state_present=0
  ref="astranull-control-plane:$tag"
  if control_plane_state_exists; then
    state_present=1
    persisted_image_id=$(read_control_plane_image_id allow-legacy-tag-only)
  fi
  control_plane_cid=$(compose_timeout 30 ps --all -q control-plane)

  if [[ -n "$control_plane_cid" ]]; then
    actual_image_id=$(timeout -k 5 30 docker inspect --format '{{.Image}}' "$control_plane_cid")
    [[ "$actual_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
      echo 'deploy: running control-plane has an invalid image identity' >&2
      return 1
    }

    if ((state_present)) && [[ -n "$persisted_image_id" ]]; then
      [[ "$actual_image_id" == "$persisted_image_id" ]] || {
        echo 'deploy: persisted control-plane image ID does not match the running container' >&2
        return 1
      }
      rebind_control_plane_image_tag "$tag" "$persisted_image_id"
    elif ((state_present)); then
      tagged_image_id=$(image_id_for_ref "$ref") || {
        echo "deploy: legacy persisted control-plane image $ref is unavailable" >&2
        return 1
      }
      [[ "$tagged_image_id" == "$actual_image_id" ]] || {
        echo "deploy: legacy persisted control-plane tag $tag does not match the running image identity" >&2
        return 1
      }
    else
      # First upgrade bridge: the historical Compose has only `build:`. Alias the
      # immutable image used by the running container; never rebuild and guess it.
      timeout -k 5 30 docker image tag "$actual_image_id" "$ref"
      tagged_image_id=$(image_id_for_ref "$ref")
      [[ "$tagged_image_id" == "$actual_image_id" ]] || {
        echo 'deploy: could not preserve the running control-plane image identity' >&2
        return 1
      }
    fi
  elif ((state_present)) && [[ -n "$persisted_image_id" ]]; then
    # A stopped stack cannot prove identity through a container. Resolve the immutable
    # persisted ID itself, then repair the mutable tag before it can be activated.
    rebind_control_plane_image_tag "$tag" "$persisted_image_id"
    actual_image_id=$persisted_image_id
  elif ((state_present)); then
    actual_image_id=$(image_id_for_ref "$ref") || {
      echo "deploy: legacy persisted control-plane image $ref is unavailable" >&2
      return 1
    }
  else
    # A fresh host has no image to preserve. Build the previous exact commit solely as
    # a fail-safe rollback candidate; this does not start services or touch Postgres.
    build_control_plane_from_commit "$tag"
    actual_image_id=$(image_id_for_ref "$ref")
  fi

  [[ "$actual_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo 'deploy: previous control-plane image identity is invalid' >&2
    return 1
  }
  previous_control_plane_image_id=$actual_image_id
}

verify_service_image_tag() {
  local service=$1 expected=$2 preserved_image_id=${3:-}
  local cid image_ref container_image_id tagged_image_id
  cid=$(compose_timeout 30 ps -q "$service")
  [[ -n "$cid" ]] || {
    echo "deploy: $service has no container" >&2
    return 1
  }
  image_ref=$(timeout -k 5 30 docker inspect --format '{{.Config.Image}}' "$cid")
  container_image_id=$(timeout -k 5 30 docker inspect --format '{{.Image}}' "$cid")
  tagged_image_id=$(image_id_for_ref "astranull-control-plane:$expected") || {
    echo "deploy: $service expected image tag $expected is unavailable" >&2
    return 1
  }
  [[ "$image_ref" == "astranull-control-plane:$expected" ]] || {
    echo "deploy: $service uses unexpected image $image_ref" >&2
    return 1
  }
  [[ "$container_image_id" == "$tagged_image_id" ]] || {
    echo "deploy: $service container image identity does not match tag $expected" >&2
    return 1
  }
  if [[ -n "$preserved_image_id" && "$container_image_id" != "$preserved_image_id" ]]; then
    echo "deploy: $service did not restore the preserved image identity" >&2
    return 1
  fi
}

verify_control_plane_image_tag() {
  verify_service_image_tag control-plane "$1" "${2:-}"
}

verify_workers_image_tag() {
  local expected=$1 service
  for service in probe-worker password-recovery-worker test-policy-runner; do
    verify_service_image_tag "$service" "$expected"
  done
}

check_control_plane() {
  compose_timeout 30 exec -T control-plane node -e "Promise.all(['/health','/ready'].map(p=>fetch('http://127.0.0.1:8080'+p,{signal:AbortSignal.timeout(10000)}).then(r=>{if(!r.ok)throw Error(p+' '+r.status)}))).catch(e=>{console.error(e.message);process.exit(1)})" \
    || return
  curl --fail --silent --show-error --max-time 20 --retry 8 --retry-delay 3 --retry-connrefused --retry-all-errors https://astranull.site/health >/dev/null \
    || return
}

check_workers() {
  local service cid health
  for service in probe-worker password-recovery-worker test-policy-runner; do
    cid=$(compose_timeout 30 ps -q "$service")
    [[ -n "$cid" ]] || { echo "deploy: $service has no container" >&2; return 1; }
    health=$(timeout -k 5 30 docker inspect --format '{{.State.Health.Status}}' "$cid")
    [[ "$health" == healthy ]] || { echo "deploy: $service health is $health" >&2; return 1; }
  done
}

prune_backups() {
  local backups=() old
  shopt -s nullglob
  backups=("$BACKUP_DIR"/*.dump.enc)
  if ((${#backups[@]} > 10)); then
    while IFS= read -r old; do rm -f -- "$old" "$old.manifest.json"; done \
      < <(printf '%s\n' "${backups[@]}" | sort -r | tail -n +11)
  fi
  shopt -u nullglob
}

backup_database() {
  local backup_output backup_container_path plain_name
  plain_name=${plain_host##*/}
  compose_timeout 90 --profile ops run --rm --no-deps backup-role-bootstrap
  compose_timeout 180 --profile ops run --rm --no-deps \
    -u "$(id -u):$(id -g)" -v "$BACKUP_DIR:/backup" backup-dump \
    sh -eu -c 'umask 077; exec pg_dump --format=custom --no-owner --no-acl --dbname="$ASTRANULL_BACKUP_DATABASE_URL" --file="$1"' \
    sh "/backup/$plain_name"
  [[ -s "$plain_host" ]]
  chmod 600 "$plain_host"
  backup_output=$(compose_timeout 180 --profile ops run --rm --no-deps \
    -u "$(id -u):$(id -g)" -v "$BACKUP_DIR:/backup" backup \
    node scripts/postgres-backup.mjs \
    --input "/backup/$plain_name" --out /backup --label "predeploy-${previous:0:12}" \
    --database-host postgres --database-port 5432 --database-name astranull)
  rm -f -- "$plain_host"
  backup_container_path=$(printf '%s\n' "$backup_output" | sed -n 's/^  backup: //p' | tail -1)
  [[ "$backup_container_path" == /backup/*.dump.enc ]]
  backup="$BACKUP_DIR/${backup_container_path##*/}"
  [[ -s "$backup" && -s "$backup.manifest.json" ]]
  chmod 600 "$backup" "$backup.manifest.json"
  compose_timeout 180 --profile ops run --rm --no-deps \
    -u "$(id -u):$(id -g)" -v "$BACKUP_DIR:/backup:ro" backup \
    node scripts/postgres-restore-drill.mjs \
    --manifest "/backup/${backup##*/}.manifest.json" --backup "/backup/${backup##*/}" --validate-only
  prune_backups
}

rollback_on_error() {
  local rc=${1:-1} rollback_compose rollback_orchestration_tag
  ((rc != 0)) || rc=1
  trap - ERR INT TERM HUP EXIT
  set +e

  if ((activated)); then
    if [[ "$MODE" == rollback ]]; then
      rollback_compose=$previous_compose
      rollback_orchestration_tag=$previous
    else
      # Once a target migration/activation has begun, retain the tested target Compose
      # and workers. Only the control-plane returns to its exact predeploy image.
      rollback_compose=$target_compose
      rollback_orchestration_tag=$SHA
    fi
  else
    rollback_compose=$previous_compose
    rollback_orchestration_tag=$previous
  fi
  ACTIVE_COMPOSE_FILE=$rollback_compose

  [[ -z ${plain_host:-} ]] || rm -f -- "$plain_host"

  if ((activated)); then
    export ASTRANULL_IMAGE_TAG="$rollback_orchestration_tag"
    export ASTRANULL_CONTROL_PLANE_IMAGE_TAG="$previous_control_plane_tag"
    export ASTRANULL_WORKER_IMAGE_TAG="$rollback_orchestration_tag"
    if ! git checkout -q --detach "$rollback_orchestration_tag"; then
      echo "deploy: automatic hybrid rollback could not restore orchestration checkout $rollback_orchestration_tag; encrypted database backup is $backup" >&2
    elif ! rebind_control_plane_image_tag "$previous_control_plane_tag" "$previous_control_plane_image_id"; then
      echo "deploy: automatic hybrid rollback could not rebind the preserved control-plane image; encrypted database backup is $backup" >&2
    elif ! compose_timeout 300 up -d --remove-orphans --wait --wait-timeout 240; then
      echo "deploy: automatic hybrid rollback failed; encrypted database backup is $backup" >&2
    elif ! check_control_plane || ! check_workers; then
      echo "deploy: hybrid rollback stack failed health checks; encrypted database backup is $backup" >&2
    elif ! verify_control_plane_image_tag "$previous_control_plane_tag" "$previous_control_plane_image_id" \
      || ! verify_workers_image_tag "$rollback_orchestration_tag" \
      || ! persist_control_plane_image_state "$previous_control_plane_tag" "$previous_control_plane_image_id"; then
      echo "deploy: hybrid rollback image identity could not be verified or persisted; encrypted database backup is $backup" >&2
    else
      echo "deploy: automatic hybrid rollback restored control-plane $previous_control_plane_tag@$previous_control_plane_image_id with orchestration/workers $rollback_orchestration_tag; database was not downgraded; encrypted backup is $backup" >&2
    fi
  else
    if [[ -n "$previous_control_plane_tag" && -n "$previous_control_plane_image_id" ]] \
      && ! rebind_control_plane_image_tag "$previous_control_plane_tag" "$previous_control_plane_image_id"; then
      echo 'deploy: failed before service activation and could not restore the preserved control-plane tag identity' >&2
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
  cleanup_compose_snapshots
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

main() {
  MODE=deploy
  if [[ ${1:-} == --rollback ]]; then MODE=rollback; shift; fi
  SHA=${1:-}
  [[ "$SHA" =~ ^[0-9a-f]{40}$ ]] || { echo 'deploy: exact 40-char SHA required' >&2; exit 1; }

  exec 9>/tmp/astranull-deploy.lock
  flock -n 9 || { echo 'deploy: another deployment or restore is active' >&2; exit 1; }
  cd "$ROOT"
  [[ -f "$ENV_FILE" ]] || { echo "deploy: missing $ENV_FILE" >&2; exit 1; }
  local env_mode env_owner remote_main stamp active_control_plane_image_id
  env_mode=$(stat -c '%a' "$ENV_FILE")
  env_owner=$(stat -c '%u' "$ENV_FILE")
  [[ "$env_mode" =~ ^[46]00$ ]] || { echo "deploy: $ENV_FILE must have mode 400 or 600" >&2; exit 1; }
  [[ "$env_owner" == "0" || "$env_owner" == "$(id -u)" ]] || { echo "deploy: $ENV_FILE must be owned by root or the deploy user" >&2; exit 1; }
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

  # Keep immutable Compose inputs for both sides of the release boundary. A normal
  # release uses target_compose; previous_compose remains for pre-activation cleanup
  # and for explicit rollback's current-orchestration boundary.
  previous_compose=$(mktemp /tmp/astranull-compose.previous.XXXXXX.yml)
  target_compose=$(mktemp /tmp/astranull-compose.target.XXXXXX.yml)
  trap cleanup_compose_snapshots EXIT
  git show "$previous:$COMPOSE_REPO_PATH" > "$previous_compose"
  git show "$SHA:$COMPOSE_REPO_PATH" > "$target_compose"
  chmod 600 "$previous_compose" "$target_compose"
  ACTIVE_COMPOSE_FILE="$previous_compose"

  mkdir -p "$BACKUP_DIR"
  chmod 700 "$BACKUP_DIR"
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  plain_host="$BACKUP_DIR/.${stamp}-${previous}.dump"
  backup=''
  activated=0
  migration_started=0
  finished=0
  previous_control_plane_image_id=''
  install_failure_traps
  previous_control_plane_tag=$(read_control_plane_image_tag "$previous")
  prepare_previous_control_plane_image "$previous_control_plane_tag"
  persist_control_plane_image_state "$previous_control_plane_tag" "$previous_control_plane_image_id"

  if [[ "$MODE" == rollback ]]; then
    # Explicit rollback retains the current release's Compose/worker contract and
    # checkout, swapping only the control-plane image built from the selected ancestor.
    ACTIVE_COMPOSE_FILE="$previous_compose"
    export ASTRANULL_IMAGE_TAG="$previous"
    export ASTRANULL_CONTROL_PLANE_IMAGE_TAG="$previous_control_plane_tag"
    export ASTRANULL_WORKER_IMAGE_TAG="$previous"
    validate_compose
    backup_database
    build_control_plane_from_commit "$SHA"
    export ASTRANULL_CONTROL_PLANE_IMAGE_TAG="$SHA"
    activated=1
    compose_timeout 300 up -d --remove-orphans --wait --wait-timeout 240
    check_control_plane
    check_workers
    active_control_plane_image_id=$(image_id_for_ref "astranull-control-plane:$SHA")
    verify_control_plane_image_tag "$SHA" "$active_control_plane_image_id"
    verify_workers_image_tag "$previous"
    persist_control_plane_image_state "$SHA" "$active_control_plane_image_id"
  else
    git checkout -q --detach "$SHA"
    [[ -z $(git status --porcelain --untracked-files=all) ]]
    ACTIVE_COMPOSE_FILE="$target_compose"
    export ASTRANULL_IMAGE_TAG="$SHA"
    export ASTRANULL_CONTROL_PLANE_IMAGE_TAG="$SHA"
    export ASTRANULL_WORKER_IMAGE_TAG="$SHA"
    validate_compose
    build_control_plane_from_commit "$SHA"
    ensure_postgres_ready_for_backup
    backup_database
    migration_started=1
    compose_timeout 180 --profile ops run --rm --no-deps migrate
    activated=1
    compose_timeout 300 up -d --remove-orphans --wait --wait-timeout 240
    check_control_plane
    check_workers
    active_control_plane_image_id=$(image_id_for_ref "astranull-control-plane:$SHA")
    verify_control_plane_image_tag "$SHA" "$active_control_plane_image_id"
    verify_workers_image_tag "$SHA"
    persist_control_plane_image_state "$SHA" "$active_control_plane_image_id"
  fi

  finished=1
  clear_failure_traps
  activated=0
  cleanup_compose_snapshots
  timeout -k 5 30 docker image prune -f >/dev/null || echo 'deploy: image prune timed out (non-fatal)' >&2

  echo "deploy: ok $SHA backup=$backup mode=$MODE control_plane=$SHA@$active_control_plane_image_id orchestration_workers=$(git rev-parse HEAD)"
  echo "deploy: code rollback='bash $ROOT/ops/aws/deploy.sh --rollback $previous'"
  echo 'deploy: database restore remains a separately approved locked operation; use ops/aws/restore.sh.'
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
