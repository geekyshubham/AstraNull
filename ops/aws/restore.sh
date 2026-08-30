#!/usr/bin/env bash
set -euo pipefail

ROOT=/opt/astranull
COMPOSE_FILE="$ROOT/ops/aws/docker-compose.yml"
ENV_FILE="$ROOT/ops/aws/.env"
BACKUP_DIR=/opt/astranull-backups
DEPLOY_STATE_DIR="$BACKUP_DIR/deploy-state"
CONTROL_PLANE_IMAGE_TAG_FILE="$DEPLOY_STATE_DIR/control-plane-image-tag"

MANIFEST=''
BACKUP=''
plain_host=''
succeeded=0
control_plane_tag=''
orchestration_tag=''
control_plane_image_id=''
worker_image_id=''

compose_timeout() {
  local duration=$1
  shift
  timeout -k 30 "$duration" docker compose --project-directory "$ROOT/ops/aws" \
    -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"
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

image_id_for_ref() {
  timeout -k 5 30 docker image inspect --format '{{.Id}}' "$1"
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

load_restore_image_identity() {
  orchestration_tag=$(git rev-parse HEAD)
  [[ "$orchestration_tag" =~ ^[0-9a-f]{40}$ ]] || {
    echo 'restore: current orchestration checkout is not an exact SHA' >&2
    return 1
  }
  control_plane_tag=$(read_control_plane_image_tag)
  control_plane_image_id=$(read_control_plane_image_id)

  # The tag is mutable and may have been clobbered by a same-SHA build. Resolve the
  # persisted immutable ID itself and repair the tag before inspecting worker semantics.
  # If control-plane and orchestration share a tag, workers intentionally follow the
  # now-rebound orchestration tag; hybrid releases keep their independent worker tag.
  rebind_control_plane_image_tag
  worker_image_id=$(image_id_for_ref "astranull-control-plane:$orchestration_tag") || {
    echo "restore: current worker image astranull-control-plane:$orchestration_tag is unavailable" >&2
    return 1
  }
  [[ "$worker_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo 'restore: current worker image identity is invalid' >&2
    return 1
  }

  export ASTRANULL_IMAGE_TAG="$orchestration_tag"
  export ASTRANULL_CONTROL_PLANE_IMAGE_TAG="$control_plane_tag"
  export ASTRANULL_WORKER_IMAGE_TAG="$orchestration_tag"
}

verify_service_image_tag() {
  local service=$1 expected_tag=$2 expected_image_id=$3
  local cid image_ref container_image_id tagged_image_id
  cid=$(compose_timeout 30 ps -q "$service")
  [[ -n "$cid" ]] || {
    echo "restore: $service has no running container" >&2
    return 1
  }
  image_ref=$(timeout -k 5 30 docker inspect --format '{{.Config.Image}}' "$cid")
  container_image_id=$(timeout -k 5 30 docker inspect --format '{{.Image}}' "$cid")
  [[ "$image_ref" == "astranull-control-plane:$expected_tag" ]] || {
    echo "restore: $service uses unexpected image $image_ref" >&2
    return 1
  }
  [[ "$container_image_id" == "$expected_image_id" ]] || {
    echo "restore: $service container did not use expected image ID $expected_image_id" >&2
    return 1
  }
  tagged_image_id=$(image_id_for_ref "astranull-control-plane:$expected_tag") || {
    echo "restore: $service expected image tag $expected_tag is unavailable" >&2
    return 1
  }
  [[ "$tagged_image_id" == "$expected_image_id" ]] || {
    echo "restore: $service tag $expected_tag changed before identity verification" >&2
    return 1
  }
}

verify_running_control_plane_state() {
  local cid
  cid=$(compose_timeout 30 ps -q control-plane)
  [[ -z "$cid" ]] || verify_service_image_tag control-plane "$control_plane_tag" "$control_plane_image_id"
}

verify_restored_image_identity() {
  local service
  verify_service_image_tag control-plane "$control_plane_tag" "$control_plane_image_id"
  for service in probe-worker password-recovery-worker test-policy-runner; do
    verify_service_image_tag "$service" "$orchestration_tag" "$worker_image_id"
  done
}

check_control_plane() {
  compose_timeout 30 exec -T control-plane node -e \
    "Promise.all(['/health','/ready'].map(p=>fetch('http://127.0.0.1:8080'+p,{signal:AbortSignal.timeout(10000)}).then(r=>{if(!r.ok)throw Error(p+' '+r.status)}))).catch(e=>{console.error(e.message);process.exit(1)})" \
    || return
  curl --fail --silent --show-error --max-time 20 --retry 8 --retry-delay 3 --retry-connrefused --retry-all-errors https://astranull.site/health >/dev/null \
    || return
}

check_workers() {
  local service cid health
  for service in probe-worker password-recovery-worker test-policy-runner; do
    cid=$(compose_timeout 30 ps -q "$service")
    [[ -n "$cid" ]] || { echo "restore: $service has no container" >&2; return 1; }
    health=$(timeout -k 5 30 docker inspect --format '{{.State.Health.Status}}' "$cid")
    [[ "$health" == healthy ]] || { echo "restore: $service health is $health" >&2; return 1; }
  done
}

cleanup() {
  local rc=$?
  trap - EXIT HUP INT TERM
  set +e
  [[ -z ${plain_host:-} ]] || rm -f -- "$plain_host"
  if (( ! succeeded )); then
    compose_timeout 120 stop caddy probe-worker password-recovery-worker test-policy-runner control-plane \
      >/dev/null 2>&1 || true
    echo 'restore: failed; runtime services remain stopped for operator investigation' >&2
  fi
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

  exec 9>/tmp/astranull-deploy.lock
  flock -n 9 || { echo 'restore: deployment or another restore is active' >&2; exit 1; }
  cd "$ROOT"
  [[ -f "$ENV_FILE" ]] || { echo "restore: missing $ENV_FILE" >&2; exit 1; }
  [[ -z $(git status --porcelain --untracked-files=all) ]] || {
    echo 'restore: repository has tracked or untracked changes; current orchestration SHA is not exact' >&2
    exit 1
  }

  load_restore_image_identity
  plain_host="$BACKUP_DIR/.restore-${orchestration_tag}-$$.dump"
  succeeded=0
  trap cleanup EXIT
  trap 'exit 130' HUP INT TERM

  compose_timeout 30 --profile ops config --format json \
    | timeout -k 5 30 node scripts/validate-aws-compose-secrets.mjs
  # A running stack must agree with persisted state before any destructive operation.
  # A fully stopped stack is allowed because the persisted immutable ID was resolved and
  # rebound to the control-plane tag above; a mutable tag alone is never trusted.
  verify_running_control_plane_state
  compose_timeout 120 stop caddy probe-worker password-recovery-worker test-policy-runner control-plane
  compose_timeout 90 --profile ops run --rm --no-deps \
    -u "$(id -u):$(id -g)" -v "$BACKUP_DIR:/backup" backup \
    node scripts/postgres-restore-drill.mjs \
    --manifest "/backup/${MANIFEST##*/}" --backup "/backup/${BACKUP##*/}" \
    --extract "/backup/${plain_host##*/}" --yes --out /tmp/restore-verification.json
  chmod 600 "$plain_host"

  # pg_restore --clean only removes objects named by the archive, so objects introduced
  # after an older backup survive and produce a hybrid schema. Connect through the
  # maintenance database, evict straggling sessions, and recreate the application database
  # from template0 before reading a single archive object. Any failure leaves writers and
  # ingress stopped for operator investigation.
  compose_timeout 90 exec -T postgres psql -U astranull -d postgres -v ON_ERROR_STOP=1 <<'SQL'
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE datname = 'astranull' AND pid <> pg_backend_pid();
DROP DATABASE IF EXISTS astranull WITH (FORCE);
CREATE DATABASE astranull WITH OWNER astranull TEMPLATE template0;
SQL

  compose_timeout 600 exec -T postgres pg_restore -U astranull -d astranull \
    --single-transaction --exit-on-error --no-owner --no-acl < "$plain_host"
  compose_timeout 180 --profile ops run --rm --no-deps migrate
  rm -f -- "$plain_host"
  compose_timeout 300 up -d --remove-orphans --wait --wait-timeout 240
  check_control_plane
  check_workers
  verify_restored_image_identity
  [[ "$(read_control_plane_image_tag)" == "$control_plane_tag" \
    && "$(read_control_plane_image_id)" == "$control_plane_image_id" ]] || {
    echo 'restore: persisted control-plane state changed during restore' >&2
    return 1
  }

  succeeded=1
  echo "restore: ok backup=$BACKUP control_plane=astranull-control-plane:$control_plane_tag@$control_plane_image_id orchestration_workers=$orchestration_tag worker_image=astranull-control-plane:$orchestration_tag@$worker_image_id"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
