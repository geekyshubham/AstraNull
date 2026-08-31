# Shared by deploy.sh and restore.sh. The caller supplies STATE_LOG_PREFIX,
# DEPLOY_STATE_DIR, compatibility projection paths, Compose helpers, and health checks.
# This file is sourced; do not enable or change the caller's shell options here.

RELEASE_BUNDLE_SCHEMA=astranull.release-image-bundle
RELEASE_BUNDLE_VERSION=1
CURRENT_RELEASE_BUNDLE_FILE="$DEPLOY_STATE_DIR/release-image-current"
PENDING_RELEASE_BUNDLE_FILE="$DEPLOY_STATE_DIR/release-image-pending"
release_state_preactivation_pending=0

release_state_error() {
  printf '%s: %s\n' "$STATE_LOG_PREFIX" "$*" >&2
}

release_state_mode() {
  stat -c '%a' -- "$1" 2>/dev/null || stat -f '%Lp' "$1"
}

release_state_owner() {
  stat -c '%u' -- "$1" 2>/dev/null || stat -f '%u' "$1"
}

release_state_links() {
  stat -c '%h' -- "$1" 2>/dev/null || stat -f '%l' "$1"
}

ensure_release_state_dir() {
  local mode owner
  [[ ! -L "$DEPLOY_STATE_DIR" ]] || {
    release_state_error "refusing symlinked deployment state directory $DEPLOY_STATE_DIR"
    return 1
  }
  mkdir -p -- "$DEPLOY_STATE_DIR" || {
    release_state_error "could not create deployment state directory $DEPLOY_STATE_DIR"
    return 1
  }
  [[ -d "$DEPLOY_STATE_DIR" && ! -L "$DEPLOY_STATE_DIR" ]] || {
    release_state_error "deployment state path is not a regular directory: $DEPLOY_STATE_DIR"
    return 1
  }
  chmod 700 "$DEPLOY_STATE_DIR" || {
    release_state_error 'could not set deployment state directory mode 0700'
    return 1
  }
  mode=$(release_state_mode "$DEPLOY_STATE_DIR") || return
  owner=$(release_state_owner "$DEPLOY_STATE_DIR") || return
  [[ "$mode" == 700 && ( "$owner" == 0 || "$owner" == "$(id -u)" ) ]] || {
    release_state_error 'deployment state directory must be mode 0700 and owned by root or the deploy user'
    return 1
  }
}

release_state_validate_regular_file() {
  local file=$1 label=$2 mode owner links
  [[ -f "$file" && ! -L "$file" ]] || {
    release_state_error "$label is missing, non-regular, or symlinked: $file"
    return 1
  }
  mode=$(release_state_mode "$file") || return
  owner=$(release_state_owner "$file") || return
  links=$(release_state_links "$file") || return
  [[ "$mode" == 600 && ( "$owner" == 0 || "$owner" == "$(id -u)" ) && "$links" == 1 ]] || {
    release_state_error "$label must be mode 0600, singly linked, and owned by root or the deploy user: $file"
    return 1
  }
}

release_state_cleanup_temp_checked() {
  local temporary=${1:-} label=${2:-release-state} failed=0
  [[ -n "$temporary" ]] || return 0
  if [[ -e "$temporary" || -L "$temporary" ]]; then
    if ! rm -f -- "$temporary"; then
      release_state_error "WARNING: could not remove temporary $label file $temporary"
      failed=1
    fi
  fi
  if [[ -e "$temporary" || -L "$temporary" ]]; then
    release_state_error "CRITICAL: temporary $label file still exists at $temporary"
    failed=1
  fi
  ((failed == 0))
}

# fsync the source and parent directory, atomically replace, then fsync the parent again.
# Directory fsync is skipped only when the local filesystem explicitly does not support it.
release_state_atomic_rename() {
  local source=$1 destination=$2
  python3 - "$source" "$destination" <<'PY'
import errno
import os
import stat
import sys

source, destination = sys.argv[1:]
parent = os.path.dirname(destination) or '.'
if os.path.dirname(source) != parent:
    raise SystemExit('release-state: source and destination must share one directory')
source_stat = os.lstat(source)
if not stat.S_ISREG(source_stat.st_mode) or source_stat.st_nlink != 1:
    raise SystemExit('release-state: atomic source must be a singly linked regular file')
if os.path.lexists(destination):
    destination_stat = os.lstat(destination)
    if not stat.S_ISREG(destination_stat.st_mode) or destination_stat.st_nlink != 1:
        raise SystemExit('release-state: refusing to replace an unsafe destination')
source_fd = os.open(source, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
try:
    os.fsync(source_fd)
finally:
    os.close(source_fd)
dir_fd = os.open(parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
try:
    try:
        os.fsync(dir_fd)
    except OSError as error:
        if error.errno not in (errno.EINVAL, errno.ENOTSUP, errno.EPERM):
            raise
    os.replace(source, destination)
    try:
        os.fsync(dir_fd)
    except OSError as error:
        if error.errno not in (errno.EINVAL, errno.ENOTSUP, errno.EPERM):
            raise
finally:
    os.close(dir_fd)
PY
}

release_state_durable_remove() {
  local target=$1 label=${2:-release-state}
  python3 - "$target" "$label" <<'PY'
import errno
import os
import stat
import sys

target, label = sys.argv[1:]
parent = os.path.dirname(target) or '.'
if not os.path.lexists(target):
    raise SystemExit(0)
target_stat = os.lstat(target)
if not stat.S_ISREG(target_stat.st_mode) or target_stat.st_nlink != 1:
    raise SystemExit(f'release-state: refusing to remove unsafe {label}: {target}')
os.unlink(target)
dir_fd = os.open(parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
try:
    try:
        os.fsync(dir_fd)
    except OSError as error:
        if error.errno not in (errno.EINVAL, errno.ENOTSUP, errno.EPERM):
            raise
finally:
    os.close(dir_fd)
PY
  [[ ! -e "$target" && ! -L "$target" ]] || {
    release_state_error "$label still exists after durable removal: $target"
    return 1
  }
}

release_bundle_load() {
  local file=$1 line_count
  local schema_line version_line control_tag_line control_id_line
  local core_tag_line core_id_line validator_tag_line validator_id_line
  local connector_enabled_line connector_tag_line connector_id_line
  release_state_validate_regular_file "$file" 'release-image bundle' || return
  line_count=$(awk 'END { print NR }' "$file") || return
  [[ "$line_count" == 11 ]] || {
    release_state_error "release-image bundle must contain exactly 11 ordered fields: $file"
    return 1
  }
  {
    IFS= read -r schema_line
    IFS= read -r version_line
    IFS= read -r control_tag_line
    IFS= read -r control_id_line
    IFS= read -r core_tag_line
    IFS= read -r core_id_line
    IFS= read -r validator_tag_line
    IFS= read -r validator_id_line
    IFS= read -r connector_enabled_line
    IFS= read -r connector_tag_line
    IFS= read -r connector_id_line
  } < "$file"
  [[ "$schema_line" == "schema=$RELEASE_BUNDLE_SCHEMA" \
    && "$version_line" == "version=$RELEASE_BUNDLE_VERSION" \
    && "$control_tag_line" == control_tag=* \
    && "$control_id_line" == control_image_id=* \
    && "$core_tag_line" == core_tag=* \
    && "$core_id_line" == core_image_id=* \
    && "$validator_tag_line" == validator_tag=* \
    && "$validator_id_line" == validator_image_id=* \
    && "$connector_enabled_line" == connector_enabled=* \
    && "$connector_tag_line" == connector_tag=* \
    && "$connector_id_line" == connector_image_id=* ]] || {
    release_state_error "release-image bundle schema/order is invalid: $file"
    return 1
  }
  release_bundle_control_tag=${control_tag_line#control_tag=}
  release_bundle_control_image_id=${control_id_line#control_image_id=}
  release_bundle_core_tag=${core_tag_line#core_tag=}
  release_bundle_core_image_id=${core_id_line#core_image_id=}
  release_bundle_validator_tag=${validator_tag_line#validator_tag=}
  release_bundle_validator_image_id=${validator_id_line#validator_image_id=}
  release_bundle_connector_enabled=${connector_enabled_line#connector_enabled=}
  release_bundle_connector_tag=${connector_tag_line#connector_tag=}
  release_bundle_connector_image_id=${connector_id_line#connector_image_id=}
  [[ "$release_bundle_control_tag" =~ ^[0-9a-f]{40}$ \
    && "$release_bundle_control_image_id" =~ ^sha256:[0-9a-f]{64}$ \
    && "$release_bundle_core_tag" =~ ^[0-9a-f]{40}$ \
    && "$release_bundle_core_image_id" =~ ^sha256:[0-9a-f]{64}$ \
    && "$release_bundle_validator_tag" =~ ^[0-9a-f]{40}$ \
    && "$release_bundle_validator_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    release_state_error "release-image bundle contains an invalid required identity: $file"
    return 1
  }
  case "$release_bundle_connector_enabled" in
    0)
      [[ -z "$release_bundle_connector_tag" && -z "$release_bundle_connector_image_id" ]] || {
        release_state_error 'disabled connector bundle fields must be empty'
        return 1
      }
      ;;
    1)
      [[ "$release_bundle_connector_tag" =~ ^[0-9a-f]{40}$ \
        && "$release_bundle_connector_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
        release_state_error 'enabled connector bundle fields must contain an exact tag and image ID'
        return 1
      }
      ;;
    *)
      release_state_error 'release-image bundle connector_enabled must be 0 or 1'
      return 1
      ;;
  esac
}

write_release_bundle_atomic() {
  local destination=$1 control_tag=$2 control_id=$3 core_tag=$4 core_id=$5
  local validator_tag=$6 validator_id=$7 connector_enabled=$8 connector_tag=${9:-}
  local connector_id=${10:-} temporary=''
  [[ "$control_tag" =~ ^[0-9a-f]{40}$ && "$control_id" =~ ^sha256:[0-9a-f]{64}$ \
    && "$core_tag" =~ ^[0-9a-f]{40}$ && "$core_id" =~ ^sha256:[0-9a-f]{64}$ \
    && "$validator_tag" =~ ^[0-9a-f]{40}$ && "$validator_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    release_state_error 'refusing to persist a release bundle with an invalid required identity'
    return 1
  }
  case "$connector_enabled" in
    0) [[ -z "$connector_tag" && -z "$connector_id" ]] || return 1 ;;
    1) [[ "$connector_tag" =~ ^[0-9a-f]{40}$ && "$connector_id" =~ ^sha256:[0-9a-f]{64}$ ]] || return 1 ;;
    *) return 1 ;;
  esac
  ensure_release_state_dir || return
  if [[ -e "$destination" || -L "$destination" ]]; then
    release_state_validate_regular_file "$destination" 'existing release-image bundle' || return
  fi
  temporary=$(umask 077; mktemp "$DEPLOY_STATE_DIR/.${destination##*/}.XXXXXX") || {
    release_state_error 'could not create a private release-bundle temporary file'
    return 1
  }
  if ! printf '%s\n' \
    "schema=$RELEASE_BUNDLE_SCHEMA" \
    "version=$RELEASE_BUNDLE_VERSION" \
    "control_tag=$control_tag" \
    "control_image_id=$control_id" \
    "core_tag=$core_tag" \
    "core_image_id=$core_id" \
    "validator_tag=$validator_tag" \
    "validator_image_id=$validator_id" \
    "connector_enabled=$connector_enabled" \
    "connector_tag=$connector_tag" \
    "connector_image_id=$connector_id" > "$temporary"; then
    release_state_cleanup_temp_checked "$temporary" release-bundle || return 125
    return 1
  fi
  chmod 600 "$temporary" || {
    release_state_cleanup_temp_checked "$temporary" release-bundle || return 125
    return 1
  }
  release_bundle_load "$temporary" || {
    release_state_cleanup_temp_checked "$temporary" release-bundle || return 125
    return 1
  }
  if ! release_state_atomic_rename "$temporary" "$destination"; then
    release_state_error "could not durably install release-image bundle $destination"
    release_state_cleanup_temp_checked "$temporary" release-bundle || return 125
    return 1
  fi
  if [[ -e "$temporary" || -L "$temporary" ]]; then
    release_state_error 'release-bundle atomic rename reported success without consuming its source'
    release_state_cleanup_temp_checked "$temporary" release-bundle || return 125
    return 1
  fi
  temporary=''
  release_bundle_load "$destination"
}

write_pending_release_bundle() {
  write_release_bundle_atomic "$PENDING_RELEASE_BUNDLE_FILE" "$@"
}

write_current_release_bundle_for_migration() {
  [[ ! -e "$CURRENT_RELEASE_BUNDLE_FILE" && ! -L "$CURRENT_RELEASE_BUNDLE_FILE" ]] || {
    release_state_error 'refusing legacy migration because canonical current state already exists'
    return 1
  }
  write_release_bundle_atomic "$CURRENT_RELEASE_BUNDLE_FILE" "$@" || return
  regenerate_release_state_projections
}

canonical_release_bundle_exists() {
  [[ -e "$CURRENT_RELEASE_BUNDLE_FILE" || -L "$CURRENT_RELEASE_BUNDLE_FILE" ]]
}

pending_release_bundle_exists() {
  [[ -e "$PENDING_RELEASE_BUNDLE_FILE" || -L "$PENDING_RELEASE_BUNDLE_FILE" ]]
}

legacy_image_state_read() {
  local file=$1 field=$2 label=$3 line_count value
  [[ -f "$file" && ! -L "$file" ]] || {
    release_state_error "missing or invalid compatibility $label state $file"
    return 1
  }
  line_count=$(awk 'END { print NR }' "$file") || return
  [[ "$line_count" == 2 ]] || {
    release_state_error "compatibility $label state must contain exactly tag and image ID"
    return 1
  }
  case "$field" in
    tag) IFS= read -r value < "$file"; [[ "$value" =~ ^[0-9a-f]{40}$ ]] ;;
    image_id) value=$(sed -n '2p' "$file"); [[ "$value" =~ ^sha256:[0-9a-f]{64}$ ]] ;;
    *) return 1 ;;
  esac || {
    release_state_error "compatibility $label $field is invalid"
    return 1
  }
  printf '%s\n' "$value"
}

control_plane_state_exists() {
  canonical_release_bundle_exists || [[ -e "$CONTROL_PLANE_IMAGE_TAG_FILE" || -L "$CONTROL_PLANE_IMAGE_TAG_FILE" ]]
}

read_control_plane_image_tag() {
  if canonical_release_bundle_exists; then release_bundle_load "$CURRENT_RELEASE_BUNDLE_FILE" || return; printf '%s\n' "$release_bundle_control_tag";
  else legacy_image_state_read "$CONTROL_PLANE_IMAGE_TAG_FILE" tag control-plane; fi
}

read_control_plane_image_id() {
  if canonical_release_bundle_exists; then release_bundle_load "$CURRENT_RELEASE_BUNDLE_FILE" || return; printf '%s\n' "$release_bundle_control_image_id";
  else legacy_image_state_read "$CONTROL_PLANE_IMAGE_TAG_FILE" image_id control-plane; fi
}

core_worker_image_state_exists() {
  canonical_release_bundle_exists || [[ -e "$CORE_WORKER_IMAGE_STATE_FILE" || -L "$CORE_WORKER_IMAGE_STATE_FILE" ]]
}

read_core_worker_image_tag() {
  if canonical_release_bundle_exists; then release_bundle_load "$CURRENT_RELEASE_BUNDLE_FILE" || return; printf '%s\n' "$release_bundle_core_tag";
  else legacy_image_state_read "$CORE_WORKER_IMAGE_STATE_FILE" tag core/ops-worker; fi
}

read_core_worker_image_id() {
  if canonical_release_bundle_exists; then release_bundle_load "$CURRENT_RELEASE_BUNDLE_FILE" || return; printf '%s\n' "$release_bundle_core_image_id";
  else legacy_image_state_read "$CORE_WORKER_IMAGE_STATE_FILE" image_id core/ops-worker; fi
}

connector_image_state_exists() {
  if canonical_release_bundle_exists; then
    release_bundle_load "$CURRENT_RELEASE_BUNDLE_FILE" || return
    [[ "$release_bundle_connector_enabled" == 1 ]]
  else
    [[ -e "$CONNECTOR_IMAGE_STATE_FILE" || -L "$CONNECTOR_IMAGE_STATE_FILE" ]]
  fi
}

read_connector_image_tag() {
  if canonical_release_bundle_exists; then
    release_bundle_load "$CURRENT_RELEASE_BUNDLE_FILE" || return
    [[ "$release_bundle_connector_enabled" == 1 ]] || { release_state_error 'canonical connectors are disabled'; return 1; }
    printf '%s\n' "$release_bundle_connector_tag"
  else
    legacy_image_state_read "$CONNECTOR_IMAGE_STATE_FILE" tag connector
  fi
}

read_connector_image_id() {
  if canonical_release_bundle_exists; then
    release_bundle_load "$CURRENT_RELEASE_BUNDLE_FILE" || return
    [[ "$release_bundle_connector_enabled" == 1 ]] || { release_state_error 'canonical connectors are disabled'; return 1; }
    printf '%s\n' "$release_bundle_connector_image_id"
  else
    legacy_image_state_read "$CONNECTOR_IMAGE_STATE_FILE" image_id connector
  fi
}

release_validator_image_state_exists() {
  canonical_release_bundle_exists || [[ -e "$RELEASE_VALIDATOR_IMAGE_STATE_FILE" || -L "$RELEASE_VALIDATOR_IMAGE_STATE_FILE" ]]
}

read_release_validator_image_tag() {
  if canonical_release_bundle_exists; then release_bundle_load "$CURRENT_RELEASE_BUNDLE_FILE" || return; printf '%s\n' "$release_bundle_validator_tag";
  else legacy_image_state_read "$RELEASE_VALIDATOR_IMAGE_STATE_FILE" tag release-validator; fi
}

read_release_validator_image_id() {
  if canonical_release_bundle_exists; then release_bundle_load "$CURRENT_RELEASE_BUNDLE_FILE" || return; printf '%s\n' "$release_bundle_validator_image_id";
  else legacy_image_state_read "$RELEASE_VALIDATOR_IMAGE_STATE_FILE" image_id release-validator; fi
}

# Compatibility projections are never authoritative. They are atomically regenerated
# from canonical current state and may be safely repaired after any process interruption.
persist_image_state_atomic() {
  local label=$1 destination=$2 tag=$3 image_id=$4 temporary=''
  [[ "$tag" =~ ^[0-9a-f]{40}$ && "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    release_state_error "refusing to project invalid $label image identity"
    return 1
  }
  ensure_release_state_dir || return
  if [[ -e "$destination" || -L "$destination" ]]; then
    release_state_validate_regular_file "$destination" "existing $label compatibility projection" || return
  fi
  temporary=$(umask 077; mktemp "$DEPLOY_STATE_DIR/.${destination##*/}.XXXXXX") || return
  if ! printf '%s\n%s\n' "$tag" "$image_id" > "$temporary" \
    || ! chmod 600 "$temporary" \
    || ! release_state_validate_regular_file "$temporary" "temporary $label compatibility projection" \
    || ! release_state_atomic_rename "$temporary" "$destination"; then
    release_state_cleanup_temp_checked "$temporary" "$label projection" || return 125
    return 1
  fi
  if [[ -e "$temporary" || -L "$temporary" ]]; then
    release_state_error "$label projection atomic rename reported success without consuming its source"
    release_state_cleanup_temp_checked "$temporary" "$label projection" || return 125
    return 1
  fi
  temporary=''
  [[ "$(legacy_image_state_read "$destination" tag "$label")" == "$tag" \
    && "$(legacy_image_state_read "$destination" image_id "$label")" == "$image_id" ]]
}

persist_control_plane_image_state() { persist_image_state_atomic control-plane "$CONTROL_PLANE_IMAGE_TAG_FILE" "$1" "$2"; }
persist_core_worker_image_state() { persist_image_state_atomic core/ops-worker "$CORE_WORKER_IMAGE_STATE_FILE" "$1" "$2"; }
persist_connector_image_state() { persist_image_state_atomic connector "$CONNECTOR_IMAGE_STATE_FILE" "$1" "$2"; }
persist_release_validator_image_state() { persist_image_state_atomic release-validator "$RELEASE_VALIDATOR_IMAGE_STATE_FILE" "$1" "$2"; }

clear_connector_image_state() {
  if [[ -e "$CONNECTOR_IMAGE_STATE_FILE" || -L "$CONNECTOR_IMAGE_STATE_FILE" ]]; then
    release_state_validate_regular_file "$CONNECTOR_IMAGE_STATE_FILE" 'connector compatibility projection' || return
    release_state_durable_remove "$CONNECTOR_IMAGE_STATE_FILE" 'connector compatibility projection' || return
  fi
  [[ ! -e "$CONNECTOR_IMAGE_STATE_FILE" && ! -L "$CONNECTOR_IMAGE_STATE_FILE" ]]
}

regenerate_release_state_projections() {
  canonical_release_bundle_exists || return 0
  release_bundle_load "$CURRENT_RELEASE_BUNDLE_FILE" || return
  local control_tag=$release_bundle_control_tag control_id=$release_bundle_control_image_id
  local core_tag=$release_bundle_core_tag core_id=$release_bundle_core_image_id
  local validator_tag=$release_bundle_validator_tag validator_id=$release_bundle_validator_image_id
  local connector_enabled=$release_bundle_connector_enabled
  local connector_tag=$release_bundle_connector_tag connector_id=$release_bundle_connector_image_id
  persist_control_plane_image_state "$control_tag" "$control_id" || return
  persist_core_worker_image_state "$core_tag" "$core_id" || return
  persist_release_validator_image_state "$validator_tag" "$validator_id" || return
  if [[ "$connector_enabled" == 1 ]]; then
    persist_connector_image_state "$connector_tag" "$connector_id"
  else
    clear_connector_image_state
  fi
}

promote_pending_release_bundle() {
  pending_release_bundle_exists || {
    release_state_error 'cannot promote release state without a pending bundle'
    return 1
  }
  release_bundle_load "$PENDING_RELEASE_BUNDLE_FILE" || return
  if [[ -e "$CURRENT_RELEASE_BUNDLE_FILE" || -L "$CURRENT_RELEASE_BUNDLE_FILE" ]]; then
    release_state_validate_regular_file "$CURRENT_RELEASE_BUNDLE_FILE" 'canonical current release-image bundle' || return
  fi
  release_state_atomic_rename "$PENDING_RELEASE_BUNDLE_FILE" "$CURRENT_RELEASE_BUNDLE_FILE" || {
    release_state_error 'could not atomically promote pending release-image bundle'
    return 1
  }
  [[ ! -e "$PENDING_RELEASE_BUNDLE_FILE" && ! -L "$PENDING_RELEASE_BUNDLE_FILE" ]] || {
    release_state_error 'pending promotion reported success without consuming the pending bundle'
    return 1
  }
  release_bundle_load "$CURRENT_RELEASE_BUNDLE_FILE" || return
  regenerate_release_state_projections
}

release_runtime_service_present() {
  local service=$1 running all
  running=$(compose_timeout 30 ps -q "$service") || return 2
  all=$(compose_timeout 30 ps --all -q "$service") || return 2
  [[ -n "$running" && "$running" != *$'\n'* && "$all" == "$running" ]]
}

release_runtime_service_matches_id() {
  local service=$1 expected_id=$2 cid all image_ref image_id
  cid=$(compose_timeout 30 ps -q "$service") || return 2
  all=$(compose_timeout 30 ps --all -q "$service") || return 2
  [[ -n "$cid" && "$cid" != *$'\n'* && "$all" == "$cid" ]] || return 1
  image_ref=$(timeout -k 5 30 docker inspect --format '{{.Config.Image}}' "$cid") || return 2
  image_id=$(timeout -k 5 30 docker inspect --format '{{.Image}}' "$cid") || return 2
  [[ "$image_ref" == "$expected_id" && "$image_id" == "$expected_id" ]]
}

release_runtime_service_matches_legacy_identity() {
  local service=$1 expected_tag=$2 expected_id=$3 cid all image_ref image_id
  cid=$(compose_timeout 30 ps -q "$service") || return 2
  all=$(compose_timeout 30 ps --all -q "$service") || return 2
  [[ -n "$cid" && "$cid" != *$'\n'* && "$all" == "$cid" ]] || return 1
  image_ref=$(timeout -k 5 30 docker inspect --format '{{.Config.Image}}' "$cid") || return 2
  image_id=$(timeout -k 5 30 docker inspect --format '{{.Image}}' "$cid") || return 2
  [[ ( "$image_ref" == "$expected_id" \
      || "$image_ref" == "astranull-control-plane:$expected_tag" ) \
    && "$image_id" == "$expected_id" ]]
}

release_runtime_matches_loaded_bundle_for_legacy_migration() {
  local service
  release_runtime_service_present postgres || return $?
  release_runtime_service_present caddy || return $?
  release_runtime_service_matches_legacy_identity control-plane \
    "$release_bundle_control_tag" "$release_bundle_control_image_id" || return $?
  for service in probe-worker password-recovery-worker test-policy-runner; do
    release_runtime_service_matches_legacy_identity "$service" \
      "$release_bundle_core_tag" "$release_bundle_core_image_id" || return $?
  done
  if [[ "$release_bundle_connector_enabled" == 1 ]]; then
    for service in connector-poll-scheduler connector-poll-runner; do
      release_runtime_service_matches_legacy_identity "$service" \
        "$release_bundle_connector_tag" "$release_bundle_connector_image_id" || return $?
    done
  else
    release_runtime_services_absent connector-poll-scheduler connector-poll-runner || return $?
  fi
}

release_runtime_matches_bundle_file_for_legacy_migration() {
  release_bundle_load "$1" || return 2
  release_runtime_matches_loaded_bundle_for_legacy_migration
}

release_runtime_services_absent() {
  local service all
  for service in "$@"; do
    all=$(compose_timeout 30 ps --all -q "$service") || return 2
    [[ -z "${all//[[:space:]]/}" ]] || return 1
  done
}

release_runtime_matches_loaded_bundle() {
  local service rc
  release_runtime_service_present postgres || return $?
  release_runtime_service_present caddy || return $?
  release_runtime_service_matches_id control-plane "$release_bundle_control_image_id" || return $?
  for service in probe-worker password-recovery-worker test-policy-runner; do
    release_runtime_service_matches_id "$service" "$release_bundle_core_image_id" || return $?
  done
  if [[ "$release_bundle_connector_enabled" == 1 ]]; then
    for service in connector-poll-scheduler connector-poll-runner; do
      release_runtime_service_matches_id "$service" "$release_bundle_connector_image_id" || return $?
    done
  else
    release_runtime_services_absent connector-poll-scheduler connector-poll-runner || return $?
  fi
}

release_runtime_matches_bundle_file() {
  release_bundle_load "$1" || return 2
  release_runtime_matches_loaded_bundle
}

release_runtime_health_for_bundle_file() {
  local file=$1 connector_enabled
  release_bundle_load "$file" || return
  connector_enabled=$release_bundle_connector_enabled
  check_postgres || return
  check_control_plane || return
  check_core_workers || return
  if [[ "$connector_enabled" == 1 ]]; then
    check_connector_workers
  else
    verify_services_absent connector-poll-scheduler connector-poll-runner
  fi
}

reconcile_pending_release_bundle() {
  local pending_match=0 current_match=0 legacy_current_match=0 rc
  release_state_preactivation_pending=0
  ensure_release_state_dir || return
  if ! pending_release_bundle_exists; then
    if canonical_release_bundle_exists; then
      release_bundle_load "$CURRENT_RELEASE_BUNDLE_FILE" || return
      if release_runtime_matches_bundle_file "$CURRENT_RELEASE_BUNDLE_FILE"; then
        current_match=1
      else
        rc=$?
        ((rc == 1)) || return "$rc"
        if release_runtime_matches_bundle_file_for_legacy_migration "$CURRENT_RELEASE_BUNDLE_FILE"; then
          legacy_current_match=1
        else
          rc=$?
          ((rc == 1)) || {
            release_state_error 'could not inspect immutable runtime IDs against canonical current state'
            return "$rc"
          }
        fi
      fi
      # Preserve the normal cleanup of disabled connectors for a strict raw-ID fleet,
      # but never use that cleanup to make a legacy-tag compatibility proof pass. The
      # narrow compatibility proof itself must observe connector presence matching the
      # canonical bundle.
      if (( ! current_match && ! legacy_current_match )) \
        && [[ "$release_bundle_connector_enabled" == 0 ]]; then
        if release_runtime_services_absent connector-poll-scheduler connector-poll-runner; then :; else
          rc=$?
          ((rc == 1)) || {
            release_state_error 'could not inspect disabled connector runtime state'
            return "$rc"
          }
          stop_remove_services connector-poll-scheduler connector-poll-runner || return
          if release_runtime_matches_bundle_file "$CURRENT_RELEASE_BUNDLE_FILE"; then
            current_match=1
          else
            rc=$?
            ((rc == 1)) || return "$rc"
          fi
        fi
      fi
      if ((current_match || legacy_current_match)); then
        release_runtime_health_for_bundle_file "$CURRENT_RELEASE_BUNDLE_FILE" || {
          if ((legacy_current_match)); then
            release_state_error 'canonical legacy-tag runtime failed health verification; refusing compatibility recovery'
          fi
          return 1
        }
      else
        if release_runtime_services_absent caddy control-plane probe-worker \
          password-recovery-worker test-policy-runner connector-poll-scheduler connector-poll-runner; then :; else
          rc=$?
          ((rc == 1)) || return "$rc"
          release_state_error 'canonical runtime is partial or disagrees with current raw image IDs'
          return 1
        fi
      fi
      regenerate_release_state_projections || return
    fi
    return 0
  fi
  release_bundle_load "$PENDING_RELEASE_BUNDLE_FILE" || return
  if release_runtime_matches_bundle_file "$PENDING_RELEASE_BUNDLE_FILE"; then
    pending_match=1
  else
    rc=$?
    ((rc == 1)) || {
      release_state_error 'could not inspect the complete runtime while reconciling pending release state'
      return "$rc"
    }
  fi
  if canonical_release_bundle_exists; then
    release_bundle_load "$CURRENT_RELEASE_BUNDLE_FILE" || return
    if release_runtime_matches_bundle_file "$CURRENT_RELEASE_BUNDLE_FILE"; then
      current_match=1
    else
      rc=$?
      ((rc == 1)) || {
        release_state_error 'could not inspect the complete runtime against canonical current state'
        return "$rc"
      }
    fi
  fi
  # Releases that first introduced canonical bundles could persist an observed legacy
  # fleet, write the target pending bundle, and then fail before activation. Those
  # unchanged containers retain exact-SHA Config.Image references even though their
  # immutable .Image IDs exactly match canonical current. Keep this compatibility path
  # narrower than normal reconciliation: it is considered only when neither strict
  # bundle matches, and it still requires every canonical application container's exact
  # immutable ID plus the complete postgres/caddy/connector presence contract.
  if (( ! pending_match && ! current_match )) && canonical_release_bundle_exists; then
    if release_runtime_matches_bundle_file_for_legacy_migration "$CURRENT_RELEASE_BUNDLE_FILE"; then
      legacy_current_match=1
    else
      rc=$?
      ((rc == 1)) || {
        release_state_error 'could not inspect immutable runtime IDs against canonical current state'
        return "$rc"
      }
    fi
  fi
  if ((pending_match)); then
    release_runtime_health_for_bundle_file "$PENDING_RELEASE_BUNDLE_FILE" || {
      release_state_error 'runtime matches pending image IDs but failed health verification; refusing promotion'
      return 1
    }
    promote_pending_release_bundle || return
    release_state_error 'reconciled fully activated pending release state into canonical current state'
  elif ((current_match)); then
    release_runtime_health_for_bundle_file "$CURRENT_RELEASE_BUNDLE_FILE" || {
      release_state_error 'runtime matches canonical current image IDs but failed health verification; refusing pending discard'
      return 1
    }
    release_state_durable_remove "$PENDING_RELEASE_BUNDLE_FILE" 'stale pending release-image bundle' || return
    regenerate_release_state_projections || return
    release_state_error 'discarded pending release state because the complete runtime still matches canonical current state'
  elif ((legacy_current_match)); then
    release_runtime_health_for_bundle_file "$CURRENT_RELEASE_BUNDLE_FILE" || {
      release_state_error 'runtime immutable IDs match canonical current state but failed health verification; refusing compatibility recovery'
      return 1
    }
    # Repair non-authoritative projections before consuming the pending journal. If a
    # checked atomic write fails, pending remains as retry/evidence. Once durable removal
    # succeeds, every compatibility projection has already settled from canonical state.
    regenerate_release_state_projections || {
      release_state_error 'could not repair compatibility projections; refusing pending discard'
      return 1
    }
    release_state_durable_remove "$PENDING_RELEASE_BUNDLE_FILE" \
      'stale pre-activation pending release-image bundle' || return
    release_state_error 'discarded stale pre-activation pending state because complete runtime immutable IDs still match canonical current state'
  elif ! canonical_release_bundle_exists; then
    if release_runtime_services_absent caddy control-plane probe-worker password-recovery-worker \
      test-policy-runner connector-poll-scheduler connector-poll-runner; then
      release_state_preactivation_pending=1
      release_state_error 'retained resumable first-boot pending state with no application runtime'
    else
      rc=$?
      ((rc == 1)) || return "$rc"
      release_state_error 'first-boot pending state has partial or unexpected application runtime'
      return 1
    fi
  else
    release_state_error 'pending release state is mixed or matches neither pending nor canonical current; refusing release operations'
    return 1
  fi
}

verify_release_state_settled() {
  canonical_release_bundle_exists || {
    release_state_error 'canonical current release-image bundle is missing'
    return 1
  }
  release_bundle_load "$CURRENT_RELEASE_BUNDLE_FILE" || return
  [[ ! -e "$PENDING_RELEASE_BUNDLE_FILE" && ! -L "$PENDING_RELEASE_BUNDLE_FILE" ]] || {
    release_state_error 'pending release-image bundle remains after completed promotion'
    return 1
  }
  regenerate_release_state_projections
}

verify_release_state_journal_safe() {
  if canonical_release_bundle_exists; then release_bundle_load "$CURRENT_RELEASE_BUNDLE_FILE" || return; fi
  if pending_release_bundle_exists; then release_bundle_load "$PENDING_RELEASE_BUNDLE_FILE" || return; fi
}
