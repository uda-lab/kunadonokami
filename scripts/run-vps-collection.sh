#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage: scripts/run-vps-collection.sh [options] <ssh-target>

Options:
  --include-raw-auth-log   ask the collector to copy /var/log/auth.log
  --remote-dir DIR         remote snapshot dir under /tmp/kunadonokami-*.
                           default: /tmp/kunadonokami-snapshot-<utc>
  --local-dir DIR          local destination for the returned tarball.
                           default: .
  -h, --help               show this help
USAGE
}

utc_stamp() {
  date -u +%Y%m%dT%H%M%SZ
}

die() {
  echo "error: $*" >&2
  exit 2
}

default_remote_dir() {
  local tmp_dir base
  tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/kunadonokami-snapshot-$(utc_stamp)-XXXXXXXX")" ||
    die "failed to allocate local random name"
  base="$(basename "$tmp_dir")"
  rmdir "$tmp_dir" || die "failed to remove local temporary name: $tmp_dir"
  printf "/tmp/%s\n" "$base"
}

require_safe_remote_tmp_path() {
  local path="$1"
  [[ "$path" == /tmp/kunadonokami-* ]] ||
    die "remote path must begin with /tmp/kunadonokami-: $path"
  [[ "$path" =~ ^/[A-Za-z0-9._/-]+$ ]] ||
    die "remote path may only contain letters, numbers, dots, underscores, dashes, and slashes: $path"
  [[ "$path" != */.. && "$path" != *"/../"* ]] ||
    die "remote path must not contain .. segments: $path"
}

shell_quote() {
  local value="$1"
  printf "'"
  printf "%s" "$value" | sed "s/'/'\\\\''/g"
  printf "'"
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
COLLECTOR="$REPO_ROOT/scripts/collect-vps-security-snapshot.sh"

INCLUDE_RAW_AUTH_LOG=0
REMOTE_DIR=""
LOCAL_DIR="."
SSH_TARGET=""
REMOTE_CREATED=0
CLEANUP_DONE=0

cleanup_remote() {
  local rc=$?
  if [[ "$REMOTE_CREATED" -eq 1 && "$CLEANUP_DONE" -eq 0 ]]; then
    CLEANUP_DONE=1
    echo "Removing remote temporary files" >&2
    ssh "$SSH_TARGET" "rm -f -- $REMOTE_COLLECTOR_Q $REMOTE_ARCHIVE_Q && rm -rf -- $REMOTE_DIR_Q" >&2 || {
      echo "warning: failed to remove remote temporary files from $SSH_TARGET" >&2
    }
  fi
  exit "$rc"
}

while (($#)); do
  case "$1" in
    --include-raw-auth-log)
      INCLUDE_RAW_AUTH_LOG=1
      ;;
    --remote-dir)
      shift
      (($#)) || die "--remote-dir requires a path"
      REMOTE_DIR="$1"
      ;;
    --local-dir)
      shift
      (($#)) || die "--local-dir requires a path"
      LOCAL_DIR="$1"
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    -*)
      die "unknown option: $1"
      ;;
    *)
      [[ -z "$SSH_TARGET" ]] || die "ssh-target specified more than once"
      SSH_TARGET="$1"
      ;;
  esac
  shift
done

[[ -n "$SSH_TARGET" ]] || {
  usage
  exit 2
}

[[ "$SSH_TARGET" != -* ]] || die "ssh-target must not begin with '-'"
[[ "$LOCAL_DIR" != -* ]] || die "local destination must not begin with '-'"
if [[ -z "$REMOTE_DIR" ]]; then
  REMOTE_DIR="$(default_remote_dir)"
fi
[[ -f "$COLLECTOR" ]] || die "collector not found: $COLLECTOR"
[[ -d "$LOCAL_DIR" ]] || die "local destination is not a directory: $LOCAL_DIR"
[[ -w "$LOCAL_DIR" && -x "$LOCAL_DIR" ]] ||
  die "local destination is not writable/searchable: $LOCAL_DIR"

REMOTE_DIR="${REMOTE_DIR%/}"
require_safe_remote_tmp_path "$REMOTE_DIR"
REMOTE_COLLECTOR="${REMOTE_DIR}.collector.sh"
REMOTE_ARCHIVE="${REMOTE_DIR}.tar.gz"
require_safe_remote_tmp_path "$REMOTE_COLLECTOR"
require_safe_remote_tmp_path "$REMOTE_ARCHIVE"

COLLECT_ARGS=()
if [[ "$INCLUDE_RAW_AUTH_LOG" -eq 1 ]]; then
  COLLECT_ARGS+=(--include-raw-auth-log)
fi
COLLECT_ARGS+=("$REMOTE_DIR")

REMOTE_COLLECTOR_Q="$(shell_quote "$REMOTE_COLLECTOR")"
REMOTE_DIR_Q="$(shell_quote "$REMOTE_DIR")"
REMOTE_ARCHIVE_Q="$(shell_quote "$REMOTE_ARCHIVE")"
trap cleanup_remote EXIT INT TERM

echo "Creating remote snapshot directory $SSH_TARGET:$REMOTE_DIR" >&2
ssh "$SSH_TARGET" "umask 077 && mkdir $REMOTE_DIR_Q"
REMOTE_CREATED=1

echo "Copying collector to $SSH_TARGET:$REMOTE_COLLECTOR" >&2
scp "$COLLECTOR" "$SSH_TARGET:$REMOTE_COLLECTOR"

echo "Running collector on $SSH_TARGET" >&2
ssh -t "$SSH_TARGET" "bash $REMOTE_COLLECTOR_Q $(printf "%q " "${COLLECT_ARGS[@]}")"

echo "Retrieving $SSH_TARGET:$REMOTE_ARCHIVE" >&2
scp "$SSH_TARGET:$REMOTE_ARCHIVE" "$LOCAL_DIR/"

echo "Wrote $LOCAL_DIR/$(basename "$REMOTE_ARCHIVE")"
