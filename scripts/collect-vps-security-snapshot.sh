#!/usr/bin/env bash
set -euo pipefail

INCLUDE_RAW_AUTH_LOG=0
POSITIONAL=()
for arg in "$@"; do
  case "$arg" in
    --include-raw-auth-log) INCLUDE_RAW_AUTH_LOG=1 ;;
    *) POSITIONAL+=("$arg") ;;
  esac
done

OUT="${POSITIONAL[0]:-security-snapshot-$(hostname)-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT"
chmod 700 "$OUT"

STATUS_FILE="$OUT/collection-status.txt"
{
  echo "# collection-status"
  echo "# date_utc: $(date -u --iso-8601=seconds)"
} > "$STATUS_FILE"

record_status() {
  local name="$1" exit_code="$2"
  echo "${exit_code} ${name}" >> "$STATUS_FILE"
}

write_cmd() {
  local name="$1"
  shift
  local rc=0
  {
    echo "# command: $*"
    echo "# date_utc: $(date -u --iso-8601=seconds)"
    echo
    "$@"
  } > "$OUT/$name" 2>&1 || rc=$?
  record_status "$name" "$rc"
}

write_sudo_cmd() {
  local name="$1"
  shift
  local rc=0
  {
    echo "# command: sudo $*"
    echo "# date_utc: $(date -u --iso-8601=seconds)"
    echo
    sudo "$@"
  } > "$OUT/$name" 2>&1 || rc=$?
  record_status "$name" "$rc"
}

{
  echo "host=$(hostname)"
  echo "date_utc=$(date -u --iso-8601=seconds)"
  echo "kernel=$(uname -a)"
  echo "collector_user=$(id)"
  echo "snapshot_version=0"
} > "$OUT/meta.txt"

# SSH logs. Different distributions use either ssh or sshd as the unit name.
# Note: both units may be present on the same system and will contain duplicate
# events; reducers should de-duplicate by timestamp and message before analysis.
write_sudo_cmd journal-ssh.txt journalctl -u ssh --since "7 days ago" --no-pager
write_sudo_cmd journal-sshd.txt journalctl -u sshd --since "7 days ago" --no-pager

# Debian/Ubuntu auth log: opt-in only (--include-raw-auth-log) because copying
# the whole file can be broad. By default collect a bounded recent slice instead.
if [ "$INCLUDE_RAW_AUTH_LOG" -eq 1 ]; then
  _rc=0
  sudo cp /var/log/auth.log "$OUT/auth.log.txt" 2>/dev/null || _rc=$?
  record_status "auth.log.txt" "$_rc"
else
  write_sudo_cmd auth.log.txt journalctl --identifier sshd --identifier sudo \
    --since "7 days ago" --no-pager
fi

# fail2ban state.
write_sudo_cmd fail2ban-status.txt fail2ban-client status
write_sudo_cmd fail2ban-sshd.txt fail2ban-client status sshd
_rc=0
sudo sh -c 'zgrep -h "Ban " /var/log/fail2ban.log* 2>/dev/null' > "$OUT/fail2ban-log.txt" 2>&1 || _rc=$?
record_status "fail2ban-log.txt" "$_rc"

# Listening services.
write_sudo_cmd ss-listening.txt ss -tulpn

# Firewall state, if tools exist.
write_sudo_cmd nft-list-ruleset.txt nft list ruleset
write_sudo_cmd ufw-status.txt ufw status verbose
write_sudo_cmd iptables-save.txt iptables-save

# Systemd anomalies.
write_cmd systemctl-failed.txt systemctl --failed
write_cmd systemctl-running.txt systemctl list-units --type=service --state=running --no-pager

# SSH configuration.
_rc=0; sudo cp /etc/ssh/sshd_config "$OUT/sshd_config.txt" 2>/dev/null || _rc=$?
record_status "sshd_config.txt" "$_rc"
_rc=0; sudo sh -c 'ls -la /etc/ssh/sshd_config.d 2>/dev/null' > "$OUT/sshd_config_d_ls.txt" 2>&1 || _rc=$?
record_status "sshd_config_d_ls.txt" "$_rc"
_rc=0; sudo sh -c 'cat /etc/ssh/sshd_config.d/*.conf 2>/dev/null' > "$OUT/sshd_config_d.txt" 2>&1 || _rc=$?
record_status "sshd_config_d.txt" "$_rc"

# Basic login history.
write_cmd last.txt bash -lc 'last -a | head -200'
write_sudo_cmd lastb.txt bash -lc 'lastb -a | head -200'

# Basic account hints. Avoid dumping secrets.
write_sudo_cmd passwd-users.txt awk -F: '{ print $1 ":" $3 ":" $7 }' /etc/passwd

# Integrity-relevant writable locations, shallow only.
write_sudo_cmd cron-ls.txt bash -lc 'ls -la /etc/cron* 2>/dev/null'
write_sudo_cmd systemd-etc-ls.txt bash -lc 'find /etc/systemd/system -maxdepth 2 -type f -printf "%TY-%Tm-%Td %TH:%TM %p\n" 2>/dev/null | sort'

# Archive.
tar -czf "$OUT.tar.gz" "$OUT"
echo "Wrote $OUT.tar.gz"
