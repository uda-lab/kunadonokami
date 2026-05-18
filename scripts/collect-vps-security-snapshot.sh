#!/usr/bin/env bash
set -euo pipefail

OUT="${1:-security-snapshot-$(hostname)-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT"
chmod 700 "$OUT"

write_cmd() {
  local name="$1"
  shift
  {
    echo "# command: $*"
    echo "# date_utc: $(date -u --iso-8601=seconds)"
    echo
    "$@"
  } > "$OUT/$name" 2>&1 || true
}

write_sudo_cmd() {
  local name="$1"
  shift
  {
    echo "# command: sudo $*"
    echo "# date_utc: $(date -u --iso-8601=seconds)"
    echo
    sudo "$@"
  } > "$OUT/$name" 2>&1 || true
}

{
  echo "host=$(hostname)"
  echo "date_utc=$(date -u --iso-8601=seconds)"
  echo "kernel=$(uname -a)"
  echo "collector_user=$(id)"
  echo "snapshot_version=0"
} > "$OUT/meta.txt"

# SSH logs. Different distributions use either ssh or sshd as the unit name.
write_sudo_cmd journal-ssh.txt journalctl -u ssh --since "7 days ago" --no-pager
write_sudo_cmd journal-sshd.txt journalctl -u sshd --since "7 days ago" --no-pager

# Debian/Ubuntu auth log, if present.
if sudo test -f /var/log/auth.log; then
  sudo cp /var/log/auth.log "$OUT/auth.log.txt" 2>/dev/null || true
fi

# fail2ban state.
write_sudo_cmd fail2ban-status.txt fail2ban-client status
write_sudo_cmd fail2ban-sshd.txt fail2ban-client status sshd
sudo sh -c 'zgrep -h "Ban " /var/log/fail2ban.log* 2>/dev/null' > "$OUT/fail2ban-log.txt" 2>&1 || true

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
sudo cp /etc/ssh/sshd_config "$OUT/sshd_config.txt" 2>/dev/null || true
sudo sh -c 'ls -la /etc/ssh/sshd_config.d 2>/dev/null' > "$OUT/sshd_config_d_ls.txt" 2>&1 || true
sudo sh -c 'cat /etc/ssh/sshd_config.d/*.conf 2>/dev/null' > "$OUT/sshd_config_d.txt" 2>&1 || true

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
