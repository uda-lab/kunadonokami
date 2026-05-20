# VPS Security Snapshot Reviewer

## Purpose

Review a read-only security snapshot collected from a Linux VPS.

This skill is for defensive security review only.

## Inputs

A snapshot directory containing some or all of:

- `meta.txt`
- `journal-ssh.txt`
- `journal-sshd.txt`
- `auth.log.txt`
- `fail2ban-status.txt`
- `fail2ban-sshd.txt`
- `fail2ban-log.txt`
- `ss-listening.txt`
- `nft-list-ruleset.txt`
- `ufw-status.txt`
- `iptables-save.txt`
- `systemctl-failed.txt`
- `systemctl-running.txt`
- `sshd_config.txt`
- `sshd_config_d_ls.txt`
- `sshd_config_d.txt`
- `last.txt`
- `lastb.txt`
- `wtmpdb-last.txt`
- `lslogins-failed.txt`
- `reduced-security-summary.json`

## Hard rules

- Never request SSH credentials.
- Never connect to the VPS.
- Never run sudo.
- Never modify files.
- Never suggest autonomous remediation.
- Never provide offensive instructions.
- Treat `[preauth]` SSH failures as background noise unless patterns are unusual.
- Focus on successful access, persistence, exposed services, privilege escalation, and configuration weakness.

## Review procedure

1. Read `meta.txt` first.
2. If `reduced-security-summary.json` exists, use it as the primary index.
3. Summarise snapshot scope and time range.
4. Review SSH events:
   - accepted logins,
   - accepted-login sources that overlap the fail2ban banned set,
   - failed valid-user attempts,
   - invalid-user attempts,
   - repeated source IPs,
   - unusual usernames,
   - disconnect/preauth noise,
   - key-exchange and protocol errors.
5. Review fail2ban state:
   - active jails,
   - banned IP count,
   - repeated bans,
   - possible missing jails.
6. Review exposed services from `ss-listening.txt`.
7. Review failed systemd units.
8. Review SSH hardening using the effective config across `sshd_config.txt`
   and `sshd_config.d/*.conf`:
   - `PermitRootLogin no`,
   - `PasswordAuthentication no`,
   - `KbdInteractiveAuthentication no`,
   - `PubkeyAuthentication yes`,
   - `AllowUsers` if feasible,
   - `MaxAuthTries`,
   - `LoginGraceTime`,
   - `X11Forwarding no`.
   Respect OpenSSH first-match-wins semantics and use `sshd_config_d_ls.txt`
   ordering when present.
9. Review exposed services for a VPS profile:
   - separate public binds from loopback-only services,
   - treat mDNS, printing, and wireless services as hardening observations,
     not compromise evidence by themselves.
10. Review privilege-equivalent group membership:
   - accounts in `sudo`, `docker`, or similar groups are effectively
     privileged even if they are not named `root`.
11. Produce a concise report.

## Output format

Use this structure:

### Executive summary

State whether there is evidence of compromise.

### High-priority findings

Only include concrete risks.

### Medium/low-priority findings

Include hardening suggestions.

### Background noise

Summarise brute-force and `[preauth]` activity without overemphasising it.

### Manual checks for owner

List exact read-only commands the owner may run manually.
If no manual checks are needed, say so explicitly.

### Suggested next actions

Prioritised, minimal, non-destructive.

## Interpretation rules

- A large number of failed SSH attempts is not itself evidence of compromise.
- Accepted logins are high-value evidence and must be reviewed carefully.
- Unknown listening services are more important than repeated failed preauth noise.
- Failed systemd units may indicate misconfiguration or failed persistence attempts; distinguish these carefully.
- Recommendations must be reversible and manually approved.
