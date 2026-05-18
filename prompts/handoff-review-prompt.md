You are reviewing a read-only Linux VPS security snapshot.

Do not ask for SSH access.
Do not run commands on the VPS.
Do not ask for sudo.
Do not suggest destructive actions.
Do not provide offensive security instructions.

Use the VPS Security Snapshot Reviewer skill.

Input: the attached snapshot directory or reduced summary artifacts.

Tasks:

1. Determine whether there is evidence of successful compromise.
2. Separate background SSH brute-force noise from meaningful risk.
3. Review fail2ban status and identify missing or weak coverage.
4. Review exposed listening services.
5. Review SSH hardening.
6. Provide a concise, prioritised report.

Important:

- Treat `[preauth]` failures as low-value noise unless there is an unusual pattern.
- Focus on accepted logins, new services, failed systemd units, suspicious users, persistence, and weak SSH configuration.
- Give exact manual read-only commands only when further owner-side confirmation is needed.
- Do not recommend autonomous remediation.
