# Workflow

## Stage 1: Owner-side collection

Run the collector on the VPS:

```bash
bash scripts/collect-vps-security-snapshot.sh
```

This stage may use `sudo`.

The output is a timestamped snapshot directory and a `.tar.gz` archive.

## Stage 2: Transfer

Copy the archive to a local machine or isolated analysis environment.

Do not give the AI reviewer SSH access to the VPS.

## Stage 3: Deterministic reduction

Reducers should convert raw logs into compact structured artifacts.

Examples:

* count failed SSH attempts,
* group repeated IPs,
* extract accepted logins,
* identify usernames targeted by attackers,
* summarise fail2ban state,
* summarise listening services,
* flag weak SSH configuration.

## Stage 4: AI-assisted review

The AI reviewer reads the snapshot and reduced artifacts.

Expected output:

* evidence of compromise or no evidence found,
* high-priority findings,
* medium/low-priority findings,
* background noise summary,
* manual read-only checks,
* suggested next actions.

## Stage 5: Human-approved action

The owner applies any remediation manually.

No automated patching or firewall modification is performed by Kunadonokami.
