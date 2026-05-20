# Workflow

## Stage 1: Owner-side collection

The preferred model is local control with transient VPS execution. From a local
checkout, the owner copies the collector to the VPS, runs it there, then removes
the temporary copy:

```bash
scripts/run-vps-collection.sh vps
```

This stage may use `sudo`.

The output is a snapshot directory and a `.tar.gz` archive. A full repository
checkout on the VPS is optional, not the default assumption.

## Stage 2: Transfer

Copy the archive to a local machine or isolated analysis environment.

Do not give the AI reviewer SSH access to the VPS.
Do not make remote `curl | sh` execution the standard path for privileged
collection; prefer a reviewed local copy or pinned release artifact.

## Stage 3: Deterministic reduction

Reducers should convert raw logs into compact structured artifacts.

Primary reducer entrypoint:

```bash
scripts/reduce-security-snapshot.py security-snapshot-example
```

Examples:

* count failed SSH attempts,
* group repeated IPs,
* extract accepted logins,
* identify usernames targeted by attackers,
* summarise fail2ban state,
* summarise listening services,
* flag weak SSH configuration,
* classify collection health and expected optional-tool absence.

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
