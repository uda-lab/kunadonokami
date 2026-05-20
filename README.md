# Kunadonokami

Kunadonokami is a lightweight defensive security review framework for Linux VPS environments.

It is based on three principles:

1. privileged collection,
2. deterministic reduction,
3. unprivileged AI-assisted review.

The project is intended for small VPS operators who want better security visibility without giving an AI agent direct shell, SSH, or sudo access to a production server.

## Motivation

Internet-facing VPS hosts receive constant background SSH brute-force attempts. Most of them are low-value noise, especially failed `[preauth]` events already blocked by `sshd` and `fail2ban`.

Raw log review is inefficient. Sending all logs to an LLM is also inefficient, expensive, and unreliable.

Kunadonokami therefore separates the workflow:

```text
owner-side sudo collection
  -> deterministic normalization/reduction
  -> read-only AI review
  -> human-approved action
```

The AI reviewer should not access the VPS directly. It only reviews snapshot artifacts.

## Non-goals

Kunadonokami is not:

* a penetration testing framework,
* an offensive security toolkit,
* an autonomous remediation agent,
* a remote shell wrapper,
* an unrestricted MCP server,
* a replacement for `fail2ban`, CrowdSec, Wazuh, Lynis, or OpenSCAP.

## Target environment

Initial target:

* Ubuntu/Debian VPS,
* `systemd`,
* `sshd`,
* `fail2ban`,
* optional `ufw` or `nftables`,
* owner-operated collection with `sudo`.

## Safe workflow

From a local checkout, the owner can copy the collector to the VPS, run it
there with `sudo` as needed, then copy the snapshot back:

```bash
scripts/run-vps-collection.sh vps
```

This keeps the repository and review workflow local while allowing privileged
collection on the VPS. A full repository checkout on the VPS is not required.
Avoid piping remotely fetched code directly into a shell on the VPS; use a
reviewed local copy or another pinned, verifiable release artifact instead.

The AI agent should only receive the extracted snapshot directory or reduced JSON artifacts. It should not receive SSH keys, passwords, sudo access, or unrestricted shell access to the VPS.

> **Warning: snapshots are sensitive.**
> Real snapshot archives can contain hostnames, usernames, IP addresses, listening
> services, firewall topology, and your operational baseline. Do not commit real
> snapshots to a public repository and do not paste them into public AI sessions
> without sanitisation. The `.gitignore` in this repository excludes
> `security-snapshot-*/` and `security-snapshot-*.tar.gz` by default.

## Design principle

The LLM is not the detector of first resort.

Deterministic tools should extract, normalize, and reduce events first. The LLM should only perform higher-level interpretation, prioritisation, and report writing.

To build a reduced summary for an extracted snapshot:

```bash
scripts/reduce-security-snapshot.py security-snapshot-example
```

## Status

Initial scaffold. The current implementation is intentionally minimal.
