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

On the VPS:

```bash
bash scripts/collect-vps-security-snapshot.sh
```

Then copy the generated `.tar.gz` snapshot to a local or sandboxed analysis environment.

The AI agent should only receive the extracted snapshot directory or reduced JSON artifacts. It should not receive SSH keys, passwords, sudo access, or unrestricted shell access to the VPS.

## Design principle

The LLM is not the detector of first resort.

Deterministic tools should extract, normalize, and reduce events first. The LLM should only perform higher-level interpretation, prioritisation, and report writing.

## Status

Initial scaffold. The current implementation is intentionally minimal.
