# Threat model

## Assets

Kunadonokami protects:

- VPS integrity,
- SSH access control,
- server configuration confidentiality,
- operational privacy,
- owner credentials and SSH keys,
- reliability of security review.

## Main risks

### 1. Direct compromise of the VPS

Examples:

- successful SSH login by an attacker,
- weak password authentication,
- exposed management services,
- compromised user account,
- persistence via systemd, cron, shell profile, or SSH keys.

### 2. Agent-induced risk

Examples:

- giving the agent sudo access,
- giving the agent SSH credentials,
- allowing unrestricted shell execution on production,
- allowing an MCP/tool server to expose unsafe operations,
- hallucinated firewall or SSH changes.

### 3. Snapshot leakage

Snapshots may contain sensitive information:

- hostnames,
- usernames,
- IP addresses,
- listening services,
- deployment patterns,
- operational baseline.

Snapshots should be treated as sensitive artifacts.

## Security boundaries

The owner may run privileged collection.

The AI reviewer may read only copied snapshot artifacts.

The AI reviewer must not:

- connect to the VPS,
- request credentials,
- run sudo,
- modify live configuration,
- autonomously remediate findings.

## Local policy

Public repository code should not encode the owner's real infrastructure assumptions.

Keep private:

- actual hostnames,
- VPS provider details,
- trusted IP ranges,
- real usernames,
- real service topology,
- suppression rules,
- normal traffic baseline,
- exact response thresholds.
