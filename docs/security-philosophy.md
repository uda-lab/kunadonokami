# Security philosophy

Kunadonokami follows a conservative defensive model.

The central rule is:

> Do not give a production VPS to an AI agent. Give the agent a read-only snapshot.

## Privileged collection, unprivileged analysis

Some information requires `sudo` to collect correctly: journal logs, `fail2ban` state, listening processes, `sshd_config`, and authentication history.

However, analysis does not require `sudo`.

The owner should run the collection script manually, inspect what is collected, and pass only the resulting snapshot or reduced artifact to an AI reviewer.

## Deterministic before probabilistic

LLMs are useful for summarisation, prioritisation, and cross-checking. They are not reliable as raw log parsers.

Kunadonokami therefore prefers:

```text
raw log
  -> deterministic parser
  -> normalized event stream
  -> deterministic reducer
  -> compact review artifact
  -> LLM report
```

## Background noise suppression

Internet-facing SSH receives constant background noise.

Failed `[preauth]` events are normally low-value unless they show unusual structure, such as:

* attempts against a known valid user,
* concentration from a trusted network,
* correlation with accepted logins,
* protocol anomalies followed by a successful login,
* sudden change in volume or timing.

## Human-approved remediation

Kunadonokami should not automatically modify firewall rules, ban IPs, edit SSH configuration, restart services, or delete accounts.

The AI reviewer may recommend actions, but the owner applies changes manually after review.
