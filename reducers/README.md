# Reducers

Reducers convert raw snapshot files into compact structured artifacts for AI review.

The reducer layer should be deterministic and auditable.

## Responsibilities

Reducers may:

- parse SSH log lines,
- classify `[preauth]` noise,
- count repeated source IPs,
- count targeted usernames,
- extract accepted logins,
- summarise fail2ban state,
- parse listening services,
- flag weak SSH configuration.

Reducers should not:

- call an LLM,
- connect to the VPS,
- run sudo,
- modify firewall rules,
- edit configuration files.

## Recommended output

Reducers should emit JSON artifacts matching schemas in `schemas/`.

The main target artifact is:

```text
reduced-security-summary.json
```

## Future reducer candidates

* `parse_ssh_logs.py`
* `reduce_fail2ban.py`
* `parse_ss_listening.py`
* `review_sshd_config.py`
* `merge_summary.py`
