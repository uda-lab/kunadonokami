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
- flag weak SSH configuration,
- de-duplicate events across `journal-ssh.txt` and `journal-sshd.txt` (both
  units may exist on the same host and will produce overlapping log lines).

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

Current entrypoint:

```text
scripts/reduce-security-snapshot.py <snapshot-dir>
```

Current reducer coverage:

- collection health classification,
- SSH activity summary with journal de-duplication,
- effective `sshd_config` review across drop-ins,
- fail2ban summary,
- listening-service and firewall-posture summary,
- privileged-group hints from collector metadata.

## Future reducer candidates

* normalized SSH event export
* package/update posture reducer
* filesystem persistence anomaly reducer
