# Field-test notes

This note records sanitized observations from running the Kunadonokami reviewer
against a real collected snapshot. No host identifiers, usernames, IP addresses,
operational baselines, or raw log excerpts are included.

## Scope of the field test

- Inputs: one real snapshot archive collected via the local-control workflow,
  inspected in a `.gitignore`d local workspace only.
- Procedure: Stage 4 review per `skills/vps-security-snapshot-reviewer/SKILL.md`
  performed manually, without any reducer in place.
- Output of the test itself: a private/local review report (kept off-repo) plus
  this sanitized gap summary.

## What the current reviewer workflow could determine

Working from raw artifacts alone (no reducer, no JSON summary):

- Whether SSH passwords are effectively disabled by reading `sshd_config.txt`
  and the `sshd_config.d/` drop-ins together.
- Whether any accepted SSH logins exist, how they distributed across users and
  authentication methods, and whether any accepted source IP overlapped with
  the fail2ban banned set.
- Whether `systemctl --failed` reported any failed units (a quick persistence
  / misconfiguration cue).
- Whether the host firewall has any INPUT-side filtering beyond fail2ban and
  container-managed tables.
- The set of externally listening TCP/UDP services and their bind addresses.
- fail2ban jail count, current ban count, and aggregate ban volume.

## What the current reviewer workflow could not reliably determine without a reducer

- The shape and volume of SSH events at a glance. The SSH journal artifact is
  on the order of two megabytes / ~15k lines for a 7-day window on an
  internet-exposed sshd; a reviewer cannot consume it raw and must rely on
  greps it improvises per-snapshot. This is the reducer's job.
- The effective SSH configuration when hardening lives in drop-ins. Reading
  `sshd_config.txt` alone is misleading because the main file is mostly
  commented-out defaults while the actual policy lives in
  `sshd_config.d/*.conf`. The reviewer skill must explicitly merge the two
  and respect OpenSSH's first-match-wins semantics.
- Whether nonzero collection-status entries indicate a real collection failure
  or an expected "tool not installed" condition. Examples seen: `ufw` is not
  installed on every distro; `last`/`lastb` are not part of the default
  install on minimal Debian images. Today both surface as opaque nonzero
  exits or empty-looking output.
- Whether an artifact body of "command not found" should be treated as
  "collected successfully, empty result" or as "collection failed". Some
  collector wrappers exit 0 even though the inner command failed (see "Gaps"
  below).

## Concrete gaps surfaced

### Collector script gaps

1. **`sshd-session[…]` is the dominant SSH identifier on Debian 12+/13, not
   `sshd`.** The fallback `auth.log.txt` mode uses
   `journalctl --identifier sshd --identifier sudo`, which on a modern Debian
   captures only a tiny fraction of SSH auth events because per-connection
   handlers run as `sshd-session`. The fallback should add
   `--identifier sshd-session`.

2. **`bash -lc` wrappers swallow `command not found` into exit 0.** The
   `last`/`lastb` collectors execute `bash -lc 'last -a | head -200'`, which
   exits 0 after the inner shell prints its own
   "command not found" diagnostic. Collection status records 0 even though
   the artifact is unusable. Either drop the `bash -lc` wrapper, use
   `set -o pipefail`, or `command -v` the binary first and emit a structured
   "missing tool" marker.

3. **Locale leaks into artifact bodies.** Where the host locale is non-English,
   command-not-found and journal timestamps are emitted in the host language
   (e.g. month names, "command not found" translations). Reducers will
   eventually need locale-tolerant parsing; the easier fix is for the
   collector to prefix `LC_ALL=C` (and `TZ=UTC` for predictable timestamps)
   around its subprocess invocations.

4. **`journalctl -u sshd` may be empty on hosts where the unit is `ssh`.** On
   Debian the unit is `ssh.service`; on RHEL-derived distros it is
   `sshd.service`. The collector already captures both. The reviewer skill
   should be reminded that one of the two will routinely be `-- No entries --`
   and that this is not a finding.

5. **`ufw` versus `nft` versus `iptables-nft` is not orthogonal.** On a host
   without ufw, `ufw-status.txt` will be nonzero with a "command not found"
   body, while the actual firewall lives in `nft list ruleset`. The
   collection-status reducer should treat "expected tool absent" as info
   rather than as a failure.

6. **Collector script self-archived in older snapshots.** A previously-noted
   artifact: when the collector was copied into the snapshot directory
   before running, the resulting archive includes the collector itself.
   The wrapper change in PR #3 keeps future snapshots clean; the field-test
   snapshot predates that fix and still contains a `collector.sh` entry. No
   action required beyond awareness.

### Reviewer skill / prompt gaps

1. **No guidance on merging `sshd_config` with its drop-ins.** Step 8 of
   `SKILL.md` lists hardening directives but does not say where to look. A
   reviewer following the skill literally will read only `sshd_config.txt`
   and report false negatives ("PasswordAuthentication is at OpenSSH default
   `yes`") when the effective policy is `no` via a drop-in. The skill should
   require reading `sshd_config_d.txt` (and `sshd_config_d_ls.txt` for
   ordering) and applying OpenSSH first-match-wins semantics.

2. **No guidance on the de-facto "desktop image used as a VPS" pattern.**
   Real snapshots may show printing, mDNS, wireless-supplicant, and
   container-runtime services that are typical of a desktop install but
   atypical of a hardened server. The skill currently has no language for
   "this host is running a workstation profile" as a hardening
   observation; absent that, a reviewer either over-flags every service or
   silently ignores the pattern.

3. **No guidance on privilege-equivalent group membership.** Membership in
   groups such as `docker` makes a non-root account root-equivalent via
   container mounts. The skill's hardening list focuses on sshd directives
   and does not mention group membership of the human account, which is
   visible in `meta.txt` (`collector_user`).

4. **`reduced-security-summary.json` is described as the primary index, but
   no reducer exists to produce it.** Step 2 of `SKILL.md` instructs the
   reviewer to prefer it if present. In the field test there was nothing to
   prefer; the entire review ran off raw artifacts.

5. **Output section "Manual checks for owner" implicitly assumes the reviewer
   has identified specific concrete owner actions.** When the snapshot shows
   no evidence of compromise and clean hardening, the section either
   degenerates into hygiene checklists or is omitted. The skill should
   explicitly permit "no manual checks needed" as a valid result.

6. **No size budget for raw artifacts.** The SSH journal artifact is large
   enough that a non-reducer-assisted review must improvise its own
   filtering. The skill should either point reviewers at a reducer or set
   expectations that a partial review is acceptable for the raw journal.

### Schema gaps

1. `reduced-security-summary.schema.json` has no field for `collection_health`
   (artifact → exit-code map, classification of optional-vs-required,
   expected-tool-absent markers). This information is what tells a reviewer
   whether to trust a "no findings" verdict.

2. The schema's `ssh` section has count fields but no place to record the
   short list of accepted-login source IPs (post-sanitization, optional)
   that a reviewer needs to confirm the "no compromise" verdict locally.
   A reducer must record this somewhere; whether it is in the public
   summary or a sibling local-only artifact is a design decision.

3. `normalized-ssh-event.schema.json` does not include a field for the
   syslog identifier (`sshd` vs `sshd-session` vs other), which is the only
   way to cross-check de-duplication between journal-ssh and journal-sshd
   when both units are populated.

## Confirmed first reducer target

The prior reducer backlog comment on issue #4 proposed starting with
`collection-status` + SSH-summary. The field test supports that, with one
adjustment.

Recommended first reducer target:

1. **`collection-status` reducer** — required first. Without it, every other
   reducer treats nonzero exits as failures and the reviewer cannot
   distinguish "tool not installed on this distro" from "collection broke".
   Must classify each known artifact as required vs optional, recognise the
   "expected-tool-absent" pattern (ufw on non-ufw hosts, last/lastb on
   minimal images), and surface unexpected nonzeros for reviewer attention.

2. **SSH-summary reducer** — depends on collection-status. Should:
   - prefer `journal-ssh.txt` when both unit-named journals exist and the
     other is `-- No entries --`,
   - de-duplicate by `(timestamp, pid, message-hash)` if both are populated,
   - normalise `sshd[…]`, `sshd-session[…]`, and PAM `authentication failure`
     lines into the same event vocabulary,
   - count accepted-by-method (`publickey` vs `password`), failed-by-cause,
     invalid-user, preauth disconnects, kex-identification failures,
   - record top-N source IPs and usernames as counts (raw values kept in a
     local-only artifact, not the public summary, by default).

A `merge_summary.py` step that emits a schema-conformant
`reduced-security-summary.json` (with a new `collection_health` section)
should follow once both inputs are stable.

fail2ban, listening-services, and sshd-config reducers can come after; they
are simpler and do not unblock the reviewer the same way the first two do.

## Validation of acceptance criteria

- Snapshot inspected only in a `.gitignore`d workspace; archive remains
  untracked. Verified with `git check-ignore -v`.
- No host identifiers, usernames, IPs, ranges, service enumerations,
  baselines, or raw log excerpts appear in this file.
- Reviewer-skill, prompt, collector-script, and schema gaps are enumerated
  above with the action each implies.
- First reducer target is confirmed as collection-status plus SSH-summary,
  in that order.
- No VPS SSH, sudo, secrets, or live remediation were requested or used.
