#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


KNOWN_ARTIFACTS = {
    "collection-status.txt": {"optional": False, "can_be_empty": False},
    "meta.txt": {"optional": False, "can_be_empty": False},
    "journal-ssh.txt": {"optional": False, "can_be_empty": True},
    "journal-sshd.txt": {"optional": False, "can_be_empty": True},
    "auth.log.txt": {"optional": False, "can_be_empty": True},
    "fail2ban-status.txt": {"optional": True, "can_be_empty": True},
    "fail2ban-sshd.txt": {"optional": True, "can_be_empty": True},
    "fail2ban-log.txt": {"optional": True, "can_be_empty": True},
    "ss-listening.txt": {"optional": False, "can_be_empty": True},
    "nft-list-ruleset.txt": {"optional": True, "can_be_empty": True},
    "ufw-status.txt": {"optional": True, "can_be_empty": True},
    "iptables-save.txt": {"optional": True, "can_be_empty": True},
    "systemctl-failed.txt": {"optional": False, "can_be_empty": True},
    "systemctl-running.txt": {"optional": False, "can_be_empty": False},
    "sshd_config.txt": {"optional": False, "can_be_empty": False},
    "sshd_config_d_ls.txt": {"optional": True, "can_be_empty": True},
    "sshd_config_d.txt": {"optional": True, "can_be_empty": True},
    "last.txt": {"optional": True, "can_be_empty": True},
    "lastb.txt": {"optional": True, "can_be_empty": True},
    "wtmpdb-last.txt": {"optional": True, "can_be_empty": True},
    "lslogins-failed.txt": {"optional": True, "can_be_empty": True},
    "passwd-users.txt": {"optional": False, "can_be_empty": False},
    "cron-ls.txt": {"optional": False, "can_be_empty": True},
    "systemd-etc-ls.txt": {"optional": False, "can_be_empty": True},
}

DESKTOP_SERVICE_PATTERNS = {
    "avahi-daemon": "mDNS responder",
    "cupsd": "printing service",
    "wpa_supplicant": "wireless supplicant",
}

TARGET_DIRECTIVES = {
    "permitrootlogin",
    "passwordauthentication",
    "kbdinteractiveauthentication",
    "pubkeyauthentication",
    "maxauthtries",
    "logingracetime",
    "x11forwarding",
    "allowusers",
}

SSH_LINE_RE = re.compile(
    r"^(?P<timestamp>(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)|"
    r"(?:\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d{4})))\s+"
    r"(?P<host>\S+)\s+(?P<identifier>[\w.@-]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
)
ACCEPTED_RE = re.compile(
    r"Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<source>\S+)\s+port\s+(?P<port>\d+)(?:\s+ssh2(?::\s+(?P<key_type>[A-Za-z0-9_-]+))?)?",
    re.IGNORECASE,
)
FAILED_RE = re.compile(
    r"Failed\s+(?P<method>\S+)\s+for\s+(?:(invalid user)\s+)?(?P<user>\S+)\s+from\s+(?P<source>\S+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)
INVALID_USER_RE = re.compile(
    r"Invalid user\s+(?P<user>\S+)\s+from\s+(?P<source>\S+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)
PAM_AUTH_RE = re.compile(
    r"pam_\w+\(sshd(?::auth)?\): authentication failure;",
    re.IGNORECASE,
)
SOURCE_TOKEN_RE = re.compile(r"(?:from|rhost=)\s*(?P<source>\S+)", re.IGNORECASE)
STATUS_LINE_RE = re.compile(r"^(?P<code>-?\d+)\s+(?P<name>\S+)$")
MISSING_TOOL_MARKER_RE = re.compile(r"__KUNADONOKAMI_MISSING_TOOL__:\s*(?P<tool>\S+)")
FAIL2BAN_BANNED_RE = re.compile(r"Currently banned:\s*(?P<count>\d+)", re.IGNORECASE)
FAIL2BAN_JAILS_RE = re.compile(r"Jail list:\s*(?P<value>.*)", re.IGNORECASE)
FAIL2BAN_BANNED_LIST_RE = re.compile(r"Banned IP list:\s*(?P<value>.*)", re.IGNORECASE)
LISTEN_LINE_RE = re.compile(
    r"^(?P<proto>\S+)\s+\S+\s+\S+\s+\S+\s+(?P<local>\S+)\s+(?P<peer>\S+)(?:\s+users:\(\((?P<users>.*)\)\))?"
)


@dataclass
class ArtifactHealth:
    name: str
    required: bool
    present: bool
    exit_code: int | None
    classification: str
    reason: str
    wrapper_exit_mismatch: bool = False
    missing_tool: str | None = None


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def strip_headers(text: str) -> str:
    lines = []
    in_header = True
    for line in text.splitlines():
        if in_header and line.startswith("#"):
            continue
        if in_header and not line.strip():
            continue
        in_header = False
        lines.append(line)
    return "\n".join(lines).strip()


def parse_collection_status(text: str) -> dict[str, int]:
    status: dict[str, int] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = STATUS_LINE_RE.match(line)
        if match:
            status[match.group("name")] = int(match.group("code"))
    return status


def detect_missing_tool(body: str) -> str | None:
    marker = MISSING_TOOL_MARKER_RE.search(body)
    if marker:
        return marker.group("tool")

    patterns = [
        r"(?i)\bcommand not found\b",
        r"(?i)\bnot found\b",
        r"(?i)\bno such file or directory\b",
        r"(?i)\bunknown command\b",
        r"(?i)\bunit \S+ could not be found\b",
    ]
    for pattern in patterns:
        if re.search(pattern, body):
            return "unknown"
    return None


def detect_empty_expected(name: str, body: str) -> bool:
    normalized = body.strip()
    if not normalized:
        return True
    if normalized == "-- No entries --":
        return True
    if name == "systemctl-failed.txt" and "0 loaded units listed" in normalized:
        return True
    if name == "fail2ban-log.txt" and not normalized:
        return True
    if name.endswith(".txt") and normalized in {"Status: inactive", "Status: inactive\n"}:
        return True
    return False


def classify_artifact(
    snapshot_dir: Path,
    name: str,
    status_map: dict[str, int],
) -> ArtifactHealth:
    artifact = snapshot_dir / name
    spec = KNOWN_ARTIFACTS[name]
    required = not spec["optional"]
    present = artifact.exists()
    body = strip_headers(read_text(artifact)) if present else ""
    exit_code = status_map.get(name)
    missing_tool = detect_missing_tool(body)
    wrapper_exit_mismatch = exit_code == 0 and bool(missing_tool)

    if not present:
        return ArtifactHealth(
            name=name,
            required=required,
            present=False,
            exit_code=exit_code,
            classification="unexpected_failure",
            reason="artifact file missing",
        )

    if exit_code is None:
        if name == "collection-status.txt":
            return ArtifactHealth(
                name=name,
                required=required,
                present=True,
                exit_code=0,
                classification="ok",
                reason="artifact collected successfully",
            )
        return ArtifactHealth(
            name=name,
            required=required,
            present=True,
            exit_code=None,
            classification="unexpected_failure",
            reason="artifact missing from collection-status.txt",
        )

    if missing_tool:
        classification = "missing_optional_tool" if spec["optional"] else "unexpected_failure"
        reason = "expected optional tool missing" if spec["optional"] else "required command missing"
        return ArtifactHealth(
            name=name,
            required=required,
            present=True,
            exit_code=exit_code,
            classification=classification,
            reason=reason,
            wrapper_exit_mismatch=wrapper_exit_mismatch,
            missing_tool=missing_tool,
        )

    if exit_code != 0:
        return ArtifactHealth(
            name=name,
            required=required,
            present=True,
            exit_code=exit_code,
            classification="unexpected_failure",
            reason="command exited nonzero",
        )

    if detect_empty_expected(name, body) and spec["can_be_empty"]:
        return ArtifactHealth(
            name=name,
            required=required,
            present=True,
            exit_code=exit_code,
            classification="empty_expected",
            reason="artifact is empty by design on this host",
        )

    return ArtifactHealth(
        name=name,
        required=required,
        present=True,
        exit_code=exit_code,
        classification="ok",
        reason="artifact collected successfully",
    )


def parse_meta(text: str) -> dict[str, str]:
    meta: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        meta[key] = value
    return meta


def hash_message(message: str) -> str:
    return hashlib.sha256(message.encode("utf-8")).hexdigest()[:16]


def extract_source(message: str) -> str | None:
    match = SOURCE_TOKEN_RE.search(message)
    if match:
        return match.group("source")
    return None


def extract_named_value(message: str, key: str) -> str | None:
    match = re.search(rf"{re.escape(key)}=(\S+)", message)
    if match:
        return match.group(1)
    return None


def normalize_ssh_sources(snapshot_dir: Path) -> tuple[list[dict[str, str]], list[str]]:
    sources: list[tuple[str, list[str]]] = [
        ("journal-ssh.txt", strip_headers(read_text(snapshot_dir / "journal-ssh.txt")).splitlines()),
        ("journal-sshd.txt", strip_headers(read_text(snapshot_dir / "journal-sshd.txt")).splitlines()),
        ("auth.log.txt", strip_headers(read_text(snapshot_dir / "auth.log.txt")).splitlines()),
    ]

    populated = [name for name, lines in sources if any(line.strip() and line.strip() != "-- No entries --" for line in lines)]
    preferred: list[str] = []
    if any(name in {"journal-ssh.txt", "journal-sshd.txt"} for name in populated):
        preferred = [name for name in ("journal-ssh.txt", "journal-sshd.txt") if name in populated]
    if "auth.log.txt" in populated or not preferred:
        preferred.append("auth.log.txt")

    seen: set[tuple[str, str, str]] = set()
    events: list[dict[str, str]] = []

    for name, lines in sources:
        if name not in preferred:
            continue
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped == "-- No entries --":
                continue
            match = SSH_LINE_RE.match(stripped)
            if not match:
                continue
            identifier = match.group("identifier")
            if identifier not in {"sshd", "sshd-session", "sudo"} and "ssh" not in identifier:
                continue
            message = match.group("message")
            if "sudo" in identifier and "ssh" not in message.lower():
                continue
            dedupe_key = (
                match.group("timestamp"),
                match.group("pid") or "",
                hash_message(message),
            )
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            events.append(
                {
                    "timestamp": match.group("timestamp"),
                    "host": match.group("host"),
                    "identifier": identifier,
                    "pid": match.group("pid") or "",
                    "message": message,
                    "source_artifact": name,
                }
            )
    return events, preferred


def top_items(counter: Counter[str], key_name: str, limit: int = 5) -> list[dict[str, object]]:
    return [{key_name: value, "count": count} for value, count in counter.most_common(limit)]


def parse_ssh_summary(snapshot_dir: Path, fail2ban_banned_sources: set[str]) -> dict[str, object]:
    events, source_artifacts = normalize_ssh_sources(snapshot_dir)
    accepted_logins: list[dict[str, str]] = []
    accepted_methods: Counter[str] = Counter()
    accepted_key_types: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    targeted_usernames: Counter[str] = Counter()
    failed_auth_count = 0
    invalid_user_count = 0
    root_auth_attempt_count = 0
    preauth_disconnect_count = 0
    protocol_error_count = 0

    for event in events:
        message = event["message"]
        accepted = ACCEPTED_RE.search(message)
        if accepted:
            method = accepted.group("method").lower()
            user = accepted.group("user")
            source = accepted.group("source")
            key_type = accepted.group("key_type") or ""
            accepted_methods[method] += 1
            if key_type:
                accepted_key_types[key_type.lower()] += 1
            source_counts[source] += 1
            targeted_usernames[user] += 1
            accepted_logins.append(
                {
                    "timestamp": event["timestamp"],
                    "identifier": event["identifier"],
                    "method": method,
                    "username": user,
                    "source": source,
                    "port": accepted.group("port"),
                    **({"key_type": key_type.lower()} if key_type else {}),
                }
            )
            if user == "root":
                root_auth_attempt_count += 1
            continue

        failed = FAILED_RE.search(message)
        if failed:
            failed_auth_count += 1
            user = failed.group("user")
            source = failed.group("source")
            source_counts[source] += 1
            targeted_usernames[user] += 1
            if "invalid user" in message.lower():
                invalid_user_count += 1
            if user == "root":
                root_auth_attempt_count += 1
            continue

        invalid = INVALID_USER_RE.search(message)
        if invalid:
            invalid_user_count += 1
            source = invalid.group("source")
            user = invalid.group("user")
            source_counts[source] += 1
            targeted_usernames[user] += 1
            if user == "root":
                root_auth_attempt_count += 1
            continue

        pam_auth = PAM_AUTH_RE.search(message)
        if pam_auth:
            failed_auth_count += 1
            source = extract_named_value(message, "rhost") or "unknown"
            user = extract_named_value(message, "user") or "unknown"
            source_counts[source] += 1
            targeted_usernames[user] += 1
            if user == "root":
                root_auth_attempt_count += 1
            continue

        if "[preauth]" in message.lower():
            preauth_disconnect_count += 1
            source = extract_source(message)
            if source:
                source_counts[source] += 1
            if "root" in message.lower():
                root_auth_attempt_count += 1
            continue

        if any(token in message.lower() for token in ("kex_exchange_identification", "unable to negotiate", "bad protocol version", "banner exchange")):
            protocol_error_count += 1
            source = extract_source(message)
            if source:
                source_counts[source] += 1
            continue

    accepted_overlap = sorted(
        {item["source"] for item in accepted_logins if item["source"] in fail2ban_banned_sources}
    )

    return {
        "source_artifacts_used": source_artifacts,
        "deduplicated_event_count": len(events),
        "accepted_login_count": len(accepted_logins),
        "accepted_login_methods": top_items(accepted_methods, "method"),
        "accepted_login_key_types": top_items(accepted_key_types, "key_type"),
        "accepted_logins": accepted_logins,
        "failed_auth_count": failed_auth_count,
        "invalid_user_count": invalid_user_count,
        "root_auth_attempt_count": root_auth_attempt_count,
        "preauth_disconnect_count": preauth_disconnect_count,
        "protocol_error_count": protocol_error_count,
        "unique_source_address_count": len(source_counts),
        "top_source_addresses": top_items(source_counts, "source"),
        "top_targeted_usernames": top_items(targeted_usernames, "username"),
        "accepted_login_sources_overlapping_fail2ban_bans": {
            "count": len(accepted_overlap),
            "sources": accepted_overlap,
        },
    }


def parse_fail2ban(snapshot_dir: Path) -> tuple[dict[str, object], set[str]]:
    status_body = strip_headers(read_text(snapshot_dir / "fail2ban-status.txt"))
    sshd_body = strip_headers(read_text(snapshot_dir / "fail2ban-sshd.txt"))
    log_body = strip_headers(read_text(snapshot_dir / "fail2ban-log.txt"))

    jail_match = FAIL2BAN_JAILS_RE.search(status_body)
    jails = []
    if jail_match:
        jails = [value.strip() for value in jail_match.group("value").split(",") if value.strip()]

    banned_match = FAIL2BAN_BANNED_RE.search(sshd_body)
    banned_count = int(banned_match.group("count")) if banned_match else 0

    banned_sources: set[str] = set()
    banned_list_match = FAIL2BAN_BANNED_LIST_RE.search(sshd_body)
    if banned_list_match:
        banned_sources = {value for value in banned_list_match.group("value").split() if value}

    aggregate_ban_events = sum(1 for line in log_body.splitlines() if " ban " in f" {line.lower()} ")

    return (
        {
            "enabled": bool(jails or "status for the jail" in sshd_body.lower()),
            "active_jails": jails,
            "sshd_banned_count": banned_count,
            "aggregate_ban_event_count": aggregate_ban_events,
        },
        banned_sources,
    )


def parse_sshd_drop_in_order(text: str) -> list[str]:
    names = []
    for line in text.splitlines():
        match = re.search(r"(/etc/ssh/sshd_config\.d/\S+\.conf|\S+\.conf)", line)
        if match:
            names.append(Path(match.group(1)).name)
    return names


def split_drop_in_segments(text: str, order: list[str]) -> list[tuple[str, list[str]]]:
    lines = text.splitlines()
    if any(line.startswith("# file: ") for line in lines):
        segments: list[tuple[str, list[str]]] = []
        current_name = "drop-in"
        current_lines: list[str] = []
        for line in lines:
            if line.startswith("# file: "):
                if current_lines:
                    segments.append((current_name, current_lines))
                current_name = Path(line.split(": ", 1)[1].strip()).name
                current_lines = []
                continue
            current_lines.append(line)
        if current_lines:
            segments.append((current_name, current_lines))
        return segments

    cleaned = [line for line in lines if line.strip() and not line.startswith("#")]
    if not cleaned:
        return []
    name = ",".join(order) if order else "sshd_config.d"
    return [(name, cleaned)]


def parse_sshd_effective_config(snapshot_dir: Path) -> dict[str, object]:
    main_lines = read_text(snapshot_dir / "sshd_config.txt").splitlines()
    drop_in_order = parse_sshd_drop_in_order(read_text(snapshot_dir / "sshd_config_d_ls.txt"))
    drop_in_segments = split_drop_in_segments(read_text(snapshot_dir / "sshd_config_d.txt"), drop_in_order)

    combined: list[tuple[str, str]] = []
    include_inserted = False
    for line in main_lines:
        stripped = line.strip()
        combined.append(("sshd_config", line))
        if stripped.lower().startswith("include ") and "sshd_config.d" in stripped and not include_inserted:
            for name, segment_lines in drop_in_segments:
                for segment_line in segment_lines:
                    combined.append((name, segment_line))
            include_inserted = True
    if not include_inserted:
        for name, segment_lines in drop_in_segments:
            for segment_line in segment_lines:
                combined.append((name, segment_line))

    effective: dict[str, dict[str, object]] = {}
    in_match_block = False

    for source_name, line in combined:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.lower().startswith("match "):
            in_match_block = True
            continue
        if in_match_block:
            continue
        key, _, value = stripped.partition(" ")
        if not value:
            continue
        normalized_key = key.lower()
        if normalized_key not in TARGET_DIRECTIVES or normalized_key in effective:
            continue
        parsed_value: object
        if normalized_key == "allowusers":
            parsed_value = value.split()
        else:
            parsed_value = value.strip()
        effective[normalized_key] = {"value": parsed_value, "source": source_name}

    return {
        "effective_values": {
            "PermitRootLogin": effective.get("permitrootlogin", {}).get("value"),
            "PasswordAuthentication": effective.get("passwordauthentication", {}).get("value"),
            "KbdInteractiveAuthentication": effective.get("kbdinteractiveauthentication", {}).get("value"),
            "PubkeyAuthentication": effective.get("pubkeyauthentication", {}).get("value"),
            "MaxAuthTries": effective.get("maxauthtries", {}).get("value"),
            "LoginGraceTime": effective.get("logingracetime", {}).get("value"),
            "X11Forwarding": effective.get("x11forwarding", {}).get("value"),
            "AllowUsers": effective.get("allowusers", {}).get("value"),
        },
        "value_sources": {
            "PermitRootLogin": effective.get("permitrootlogin", {}).get("source"),
            "PasswordAuthentication": effective.get("passwordauthentication", {}).get("source"),
            "KbdInteractiveAuthentication": effective.get("kbdinteractiveauthentication", {}).get("source"),
            "PubkeyAuthentication": effective.get("pubkeyauthentication", {}).get("source"),
            "MaxAuthTries": effective.get("maxauthtries", {}).get("source"),
            "LoginGraceTime": effective.get("logingracetime", {}).get("source"),
            "X11Forwarding": effective.get("x11forwarding", {}).get("source"),
            "AllowUsers": effective.get("allowusers", {}).get("source"),
        },
        "drop_in_order": drop_in_order,
    }


def is_loopback(address: str) -> bool:
    host = address
    if address.startswith("[") and "]" in address:
        host = address[1:].split("]", 1)[0]
    elif ":" in address:
        host = address.rsplit(":", 1)[0]
    return host in {"127.0.0.1", "::1", "localhost"}


def is_public_bind(address: str) -> bool:
    return not is_loopback(address)


def first_process_name(users_field: str | None) -> str | None:
    if not users_field:
        return None
    match = re.search(r'"(?P<name>[^"]+)"', users_field)
    if match:
        return match.group("name")
    return None


def parse_listening_services(snapshot_dir: Path) -> dict[str, object]:
    body = strip_headers(read_text(snapshot_dir / "ss-listening.txt"))
    public_services = []
    loopback_services = []
    desktop_observations = []

    for raw in body.splitlines():
        line = raw.strip()
        if not line or line.lower().startswith("netid "):
            continue
        match = LISTEN_LINE_RE.match(line)
        if not match:
            continue
        local = match.group("local")
        proto = match.group("proto")
        process = first_process_name(match.group("users"))
        item = {"proto": proto, "local": local, "process": process}
        if process in DESKTOP_SERVICE_PATTERNS:
            desktop_observations.append(
                {
                    "process": process,
                    "observation": DESKTOP_SERVICE_PATTERNS[process],
                }
            )
        if is_public_bind(local):
            public_services.append(item)
        else:
            loopback_services.append(item)

    return {
        "public_bind_count": len(public_services),
        "loopback_bind_count": len(loopback_services),
        "public_services": public_services,
        "loopback_services": loopback_services,
        "desktop_profile_observations": desktop_observations,
    }


def parse_firewall_posture(snapshot_dir: Path, fail2ban_enabled: bool) -> dict[str, object]:
    nft_body = strip_headers(read_text(snapshot_dir / "nft-list-ruleset.txt"))
    ufw_body = strip_headers(read_text(snapshot_dir / "ufw-status.txt"))
    iptables_body = strip_headers(read_text(snapshot_dir / "iptables-save.txt"))

    nft_has_default_deny = bool(re.search(r"chain\s+input\s*\{[^}]*policy\s+(drop|reject)", nft_body, re.IGNORECASE | re.DOTALL))
    iptables_default_deny = bool(re.search(r"^:INPUT\s+(DROP|REJECT)\b", iptables_body, re.IGNORECASE | re.MULTILINE))
    ufw_default_deny = "default: deny (incoming)" in ufw_body.lower()
    docker_managed_rules_present = any(token in f"{nft_body}\n{iptables_body}".lower() for token in ("docker", "docker-user", "docker-forward"))

    nft_non_docker_rules = [
        line for line in nft_body.splitlines()
        if line.strip() and "docker" not in line.lower() and "table ip6 filter" not in line.lower()
    ]
    iptables_non_docker_rules = [
        line for line in iptables_body.splitlines()
        if line.strip() and "docker" not in line.lower()
    ]
    base_firewall_detected = any(
        [
            nft_has_default_deny,
            iptables_default_deny,
            ufw_default_deny,
            any(re.search(r"\binput\b", line, re.IGNORECASE) and re.search(r"\b(drop|reject|accept)\b", line, re.IGNORECASE) for line in nft_non_docker_rules),
            any(line.startswith("-A INPUT ") for line in iptables_non_docker_rules),
        ]
    )

    fail2ban_only = fail2ban_enabled and not base_firewall_detected
    if nft_has_default_deny or iptables_default_deny or ufw_default_deny:
        summary = "inbound_default_deny"
    elif fail2ban_only:
        summary = "fail2ban_only"
    elif base_firewall_detected:
        summary = "custom_base_firewall"
    else:
        summary = "no_base_firewall_evidence"

    return {
        "summary": summary,
        "inbound_default_deny": nft_has_default_deny or iptables_default_deny or ufw_default_deny,
        "base_firewall_detected": base_firewall_detected,
        "fail2ban_only": fail2ban_only,
        "docker_managed_rules_present": docker_managed_rules_present,
        "ufw_enabled": "status: active" in ufw_body.lower(),
        "nftables_rules_present": bool(nft_body),
        "iptables_rules_present": bool(iptables_body),
    }


def parse_privileged_groups(snapshot_dir: Path) -> dict[str, object]:
    meta = read_text(snapshot_dir / "meta.txt")
    collector_user = parse_meta(meta).get("collector_user", "")
    groups = []
    match = re.search(r"groups=([^\n]+)", collector_user)
    if match:
        for token in match.group(1).split(","):
            token = token.strip()
            group_match = re.search(r"\(([^)]+)\)", token)
            if group_match:
                groups.append(group_match.group(1))
    root_equivalent = [group for group in groups if group in {"sudo", "docker", "wheel"}]
    return {
        "collector_user_groups": groups,
        "root_equivalent_groups": root_equivalent,
    }


def build_findings(
    ssh_summary: dict[str, object],
    sshd_effective_config: dict[str, object],
    listening_services: dict[str, object],
    firewall_posture: dict[str, object],
    privileged_groups: dict[str, object],
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    effective = sshd_effective_config["effective_values"]

    if effective.get("PasswordAuthentication") not in {None, "no"}:
        findings.append(
            {
                "severity": "medium",
                "title": "SSH password authentication is enabled or unspecified",
                "evidence": "Effective PasswordAuthentication is not 'no'.",
                "recommendation": "Confirm the intended SSH auth policy across sshd_config and drop-ins.",
            }
        )
    if effective.get("PermitRootLogin") not in {None, "no"}:
        findings.append(
            {
                "severity": "medium",
                "title": "SSH root login is not explicitly disabled",
                "evidence": "Effective PermitRootLogin is not 'no'.",
                "recommendation": "Set PermitRootLogin no unless there is a documented operational need.",
            }
        )
    if listening_services["desktop_profile_observations"]:
        findings.append(
            {
                "severity": "low",
                "title": "Desktop-oriented services are present on a VPS profile",
                "evidence": "Detected services typically associated with workstation installs.",
                "recommendation": "Review whether mDNS, printing, or wireless services should remain installed on this host.",
            }
        )
    if firewall_posture["fail2ban_only"]:
        findings.append(
            {
                "severity": "low",
                "title": "Firewall posture appears to rely on fail2ban without a base inbound policy",
                "evidence": "No default-deny base firewall was detected outside Docker-managed rules.",
                "recommendation": "Consider a host or provider-level inbound allowlist/deny policy in addition to fail2ban.",
            }
        )
    if privileged_groups["root_equivalent_groups"]:
        findings.append(
            {
                "severity": "low",
                "title": "Collector user belongs to root-equivalent groups",
                "evidence": "Collector user has membership in privileged local groups.",
                "recommendation": "Review whether sudo/docker-equivalent group membership is still necessary.",
            }
        )
    if ssh_summary["accepted_login_count"] == 0 and ssh_summary["failed_auth_count"]:
        findings.append(
            {
                "severity": "info",
                "title": "SSH noise without accepted logins",
                "evidence": "Failed authentication activity was observed without an accepted login in the reduced summary.",
                "recommendation": "Continue routine monitoring; prioritize accepted-login review when present.",
            }
        )
    return findings


def reduce_snapshot(snapshot_dir: Path) -> dict[str, object]:
    status_map = parse_collection_status(read_text(snapshot_dir / "collection-status.txt"))
    health = [classify_artifact(snapshot_dir, name, status_map) for name in KNOWN_ARTIFACTS]
    meta = parse_meta(read_text(snapshot_dir / "meta.txt"))
    fail2ban, fail2ban_banned_sources = parse_fail2ban(snapshot_dir)
    ssh_summary = parse_ssh_summary(snapshot_dir, fail2ban_banned_sources)
    sshd_effective_config = parse_sshd_effective_config(snapshot_dir)
    listening_services = parse_listening_services(snapshot_dir)
    firewall_posture = parse_firewall_posture(snapshot_dir, bool(fail2ban.get("enabled")))
    privileged_groups = parse_privileged_groups(snapshot_dir)

    findings = build_findings(
        ssh_summary=ssh_summary,
        sshd_effective_config=sshd_effective_config,
        listening_services=listening_services,
        firewall_posture=firewall_posture,
        privileged_groups=privileged_groups,
    )

    summary = {
        "snapshot": {
            "host": meta.get("host"),
            "date_utc": meta.get("date_utc"),
            "time_range": "last 7 days",
            "snapshot_version": meta.get("snapshot_version"),
        },
        "collection_health": {
            "artifacts": [
                {
                    "name": item.name,
                    "required": item.required,
                    "present": item.present,
                    "exit_code": item.exit_code,
                    "classification": item.classification,
                    "reason": item.reason,
                    **({"wrapper_exit_mismatch": True} if item.wrapper_exit_mismatch else {}),
                    **({"missing_tool": item.missing_tool} if item.missing_tool else {}),
                }
                for item in health
            ],
            "classification_counts": dict(Counter(item.classification for item in health)),
        },
        "ssh_summary": ssh_summary,
        "ssh": {
            "accepted_login_count": ssh_summary["accepted_login_count"],
            "failed_login_count": ssh_summary["failed_auth_count"],
            "invalid_user_count": ssh_summary["invalid_user_count"],
            "preauth_noise_count": ssh_summary["preauth_disconnect_count"],
            "unique_source_ip_count": ssh_summary["unique_source_address_count"],
            "top_usernames": ssh_summary["top_targeted_usernames"],
            "top_source_ips": ssh_summary["top_source_addresses"],
        },
        "fail2ban": fail2ban,
        "sshd_effective_config": sshd_effective_config,
        "listening_services": listening_services,
        "firewall_posture": firewall_posture,
        "privileged_groups": privileged_groups,
        "findings": findings,
    }
    return summary


def write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Reduce a Kunadonokami snapshot into compact JSON artifacts.")
    parser.add_argument("snapshot_dir", type=Path, help="Path to the extracted snapshot directory")
    parser.add_argument(
        "--output",
        type=Path,
        help="Write JSON to this file. Defaults to <snapshot_dir>/reduced-security-summary.json",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    snapshot_dir = args.snapshot_dir.resolve()
    output_path = args.output or (snapshot_dir / "reduced-security-summary.json")
    summary = reduce_snapshot(snapshot_dir)
    write_json(output_path, summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
