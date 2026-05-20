from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "sanitized-snapshot-issue6"

sys.path.insert(0, str(REPO_ROOT))

from reducers.reduce_snapshot import reduce_snapshot


class ReduceSnapshotTest(unittest.TestCase):
    def test_reduce_snapshot_fixture(self) -> None:
        summary = reduce_snapshot(FIXTURE_DIR)

        self.assertIn("collection_health", summary)
        self.assertIn("ssh_summary", summary)

        artifacts = {item["name"]: item for item in summary["collection_health"]["artifacts"]}
        self.assertEqual(artifacts["journal-ssh.txt"]["classification"], "empty_expected")
        self.assertEqual(artifacts["ufw-status.txt"]["classification"], "missing_optional_tool")
        self.assertEqual(artifacts["last.txt"]["classification"], "missing_optional_tool")
        self.assertEqual(artifacts["lastb.txt"]["classification"], "missing_optional_tool")
        self.assertTrue(artifacts["lastb.txt"]["wrapper_exit_mismatch"])

        ssh_summary = summary["ssh_summary"]
        self.assertEqual(ssh_summary["accepted_login_count"], 1)
        self.assertEqual(ssh_summary["failed_auth_count"], 2)
        self.assertEqual(ssh_summary["invalid_user_count"], 2)
        self.assertEqual(ssh_summary["root_auth_attempt_count"], 2)
        self.assertEqual(ssh_summary["accepted_login_sources_overlapping_fail2ban_bans"]["count"], 1)
        self.assertEqual(
            ssh_summary["source_artifacts_used"],
            ["journal-sshd.txt", "auth.log.txt"],
        )

        effective = summary["sshd_effective_config"]["effective_values"]
        effective_sources = summary["sshd_effective_config"]["value_sources"]
        self.assertEqual(effective["PasswordAuthentication"], "no")
        self.assertEqual(effective["PermitRootLogin"], "no")
        self.assertEqual(effective["AllowUsers"], ["deployer"])
        self.assertEqual(effective_sources["PasswordAuthentication"], "10-hardening.conf")

        self.assertTrue(summary["firewall_posture"]["fail2ban_only"])
        self.assertTrue(summary["firewall_posture"]["docker_managed_rules_present"])
        self.assertEqual(summary["listening_services"]["public_bind_count"], 2)
        self.assertEqual(len(summary["listening_services"]["desktop_profile_observations"]), 1)
        self.assertEqual(summary["privileged_groups"]["root_equivalent_groups"], ["sudo", "docker"])

    def test_cli_writes_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "summary.json"
            subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "scripts" / "reduce-security-snapshot.py"),
                    str(FIXTURE_DIR),
                    "--output",
                    str(output_path),
                ],
                cwd=REPO_ROOT,
                check=True,
            )
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertIn("collection_health", payload)
            self.assertIn("ssh_summary", payload)


if __name__ == "__main__":
    unittest.main()
