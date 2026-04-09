from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "sdk" / "python"))

from context_control_plane.surfaces import cli as discovery_cli  # noqa: E402


def _run_discovery(*argv: str) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    exit_code = discovery_cli.run(list(argv), stdout=stdout, stderr=stderr)
    return exit_code, stdout.getvalue(), stderr.getvalue()


class McpManagementPhaseTenTests(unittest.TestCase):
    def test_mcp_add_creates_server_and_policy_resources(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)

            exit_code, stdout, stderr = _run_discovery(
                "mcp",
                "add",
                "--resource-dir",
                str(root),
                "--name",
                "github-safe",
                "--transport",
                "stdio",
                "--command",
                sys.executable,
                "--declared-tool",
                "list_issues",
                "--capability",
                "issues.read",
                "--trust-tier",
                "quarantined",
                "--egress-mode",
                "allowlist",
                "--egress-allow",
                "api.github.com",
                "--sandbox-read",
                "/tmp/config",
                "--json",
            )

            server_path = root / "github-safe.server.json"
            policy_path = root / "github-safe.policy.json"

            self.assertTrue(server_path.exists())
            self.assertTrue(policy_path.exists())
            server_payload = json.loads(server_path.read_text(encoding="utf-8"))
            policy_payload = json.loads(policy_path.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0, msg=stderr)
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(server_payload["kind"], "McpServer")
        self.assertEqual(server_payload["spec"]["declared_tools"], ["list_issues"])
        self.assertEqual(policy_payload["kind"], "McpPolicy")
        self.assertEqual(policy_payload["spec"]["trust_tier"], "quarantined")
        self.assertEqual(policy_payload["spec"]["egress_policy"]["allow"], ["api.github.com"])

    def test_mcp_disable_updates_existing_server_resource(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            add_exit, _, add_stderr = _run_discovery(
                "mcp",
                "add",
                "--resource-dir",
                str(root),
                "--name",
                "github-safe",
                "--transport",
                "stdio",
                "--command",
                sys.executable,
                "--json",
            )
            self.assertEqual(add_exit, 0, msg=add_stderr)

            disable_exit, disable_stdout, disable_stderr = _run_discovery(
                "mcp",
                "disable",
                "--resource-dir",
                str(root),
                "--name",
                "github-safe",
                "--json",
            )

            server_payload = json.loads((root / "github-safe.server.json").read_text(encoding="utf-8"))

        self.assertEqual(disable_exit, 0, msg=disable_stderr)
        payload = json.loads(disable_stdout)
        self.assertEqual(payload["status"], "ok")
        self.assertFalse(server_payload["spec"]["enabled"])


if __name__ == "__main__":
    unittest.main()
