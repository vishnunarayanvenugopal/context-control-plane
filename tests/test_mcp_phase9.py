from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "sdk" / "python"))

from context_control_plane.kernel import CORE_DEFAULT_API_VERSION  # noqa: E402
from context_control_plane.surfaces import cli as discovery_cli  # noqa: E402


def _run_discovery(*argv: str) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    exit_code = discovery_cli.run(list(argv), stdout=stdout, stderr=stderr)
    return exit_code, stdout.getvalue(), stderr.getvalue()


def _write_mcp_server(
    root: Path,
    *,
    name: str,
    transport: str = "stdio",
    command: str = "",
    args: list[str] | None = None,
    url: str = "",
    enabled: bool = True,
    declared_tools: list[str] | None = None,
    capabilities: list[str] | None = None,
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{name}.server.json"
    spec = {
        "transport": transport,
        "enabled": enabled,
        "mode": "read",
        "capabilities": capabilities or [],
        "declared_tools": declared_tools or [],
    }
    if command:
        spec["command"] = command
    if args:
        spec["args"] = args
    if url:
        spec["url"] = url
    path.write_text(
        json.dumps(
            {
                "apiVersion": CORE_DEFAULT_API_VERSION,
                "kind": "McpServer",
                "metadata": {"name": name},
                "spec": spec,
            }
        ),
        encoding="utf-8",
    )
    return path


def _write_mcp_policy(
    root: Path,
    *,
    name: str,
    targets: list[str] | None = None,
    trust_tier: str = "verified",
    sandbox_profile: dict | None = None,
    egress_policy: dict | None = None,
    secret_usage_mode: str = "brokered",
    input_sanitization: dict | None = None,
    output_sanitization: dict | None = None,
    trace_redaction: dict | None = None,
    tool_rules: list[dict] | None = None,
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{name}.policy.json"
    path.write_text(
        json.dumps(
            {
                "apiVersion": CORE_DEFAULT_API_VERSION,
                "kind": "McpPolicy",
                "metadata": {"name": name},
                "spec": {
                    "targets": targets or [name],
                    "trust_tier": trust_tier,
                    "sandbox_profile": sandbox_profile or {},
                    "egress_policy": egress_policy or {},
                    "secret_usage_mode": secret_usage_mode,
                    "input_sanitization": input_sanitization or {},
                    "output_sanitization": output_sanitization or {},
                    "trace_redaction": trace_redaction or {},
                    "tool_rules": tool_rules or [],
                },
            }
        ),
        encoding="utf-8",
    )
    return path


class McpPhaseNineTests(unittest.TestCase):
    def test_mcp_list_reports_trust_and_policy_health(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            _write_mcp_server(
                root,
                name="github-safe",
                command=sys.executable,
                declared_tools=["list_issues"],
                capabilities=["issues.read"],
            )
            _write_mcp_policy(
                root,
                name="github-safe",
                trust_tier="verified",
                sandbox_profile={"filesystem": {"read": ["/tmp/config"], "write": []}},
                egress_policy={"mode": "allowlist", "allow": ["api.github.com"]},
                secret_usage_mode="brokered",
                input_sanitization={"redact": ["token"]},
                output_sanitization={"redact": ["authorization"]},
                trace_redaction={"redact": ["cookie"]},
                tool_rules=[{"tool": "list_issues", "access": "read"}],
            )
            _write_mcp_server(root, name="github-raw", command=sys.executable)

            exit_code, stdout, stderr = _run_discovery("mcp", "list", "--resource-dir", str(root), "--json")

        self.assertEqual(exit_code, 0, msg=stderr)
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["result"]["summary"]["servers"], 2)
        self.assertEqual(payload["result"]["summary"]["safe"], 1)
        self.assertEqual(payload["result"]["summary"]["attentionNeeded"], 1)
        records = {item["name"]: item for item in payload["result"]["servers"]}
        self.assertEqual(records["github-safe"]["trustTier"], "verified")
        self.assertEqual(records["github-safe"]["health"], "safe")
        self.assertFalse(records["github-raw"]["policyAttached"])
        self.assertEqual(records["github-raw"]["health"], "attention_needed")

    def test_mcp_test_reports_safe_install_for_verified_stdio_server(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            _write_mcp_server(
                root,
                name="github-safe",
                command=sys.executable,
                args=["-m", "demo"],
                declared_tools=["list_issues"],
                capabilities=["issues.read"],
            )
            _write_mcp_policy(
                root,
                name="github-safe",
                trust_tier="verified",
                sandbox_profile={"filesystem": {"read": ["/tmp/config"], "write": [], "allowTmp": False}},
                egress_policy={"mode": "allowlist", "allow": ["api.github.com"]},
                secret_usage_mode="brokered",
                input_sanitization={"redact": ["token"]},
                output_sanitization={"redact": ["authorization"]},
                trace_redaction={"redact": ["cookie"]},
                tool_rules=[{"tool": "list_issues", "access": "read"}],
            )

            exit_code, stdout, stderr = _run_discovery(
                "mcp",
                "test",
                "--resource-dir",
                str(root),
                "--name",
                "github-safe",
                "--json",
            )

        self.assertEqual(exit_code, 0, msg=stderr)
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["result"]["health"], "safe")
        self.assertEqual(payload["result"]["trustTier"], "verified")
        self.assertTrue(payload["result"]["startup"]["success"])
        self.assertIn("list_issues", payload["result"]["declaredTools"])
        self.assertIn("api.github.com", payload["result"]["networkDestinationsRequested"])
        self.assertEqual(payload["result"]["filesystemAccessRequested"]["write"], [])
        self.assertEqual(payload["result"]["secretUsageMode"], "brokered")
        self.assertTrue(payload["result"]["sanitizationPolicyApplied"]["input"])
        self.assertTrue(payload["result"]["sanitizationPolicyApplied"]["output"])
        self.assertTrue(payload["result"]["sanitizationPolicyApplied"]["trace"])

    def test_mcp_test_requires_policy_review_when_server_is_unreviewed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            _write_mcp_server(root, name="github-raw", command=sys.executable)

            exit_code, stdout, stderr = _run_discovery(
                "mcp",
                "test",
                "--resource-dir",
                str(root),
                "--name",
                "github-raw",
                "--json",
            )

        self.assertEqual(exit_code, 1)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["result"]["health"], "attention_needed")
        self.assertEqual(payload["result"]["trustTier"], "quarantined")
        self.assertIn("no McpPolicy is attached", " ".join(payload["result"]["warnings"]))
        self.assertEqual(payload["next_action"]["command"], "ccp schema get McpPolicy --json")

    def test_mcp_test_blocks_missing_stdio_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            _write_mcp_server(root, name="broken-mcp", command="definitely-not-a-real-ccp-binary")
            _write_mcp_policy(
                root,
                name="broken-mcp",
                trust_tier="verified",
                sandbox_profile={"filesystem": {"read": [], "write": []}},
                egress_policy={"mode": "allowlist", "allow": ["api.github.com"]},
                secret_usage_mode="brokered",
                input_sanitization={"redact": ["token"]},
                output_sanitization={"redact": ["authorization"]},
                trace_redaction={"redact": ["cookie"]},
            )

            exit_code, stdout, stderr = _run_discovery(
                "mcp",
                "test",
                "--resource-dir",
                str(root),
                "--name",
                "broken-mcp",
                "--json",
            )

        self.assertEqual(exit_code, 1)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["result"]["health"], "blocked")
        self.assertFalse(payload["result"]["startup"]["success"])
        self.assertIn("not available on PATH", payload["result"]["startup"]["reason"])


if __name__ == "__main__":
    unittest.main()
