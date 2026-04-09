from __future__ import annotations

import io
import json
import platform
import shutil
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


def _write_mcp_server(root: Path, *, name: str, command: str, args: list[str] | None = None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{name}.server.json"
    path.write_text(
        json.dumps(
            {
                "apiVersion": CORE_DEFAULT_API_VERSION,
                "kind": "McpServer",
                "metadata": {"name": name},
                "spec": {
                    "transport": "stdio",
                    "enabled": True,
                    "mode": "read",
                    "command": command,
                    "args": args or [],
                    "declared_tools": ["list_data"],
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def _write_mcp_policy(root: Path, *, name: str, egress_allow: list[str]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{name}.policy.json"
    path.write_text(
        json.dumps(
            {
                "apiVersion": CORE_DEFAULT_API_VERSION,
                "kind": "McpPolicy",
                "metadata": {"name": name},
                "spec": {
                    "targets": [name],
                    "trust_tier": "verified",
                    "sandbox_profile": {"filesystem": {"read": [], "write": [], "allowTmp": True}},
                    "egress_policy": {"mode": "allowlist", "allow": egress_allow},
                    "secret_usage_mode": "brokered",
                    "input_sanitization": {"redact": ["token"]},
                    "output_sanitization": {"redact": ["authorization"]},
                    "trace_redaction": {"redact": ["cookie"]},
                    "tool_rules": [{"tool": "list_data", "access": "read"}],
                },
            }
        ),
        encoding="utf-8",
    )
    return path


class McpProxyPhaseSeventeenTests(unittest.TestCase):
    def test_observed_probe_keeps_unapproved_external_egress_out_of_safe_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            script = "\n".join(
                [
                    "import time",
                    "import urllib.request",
                    "try:",
                    "    urllib.request.urlopen('http://example.com/', timeout=0.5)",
                    "except Exception:",
                    "    pass",
                    "time.sleep(0.3)",
                ]
            )
            _write_mcp_server(root, name="proxy-guarded", command=sys.executable, args=["-c", script])
            _write_mcp_policy(root, name="proxy-guarded", egress_allow=["api.vendor.example:443"])

            exit_code, stdout, stderr = _run_discovery(
                "mcp",
                "test",
                "--resource-dir",
                str(root),
                "--name",
                "proxy-guarded",
                "--observed",
                "--probe-seconds",
                "0.2",
                "--json",
            )

        self.assertEqual(exit_code, 1, msg=stderr)
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "error")
        self.assertIn(payload["result"]["health"], {"blocked", "attention_needed"})
        observed = payload["result"]["observed"]
        expected_mode = (
            "sandbox-exec-proxy-probe"
            if platform.system() == "Darwin" and shutil.which("sandbox-exec")
            else "proxy-process-probe"
        )
        self.assertEqual(observed["mode"], expected_mode)
        self.assertTrue(observed["sandboxApplied"]["proxy"]["active"])
        enforcement = observed["sandboxApplied"]["egressEnforcement"]
        self.assertIn("proxy", enforcement)
        self.assertNotEqual(payload["result"]["health"], "safe")
        if observed["observedNetworkDestinations"]:
            self.assertIn("example.com:80", observed["observedNetworkDestinations"])
        if observed["egressViolations"]:
            self.assertTrue(any("example.com:80" in item for item in observed["egressViolations"]))


if __name__ == "__main__":
    unittest.main()
