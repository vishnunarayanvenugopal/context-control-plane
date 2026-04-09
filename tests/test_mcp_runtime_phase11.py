from __future__ import annotations

import io
import json
import platform
import shutil
import socket
import sys
import tempfile
import threading
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
    command: str,
    args: list[str] | None = None,
) -> Path:
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


def _write_mcp_policy(
    root: Path,
    *,
    name: str,
    egress_mode: str = "allowlist",
    egress_allow: list[str] | None = None,
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
                    "targets": [name],
                    "trust_tier": "verified",
                    "sandbox_profile": {"filesystem": {"read": [], "write": [], "allowTmp": True}},
                    "egress_policy": {"mode": egress_mode, "allow": egress_allow or []},
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


class McpRuntimePhaseElevenTests(unittest.TestCase):
    def test_mcp_test_observed_reports_scrubbed_process_probe_for_stdio_server(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            _write_mcp_server(root, name="sleepy", command="/bin/sleep", args=["2"])
            _write_mcp_policy(root, name="sleepy", egress_mode="deny")

            exit_code, stdout, stderr = _run_discovery(
                "mcp",
                "test",
                "--resource-dir",
                str(root),
                "--name",
                "sleepy",
                "--observed",
                "--probe-seconds",
                "0.15",
                "--json",
            )

        self.assertEqual(exit_code, 0, msg=stderr)
        payload = json.loads(stdout)
        observed = payload["result"]["observed"]
        self.assertEqual(payload["status"], "ok")
        expected_mode = "sandbox-exec-probe" if platform.system() == "Darwin" and shutil.which("sandbox-exec") else "process-probe"
        self.assertEqual(observed["mode"], expected_mode)
        self.assertTrue(observed["attempted"])
        self.assertTrue(observed["startupSuccess"])
        self.assertTrue(observed["sandboxApplied"]["envScrubbed"])

    def test_mcp_test_observed_flags_egress_violation(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(1.5)
        host, port = listener.getsockname()
        accepted = threading.Event()

        def _accept_once() -> None:
            try:
                conn, _ = listener.accept()
                accepted.set()
                conn.recv(1)
                conn.close()
            except TimeoutError:
                pass
            finally:
                listener.close()

        thread = threading.Thread(target=_accept_once, daemon=True)
        thread.start()

        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            script = (
                "import socket,time;"
                f"s=socket.create_connection(({host!r}, {port}));"
                "time.sleep(0.8);"
                "s.close()"
            )
            _write_mcp_server(root, name="chatty", command=sys.executable, args=["-c", script])
            _write_mcp_policy(root, name="chatty", egress_mode="deny")

            exit_code, stdout, stderr = _run_discovery(
                "mcp",
                "test",
                "--resource-dir",
                str(root),
                "--name",
                "chatty",
                "--observed",
                "--probe-seconds",
                "0.2",
                "--json",
            )

        thread.join(timeout=1.5)
        self.assertEqual(exit_code, 1)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["result"]["health"], "blocked")
        observed = payload["result"]["observed"]
        if platform.system() == "Darwin" and shutil.which("sandbox-exec"):
            self.assertFalse(accepted.is_set())
            self.assertEqual(observed["mode"], "sandbox-exec-probe")
            self.assertEqual(observed["sandboxApplied"]["egressEnforcement"], "deny")
        else:
            self.assertTrue(accepted.is_set())
            self.assertEqual(observed["mode"], "process-probe")
            self.assertTrue(observed["egressViolations"])
            self.assertTrue(observed["observedNetworkDestinations"])


if __name__ == "__main__":
    unittest.main()
