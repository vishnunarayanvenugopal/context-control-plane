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


def _write_mcp_policy(
    root: Path,
    *,
    name: str,
    egress_mode: str,
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


@unittest.skipUnless(platform.system() == "Darwin" and shutil.which("sandbox-exec"), "sandbox-exec enforcement is macOS-specific")
class McpEnforcementPhaseFourteenTests(unittest.TestCase):
    def test_observed_probe_denies_localhost_egress_when_policy_is_deny(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(1.0)
        host, port = listener.getsockname()
        accepted = threading.Event()

        def _accept_once() -> None:
            try:
                conn, _ = listener.accept()
                accepted.set()
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
                f"socket.create_connection(({host!r}, {port}), timeout=0.5);"
                "time.sleep(0.5)"
            )
            _write_mcp_server(root, name="chatty-deny", command=sys.executable, args=["-c", script])
            _write_mcp_policy(root, name="chatty-deny", egress_mode="deny")

            exit_code, stdout, stderr = _run_discovery(
                "mcp",
                "test",
                "--resource-dir",
                str(root),
                "--name",
                "chatty-deny",
                "--observed",
                "--probe-seconds",
                "0.2",
                "--json",
            )

        thread.join(timeout=1.2)
        self.assertFalse(accepted.is_set())
        self.assertEqual(exit_code, 1)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        observed = payload["result"]["observed"]
        self.assertEqual(observed["mode"], "sandbox-exec-probe")
        self.assertEqual(observed["sandboxApplied"]["runner"], "sandbox-exec")
        self.assertEqual(observed["sandboxApplied"]["egressEnforcement"], "deny")

    def test_observed_probe_allows_localhost_allowlist_entries(self) -> None:
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
                f"socket.create_connection(({host!r}, {port}), timeout=0.5);"
                "time.sleep(0.8)"
            )
            _write_mcp_server(root, name="chatty-allow", command=sys.executable, args=["-c", script])
            _write_mcp_policy(root, name="chatty-allow", egress_mode="allowlist", egress_allow=[f"localhost:{port}"])

            exit_code, stdout, stderr = _run_discovery(
                "mcp",
                "test",
                "--resource-dir",
                str(root),
                "--name",
                "chatty-allow",
                "--observed",
                "--probe-seconds",
                "0.2",
                "--json",
            )

        thread.join(timeout=1.5)
        self.assertTrue(accepted.is_set())
        self.assertEqual(exit_code, 0, msg=stderr)
        payload = json.loads(stdout)
        observed = payload["result"]["observed"]
        self.assertEqual(observed["mode"], "sandbox-exec-probe")
        self.assertEqual(observed["sandboxApplied"]["egressEnforcement"], "allowlist-localhost")


if __name__ == "__main__":
    unittest.main()
