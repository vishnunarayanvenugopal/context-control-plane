from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "sdk" / "python"))

from context_control_plane.kernel import CORE_DEFAULT_API_VERSION  # noqa: E402
from context_control_plane.surfaces import cli as discovery_cli  # noqa: E402


def _run_discovery(*argv: str) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    exit_code = discovery_cli.run(list(argv), stdout=stdout, stderr=stderr)
    return exit_code, stdout.getvalue(), stderr.getvalue()


def _write_connection_profile(
    root: Path,
    *,
    name: str,
    adapter: str = "mock",
    classification: str = "internal",
    allowed_access: list[str] | None = None,
    allowed_modes: list[str] | None = None,
    default_mode: str = "connect",
    approval: dict | None = None,
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{name}.json"
    spec = {
        "adapter": adapter,
        "endpoint": "https://api.example.test",
        "classification": classification,
        "allowedAccess": allowed_access or ["read"],
        "allowedModes": allowed_modes or ["connect"],
        "defaultMode": default_mode,
    }
    if approval is not None:
        spec["approval"] = approval
    path.write_text(
        json.dumps(
            {
                "apiVersion": CORE_DEFAULT_API_VERSION,
                "kind": "ConnectionProfile",
                "metadata": {"name": name},
                "spec": spec,
            }
        ),
        encoding="utf-8",
    )
    return path


class ExecRunPhaseEightTests(unittest.TestCase):
    def _approval_env(self) -> mock._patch_dict:
        return mock.patch.dict(os.environ, {"CCP_APPROVAL_SIGNING_KEY": "phase-eight-test-key"}, clear=False)

    def test_exec_run_brokered_mock_adapter_returns_sanitized_output_and_trace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            connection_path = _write_connection_profile(root, name="mock-readonly")

            exit_code, stdout, stderr = _run_discovery(
                "exec",
                "run",
                "--resource",
                str(connection_path),
                "--operation",
                "list repositories",
                "--params",
                json.dumps({"query": "core", "token": "super-secret"}),
                "--json",
            )

        self.assertEqual(exit_code, 0, msg=stderr)
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "ok")
        self.assertTrue(payload["trace_id"].startswith("trc_"))
        self.assertEqual(payload["trace_id"], payload["result"]["planning"]["plan"]["traceId"])
        self.assertEqual(payload["result"]["output"]["echoedParams"]["token"], "[redacted]")
        self.assertEqual(payload["result"]["output"]["session_cookie"], "[redacted]")
        self.assertEqual(payload["result"]["trace"]["spec"]["events"][-1]["eventType"], "governed_execution_finished")

    def test_exec_run_can_persist_trace_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            traces = root / "traces"
            connection_path = _write_connection_profile(root, name="mock-readonly")

            exit_code, stdout, stderr = _run_discovery(
                "exec",
                "run",
                "--resource",
                str(connection_path),
                "--operation",
                "list repositories",
                "--trace-dir",
                str(traces),
                "--json",
            )

            self.assertEqual(exit_code, 0, msg=stderr)
            payload = json.loads(stdout)
            trace_path = Path(payload["result"]["tracePath"])
            self.assertTrue(trace_path.exists())
            stored = json.loads(trace_path.read_text(encoding="utf-8"))
            self.assertEqual(stored["kind"], "TraceRecord")
            self.assertEqual(stored["metadata"]["name"], payload["trace_id"])

    def test_exec_run_requires_receipt_for_approval_required_operation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            connection_path = _write_connection_profile(
                root,
                name="mock-writer",
                classification="confidential",
                allowed_access=["read", "write"],
                allowed_modes=["connect", "materialize"],
                approval={"requiredForAccess": ["write"]},
            )

            exit_code, stdout, stderr = _run_discovery(
                "exec",
                "run",
                "--resource",
                str(connection_path),
                "--access",
                "write",
                "--mode",
                "materialize",
                "--operation",
                "update repository",
                "--json",
            )

        self.assertEqual(exit_code, 1)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "approval_required")
        self.assertIn("approval issue", payload["next_action"]["command"])

    def test_exec_run_with_receipt_completes_and_keeps_env_injection_off(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            connection_path = _write_connection_profile(
                root,
                name="mock-writer",
                classification="confidential",
                allowed_access=["read", "write"],
                allowed_modes=["connect", "materialize"],
                approval={"requiredForAccess": ["write"]},
            )
            receipt_path = root / "receipt.json"

            with self._approval_env():
                issue_exit, issue_stdout, issue_stderr = _run_discovery(
                    "approval",
                    "issue",
                    "--resource",
                    str(connection_path),
                    "--access",
                    "write",
                    "--mode",
                    "materialize",
                    "--operation",
                    "update repository",
                    "--approved-by",
                    "leader@example.com",
                    "--output",
                    str(receipt_path),
                    "--json",
                )
                self.assertEqual(issue_exit, 0, msg=issue_stderr)
                self.assertTrue(receipt_path.exists())

                exit_code, stdout, stderr = _run_discovery(
                    "exec",
                    "run",
                    "--resource",
                    str(connection_path),
                    "--access",
                    "write",
                    "--mode",
                    "materialize",
                    "--operation",
                    "update repository",
                    "--approval-receipt",
                    str(receipt_path),
                    "--json",
                )

        self.assertEqual(exit_code, 0, msg=stderr)
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "ok")
        self.assertFalse(payload["result"]["planning"]["plan"]["envVarInjection"])
        self.assertEqual(payload["result"]["trace"]["spec"]["status"], "ok")

    def test_exec_run_reports_unsupported_adapter_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            connection_path = _write_connection_profile(Path(tmp_dir), name="tracker-runner", adapter="tracker")

            exit_code, stdout, stderr = _run_discovery(
                "exec",
                "run",
                "--resource",
                str(connection_path),
                "--operation",
                "list projects",
                "--json",
            )

        self.assertEqual(exit_code, 1)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "error")
        self.assertIn("unsupported connection adapter", payload["reason"])


if __name__ == "__main__":
    unittest.main()
