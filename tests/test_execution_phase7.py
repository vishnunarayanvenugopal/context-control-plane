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
    endpoint: str = "https://api.example.test",
    classification: str = "internal",
    allowed_access: list[str] | None = None,
    allowed_modes: list[str] | None = None,
    default_mode: str = "connect",
    approval: dict | None = None,
    secret_handling: dict | None = None,
    gateway_policy_ref: str | None = None,
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{name}.json"
    spec = {
        "adapter": "generic-api",
        "endpoint": endpoint,
        "classification": classification,
        "allowedAccess": allowed_access or ["read"],
        "allowedModes": allowed_modes or ["connect"],
        "defaultMode": default_mode,
    }
    if approval is not None:
        spec["approval"] = approval
    if secret_handling is not None:
        spec["secretHandling"] = secret_handling
    if gateway_policy_ref is not None:
        spec["gatewayPolicyRef"] = gateway_policy_ref
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


class ExecutionPhaseSevenTests(unittest.TestCase):
    def _approval_env(self) -> mock._patch_dict:
        return mock.patch.dict(os.environ, {"CCP_APPROVAL_SIGNING_KEY": "phase-seven-test-key"}, clear=False)

    def test_approval_issue_emits_receipt_and_can_save_to_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            connection_path = _write_connection_profile(
                root,
                name="tracker-writer",
                classification="confidential",
                allowed_access=["read", "write"],
                allowed_modes=["connect", "materialize"],
                approval={"requiredForAccess": ["write"]},
            )
            receipt_path = root / "receipt.json"

            with self._approval_env():
                exit_code, stdout, stderr = _run_discovery(
                    "approval",
                    "issue",
                    "--resource",
                    str(connection_path),
                    "--access",
                    "write",
                    "--mode",
                    "materialize",
                    "--operation",
                    "comment on ticket",
                    "--approved-by",
                    "leader@example.com",
                    "--output",
                    str(receipt_path),
                    "--json",
                )

            self.assertTrue(receipt_path.exists())

        self.assertEqual(exit_code, 0, msg=stderr)
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["result"]["receipt"]["kind"], "ApprovalReceipt")
        self.assertTrue(payload["result"]["receipt"]["spec"]["signature"])
        self.assertEqual(payload["result"]["savedTo"], str(receipt_path))

    def test_approval_issue_rejects_when_approval_is_not_needed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            connection_path = _write_connection_profile(root, name="github-readonly")

            exit_code, stdout, stderr = _run_discovery(
                "approval",
                "issue",
                "--resource",
                str(connection_path),
                "--operation",
                "list repositories",
                "--approved-by",
                "leader@example.com",
                "--json",
            )

        self.assertEqual(exit_code, 1)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "error")
        self.assertIn("approval is not required", payload["reason"])

    def test_exec_plan_safe_read_only_path_returns_brokered_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            connection_path = _write_connection_profile(Path(tmp_dir), name="github-readonly")

            exit_code, stdout, stderr = _run_discovery(
                "exec",
                "plan",
                "--resource",
                str(connection_path),
                "--operation",
                "list repositories",
                "--json",
            )

        self.assertEqual(exit_code, 0, msg=stderr)
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "ok")
        plan = payload["result"]["plan"]
        self.assertEqual(plan["credentialDelivery"], "brokered")
        self.assertEqual(plan["secretExposure"], "sanitized-result-only")
        self.assertFalse(plan["envVarInjection"])

    def test_exec_plan_requires_receipt_for_gated_operation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            connection_path = _write_connection_profile(
                Path(tmp_dir),
                name="tracker-writer",
                classification="confidential",
                allowed_access=["read", "write"],
                allowed_modes=["connect", "materialize"],
                approval={"requiredForAccess": ["write"]},
            )

            exit_code, stdout, stderr = _run_discovery(
                "exec",
                "plan",
                "--resource",
                str(connection_path),
                "--access",
                "write",
                "--mode",
                "materialize",
                "--operation",
                "comment on ticket",
                "--json",
            )

        self.assertEqual(exit_code, 1)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "approval_required")
        self.assertIn("approval issue", payload["next_action"]["command"])

    def test_exec_plan_accepts_matching_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            connection_path = _write_connection_profile(
                root,
                name="tracker-writer",
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
                    "comment on ticket",
                    "--approved-by",
                    "leader@example.com",
                    "--output",
                    str(receipt_path),
                    "--json",
                )
            self.assertEqual(issue_exit, 0, msg=issue_stderr)
            self.assertTrue(receipt_path.exists())

            with self._approval_env():
                exit_code, stdout, stderr = _run_discovery(
                    "exec",
                    "plan",
                    "--resource",
                    str(connection_path),
                    "--access",
                    "write",
                    "--mode",
                    "materialize",
                    "--operation",
                    "comment on ticket",
                    "--approval-receipt",
                    str(receipt_path),
                    "--json",
                )

        self.assertEqual(exit_code, 0, msg=stderr)
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["result"]["plan"]["approvalId"], payload["result"]["approvalReceipt"]["metadata"]["name"])
        self.assertEqual(payload["result"]["plan"]["credentialDelivery"], "ephemeral-handle")

    def test_exec_plan_rejects_mismatched_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            connection_path = _write_connection_profile(
                root,
                name="tracker-writer",
                classification="confidential",
                allowed_access=["read", "write"],
                allowed_modes=["connect", "materialize"],
                approval={"requiredForAccess": ["write"]},
            )
            receipt_path = root / "receipt.json"

            with self._approval_env():
                issue_exit, _, issue_stderr = _run_discovery(
                    "approval",
                    "issue",
                    "--resource",
                    str(connection_path),
                    "--access",
                    "write",
                    "--mode",
                    "materialize",
                    "--operation",
                    "comment on ticket",
                    "--approved-by",
                    "leader@example.com",
                    "--output",
                    str(receipt_path),
                    "--json",
                )
            self.assertEqual(issue_exit, 0, msg=issue_stderr)

            with self._approval_env():
                exit_code, stdout, stderr = _run_discovery(
                    "exec",
                    "plan",
                    "--resource",
                    str(connection_path),
                    "--access",
                    "write",
                    "--mode",
                    "materialize",
                    "--operation",
                    "delete ticket",
                    "--approval-receipt",
                    str(receipt_path),
                    "--json",
                )

        self.assertEqual(exit_code, 1)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "denied")
        self.assertIn("approval receipt operation does not match", payload["reason"])

    def test_exec_plan_rejects_receipt_when_connection_binding_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            connection_path = _write_connection_profile(
                root,
                name="tracker-writer",
                endpoint="https://api.example.test",
                classification="confidential",
                allowed_access=["read", "write"],
                allowed_modes=["connect", "materialize"],
                approval={"requiredForAccess": ["write"]},
            )
            receipt_path = root / "receipt.json"

            with self._approval_env():
                issue_exit, _, issue_stderr = _run_discovery(
                    "approval",
                    "issue",
                    "--resource",
                    str(connection_path),
                    "--access",
                    "write",
                    "--mode",
                    "materialize",
                    "--operation",
                    "comment on ticket",
                    "--approved-by",
                    "leader@example.com",
                    "--output",
                    str(receipt_path),
                    "--json",
                )
            self.assertEqual(issue_exit, 0, msg=issue_stderr)

            _write_connection_profile(
                root,
                name="tracker-writer",
                endpoint="https://retargeted.example.test",
                classification="confidential",
                allowed_access=["read", "write"],
                allowed_modes=["connect", "materialize"],
                approval={"requiredForAccess": ["write"]},
            )

            with self._approval_env():
                exit_code, stdout, stderr = _run_discovery(
                    "exec",
                    "plan",
                    "--resource",
                    str(connection_path),
                    "--access",
                    "write",
                    "--mode",
                    "materialize",
                    "--operation",
                    "comment on ticket",
                    "--approval-receipt",
                    str(receipt_path),
                    "--json",
                )

        self.assertEqual(exit_code, 1)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "denied")
        self.assertIn("binding does not match", payload["reason"])

    def test_exec_plan_rejects_tampered_receipt_signature(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            connection_path = _write_connection_profile(
                root,
                name="tracker-writer",
                classification="confidential",
                allowed_access=["read", "write"],
                allowed_modes=["connect", "materialize"],
                approval={"requiredForAccess": ["write"]},
            )
            receipt_path = root / "receipt.json"

            with self._approval_env():
                issue_exit, _, issue_stderr = _run_discovery(
                    "approval",
                    "issue",
                    "--resource",
                    str(connection_path),
                    "--access",
                    "write",
                    "--mode",
                    "materialize",
                    "--operation",
                    "comment on ticket",
                    "--approved-by",
                    "leader@example.com",
                    "--output",
                    str(receipt_path),
                    "--json",
                )
            self.assertEqual(issue_exit, 0, msg=issue_stderr)

            tampered = json.loads(receipt_path.read_text(encoding="utf-8"))
            tampered["spec"]["approvedBy"] = "mallory@example.com"
            receipt_path.write_text(json.dumps(tampered), encoding="utf-8")

            with self._approval_env():
                exit_code, stdout, stderr = _run_discovery(
                    "exec",
                    "plan",
                    "--resource",
                    str(connection_path),
                    "--access",
                    "write",
                    "--mode",
                    "materialize",
                    "--operation",
                    "comment on ticket",
                    "--approval-receipt",
                    str(receipt_path),
                    "--json",
                )

        self.assertEqual(exit_code, 1)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "denied")
        self.assertIn("signature is invalid", payload["reason"])

    def test_exec_plan_enforces_gateway_policy_deny(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "default-gateway.json").write_text(
                json.dumps(
                    {
                        "apiVersion": CORE_DEFAULT_API_VERSION,
                        "kind": "GatewayPolicy",
                        "metadata": {"name": "default-gateway"},
                        "spec": {
                            "defaults": {"decision": "allow"},
                            "rules": [
                                {"match": {"access": "write"}, "decision": "deny", "reason": "writes are blocked by gateway"}
                            ],
                        },
                    }
                ),
                encoding="utf-8",
            )
            connection_path = _write_connection_profile(
                root,
                name="tracker-writer",
                classification="internal",
                allowed_access=["read", "write"],
                allowed_modes=["connect"],
                gateway_policy_ref="default-gateway",
            )

            exit_code, stdout, stderr = _run_discovery(
                "exec",
                "plan",
                "--resource-dir",
                str(root),
                "--name",
                "tracker-writer",
                "--access",
                "write",
                "--mode",
                "connect",
                "--operation",
                "comment on ticket",
                "--json",
            )

        self.assertEqual(exit_code, 1)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "denied")
        self.assertIn("writes are blocked by gateway", payload["reason"])


if __name__ == "__main__":
    unittest.main()
