from __future__ import annotations

import io
import json
import os
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


def _write_secret_backend(
    root: Path,
    *,
    name: str,
    backend_type: str = "vault",
    durability: str = "service-persistent",
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{name}.backend.json"
    path.write_text(
        json.dumps(
            {
                "apiVersion": CORE_DEFAULT_API_VERSION,
                "kind": "SecretBackend",
                "metadata": {"name": name},
                "spec": {
                    "type": backend_type,
                    "durability": durability,
                    "provider": backend_type,
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def _write_connection_profile(
    root: Path,
    *,
    name: str,
    adapter: str = "mock",
    classification: str = "internal",
    allowed_access: list[str] | None = None,
    allowed_modes: list[str] | None = None,
    approval: dict | None = None,
    secret_backend_ref: str | None = None,
    secret_refs: list[str] | None = None,
    output_policy: dict | None = None,
    materialization: dict | None = None,
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{name}.json"
    spec = {
        "adapter": adapter,
        "endpoint": "https://api.example.test",
        "classification": classification,
        "allowedAccess": allowed_access or ["read"],
        "allowedModes": allowed_modes or ["connect"],
        "defaultMode": (allowed_modes or ["connect"])[0],
    }
    if approval is not None:
        spec["approval"] = approval
    if secret_backend_ref is not None:
        spec["secretBackendRef"] = secret_backend_ref
    if secret_refs is not None:
        spec["secretRefs"] = secret_refs
    if output_policy is not None:
        spec["outputPolicy"] = output_policy
    if materialization is not None:
        spec["materialization"] = materialization
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


class SecretSafetyPhaseElevenTests(unittest.TestCase):
    def _approval_env(self) -> unittest.mock._patch_dict:
        return unittest.mock.patch.dict(os.environ, {"CCP_APPROVAL_SIGNING_KEY": "phase-eleven-test-key"}, clear=False)

    def test_connection_explain_resolves_secret_backend_and_materialization_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            _write_secret_backend(root, name="team-vault", backend_type="vault", durability="ephemeral")
            _write_connection_profile(
                root,
                name="tracker-writer",
                classification="confidential",
                allowed_access=["read", "write"],
                allowed_modes=["connect", "materialize"],
                approval={"requiredForAccess": ["write"]},
                secret_backend_ref="team-vault",
                output_policy={"allowFields": ["summary", "echoedParams", "session_cookie"]},
                materialization={"delivery": "temp-file", "ttlSeconds": 120, "cleanupOnRead": True},
            )

            exit_code, stdout, stderr = _run_discovery(
                "connection",
                "explain",
                "--resource-dir",
                str(root),
                "--name",
                "tracker-writer",
                "--access",
                "write",
                "--mode",
                "materialize",
                "--json",
            )

        self.assertEqual(exit_code, 1)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "approval_required")
        controls = payload["result"]["secretControls"]
        self.assertEqual(controls["backend"]["name"], "team-vault")
        self.assertEqual(controls["backend"]["type"], "vault")
        self.assertEqual(controls["backend"]["durability"], "ephemeral")
        self.assertEqual(controls["materialization"]["delivery"], "temp-file")
        self.assertEqual(controls["materialization"]["ttlSeconds"], 120)
        self.assertEqual(controls["responseAllowlist"]["allowFields"], ["summary", "echoedParams", "session_cookie"])
        self.assertIn("secret backend is ephemeral", " ".join(payload["result"]["warnings"]))

    def test_exec_plan_issues_materialization_lease_and_carries_backend_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            _write_secret_backend(root, name="team-vault", backend_type="vault", durability="service-persistent")
            connection_path = _write_connection_profile(
                root,
                name="tracker-writer",
                classification="confidential",
                allowed_access=["read", "write"],
                allowed_modes=["connect", "materialize"],
                approval={"requiredForAccess": ["write"]},
                secret_backend_ref="team-vault",
                output_policy={"allowFields": ["summary"]},
                materialization={"delivery": "temp-file", "ttlSeconds": 90},
            )
            receipt_path = root / "receipt.json"

            with self._approval_env():
                issue_exit, _, issue_stderr = _run_discovery(
                    "approval",
                    "issue",
                    "--resource-dir",
                    str(root),
                    "--name",
                    "tracker-writer",
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
                    "materialize",
                    "--operation",
                    "comment on ticket",
                    "--approval-receipt",
                    str(receipt_path),
                    "--json",
                )

        self.assertEqual(exit_code, 0, msg=stderr)
        payload = json.loads(stdout)
        plan = payload["result"]["plan"]
        self.assertEqual(plan["secretBackend"]["name"], "team-vault")
        self.assertEqual(plan["secretBackend"]["durability"], "service-persistent")
        self.assertEqual(plan["responseAllowlist"], ["summary"])
        self.assertEqual(plan["materialization"]["delivery"], "temp-file")
        self.assertEqual(plan["materializationLease"]["delivery"], "temp-file")
        self.assertTrue(plan["materializationLease"]["leaseId"].startswith("mtl_"))

    def test_connection_explain_rejects_invalid_secret_ref_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            _write_secret_backend(root, name="team-vault", backend_type="vault", durability="service-persistent")
            _write_connection_profile(
                root,
                name="tracker-writer",
                classification="confidential",
                allowed_access=["read", "write"],
                allowed_modes=["connect", "materialize"],
                secret_backend_ref="team-vault",
                secret_refs=["../escape"],
                materialization={"delivery": "temp-file", "ttlSeconds": 90},
            )

            exit_code, stdout, stderr = _run_discovery(
                "connection",
                "explain",
                "--resource-dir",
                str(root),
                "--name",
                "tracker-writer",
                "--access",
                "read",
                "--mode",
                "connect",
                "--operation",
                "inspect policy",
                "--json",
            )

        self.assertEqual(exit_code, 1)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "error")
        self.assertIn("secretRefs[0]", payload["reason"])

    def test_exec_run_applies_allowlist_and_secret_detectors_before_ai_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            connection_path = _write_connection_profile(
                root,
                name="mock-readonly",
                output_policy={"allowFields": ["summary", "echoedParams", "session_cookie"]},
            )

            exit_code, stdout, stderr = _run_discovery(
                "exec",
                "run",
                "--resource",
                str(connection_path),
                "--operation",
                "list repositories",
                "--params",
                json.dumps(
                    {
                        "query": "core",
                        "token": "super-secret-token-value",
                        "auth": "Bearer abcdefghijklmnopqrstuvwxyz",
                    }
                ),
                "--json",
            )

        self.assertEqual(exit_code, 0, msg=stderr)
        payload = json.loads(stdout)
        output = payload["result"]["output"]
        self.assertEqual(set(output), {"summary", "echoedParams", "session_cookie"})
        self.assertEqual(output["echoedParams"]["token"], "[redacted]")
        self.assertEqual(output["echoedParams"]["auth"], "[redacted]")
        self.assertEqual(output["session_cookie"], "[redacted]")


if __name__ == "__main__":
    unittest.main()
