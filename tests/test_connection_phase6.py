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


def _write_connection_profile(
    root: Path,
    *,
    name: str,
    classification: str = "internal",
    allowed_access: list[str] | None = None,
    allowed_modes: list[str] | None = None,
    default_mode: str = "connect",
    approval: dict | None = None,
    secret_handling: dict | None = None,
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{name}.json"
    spec = {
        "adapter": "github",
        "endpoint": "https://api.example.test",
        "classification": classification,
        "allowedAccess": allowed_access or ["read"],
        "allowedModes": allowed_modes or ["connect"],
        "defaultMode": default_mode,
    }
    if approval is not None:
        spec["approval"] = approval
    if secret_handling is not None:
        spec["secretHandling"] = secret_handling
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


class ConnectionPhaseSixTests(unittest.TestCase):
    def test_connection_explain_defaults_to_safe_brokered_connect(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            resource_path = _write_connection_profile(Path(tmp_dir), name="github-readonly")

            exit_code, stdout, stderr = _run_discovery(
                "connection",
                "explain",
                "--resource",
                str(resource_path),
                "--json",
            )

        self.assertEqual(exit_code, 0, msg=stderr)
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["result"]["requestedMode"], "connect")
        self.assertEqual(payload["result"]["requestedAccess"], "read")
        self.assertTrue(payload["result"]["secretHandling"]["brokered"])
        self.assertFalse(payload["result"]["approval"]["required"])

    def test_connection_explain_requires_one_approval_for_confidential_materialize(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            resource_path = _write_connection_profile(
                Path(tmp_dir),
                name="tracker-writer",
                classification="confidential",
                allowed_access=["read", "write"],
                allowed_modes=["connect", "materialize"],
                approval={"requiredForAccess": ["write"]},
            )

            exit_code, stdout, stderr = _run_discovery(
                "connection",
                "explain",
                "--resource",
                str(resource_path),
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
        self.assertEqual(payload["approval"]["mode"], "explicit")
        self.assertEqual(payload["resource_refs"][0]["kind"], "ConnectionProfile")
        self.assertIn("requires one explicit approval receipt", payload["reason"])

    def test_connection_explain_denies_raw_secret_reveal_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            resource_path = _write_connection_profile(
                Path(tmp_dir),
                name="slack-admin",
                allowed_access=["read", "admin"],
                allowed_modes=["connect", "reveal"],
            )

            exit_code, stdout, stderr = _run_discovery(
                "connection",
                "explain",
                "--resource",
                str(resource_path),
                "--access",
                "admin",
                "--mode",
                "reveal",
                "--json",
            )

        self.assertEqual(exit_code, 1)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "denied")
        self.assertIn("raw secret reveal is disabled", payload["reason"])
        self.assertIn("--mode connect", payload["next_action"]["command"])

    def test_connection_explain_allows_raw_reveal_only_with_explicit_approval(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            resource_path = _write_connection_profile(
                Path(tmp_dir),
                name="kube-breakglass",
                classification="restricted",
                allowed_access=["read", "admin"],
                allowed_modes=["connect", "reveal"],
                approval={"requiredForModes": ["reveal"]},
                secret_handling={"allowRawSecretReveal": True, "brokered": False},
            )

            exit_code, stdout, stderr = _run_discovery(
                "connection",
                "explain",
                "--resource",
                str(resource_path),
                "--access",
                "admin",
                "--mode",
                "reveal",
                "--json",
            )

        self.assertEqual(exit_code, 1)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "approval_required")
        warnings = payload["result"]["warnings"]
        self.assertIn("raw secret reveal should stay exceptional and short-lived", warnings)
        self.assertIn("connection is not brokered; review downstream secret handling carefully", warnings)

    def test_connection_explain_requires_name_when_multiple_profiles_loaded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            _write_connection_profile(root, name="github-readonly")
            _write_connection_profile(root, name="tracker-readonly")

            exit_code, stdout, stderr = _run_discovery(
                "connection",
                "explain",
                "--resource-dir",
                str(root),
                "--json",
            )

        self.assertEqual(exit_code, 1)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "error")
        self.assertIn("multiple ConnectionProfile resources were loaded", payload["reason"])

    def test_connection_explain_text_mode_is_compact_and_actionable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            resource_path = _write_connection_profile(
                Path(tmp_dir),
                name="tracker-writer",
                classification="confidential",
                allowed_access=["read", "write"],
                allowed_modes=["connect", "materialize"],
            )

            exit_code, stdout, stderr = _run_discovery(
                "connection",
                "explain",
                "--resource",
                str(resource_path),
                "--access",
                "write",
                "--mode",
                "materialize",
            )

        self.assertEqual(exit_code, 1)
        self.assertEqual(stderr, "")
        self.assertIn("Connection: tracker-writer [approval_required]", stdout)
        self.assertIn("Classification: confidential", stdout)
        self.assertIn("Mode: materialize", stdout)


if __name__ == "__main__":
    unittest.main()
