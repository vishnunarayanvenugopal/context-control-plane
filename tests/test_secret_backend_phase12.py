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
    backend_type: str,
    durability: str,
    config: dict | None = None,
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
                    "config": config or {},
                },
            }
        ),
        encoding="utf-8",
    )
    return path


class SecretBackendPhaseTwelveTests(unittest.TestCase):
    def test_secret_status_lists_backends_with_health_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            _write_secret_backend(root, name="local-store", backend_type="encrypted-file", durability="local-persistent")
            _write_secret_backend(root, name="team-vault", backend_type="vault", durability="service-persistent")

            exit_code, stdout, stderr = _run_discovery("secret", "status", "--resource-dir", str(root), "--json")

        self.assertEqual(exit_code, 0, msg=stderr)
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["result"]["summary"]["backends"], 2)
        names = {item["name"] for item in payload["result"]["backends"]}
        self.assertEqual(names, {"local-store", "team-vault"})

    def test_secret_explain_reports_vault_config_gap_without_showing_token(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            _write_secret_backend(
                root,
                name="team-vault",
                backend_type="vault",
                durability="ephemeral",
                config={"address": "http://localhost:8200", "tokenEnvVar": "VAULT_TOKEN"},
            )
            previous = os.environ.pop("VAULT_TOKEN", None)
            try:
                exit_code, stdout, stderr = _run_discovery(
                    "secret",
                    "explain",
                    "--resource-dir",
                    str(root),
                    "--name",
                    "team-vault",
                    "--json",
                )
            finally:
                if previous is not None:
                    os.environ["VAULT_TOKEN"] = previous

        self.assertEqual(exit_code, 1)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["result"]["backend"]["name"], "team-vault")
        self.assertEqual(payload["result"]["details"]["tokenPresent"], False)
        self.assertNotIn("super-secret", json.dumps(payload))
        self.assertTrue(payload["result"]["warnings"])

    def test_secret_explain_reports_encrypted_file_default_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            _write_secret_backend(root, name="local-store", backend_type="encrypted-file", durability="local-persistent")
            previous = os.environ.get("CCP_ENCRYPTED_FILE_KEY")
            os.environ["CCP_ENCRYPTED_FILE_KEY"] = "demo-passphrase"
            try:
                exit_code, stdout, stderr = _run_discovery(
                    "secret",
                    "explain",
                    "--resource-dir",
                    str(root),
                    "--name",
                    "local-store",
                    "--json",
                )
            finally:
                if previous is None:
                    os.environ.pop("CCP_ENCRYPTED_FILE_KEY", None)
                else:
                    os.environ["CCP_ENCRYPTED_FILE_KEY"] = previous

        self.assertEqual(exit_code, 0, msg=stderr)
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["result"]["backend"]["type"], "encrypted-file")
        self.assertIn("storagePath", payload["result"]["details"])


if __name__ == "__main__":
    unittest.main()
