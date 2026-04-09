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

from context_control_plane.adapters.secret_backends import OSKeychainSecretBackendAdapter  # noqa: E402
from context_control_plane.kernel import CORE_DEFAULT_API_VERSION, SecretBackendProfile, SecretDurability  # noqa: E402
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


class SecretOpsPhaseThirteenTests(unittest.TestCase):
    def test_secret_set_inspect_delete_roundtrip_for_memory_backend(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            _write_secret_backend(root, name="session-memory", backend_type="memory", durability="ephemeral")
            value_file = root / "secret.txt"
            value_file.write_text("super-secret-value\n", encoding="utf-8")

            set_exit, set_stdout, set_stderr = _run_discovery(
                "secret",
                "set",
                "--resource-dir",
                str(root),
                "--backend",
                "session-memory",
                "--secret",
                "github_pat",
                "--value-file",
                str(value_file),
                "--json",
            )
            self.assertEqual(set_exit, 0, msg=set_stderr)
            set_payload = json.loads(set_stdout)
            self.assertEqual(set_payload["status"], "ok")
            self.assertEqual(set_payload["result"]["secretName"], "github_pat")

            inspect_exit, inspect_stdout, inspect_stderr = _run_discovery(
                "secret",
                "inspect",
                "--resource-dir",
                str(root),
                "--backend",
                "session-memory",
                "--secret",
                "github_pat",
                "--json",
            )
            self.assertEqual(inspect_exit, 0, msg=inspect_stderr)
            inspect_payload = json.loads(inspect_stdout)
            self.assertTrue(inspect_payload["result"]["exists"])

            delete_exit, delete_stdout, delete_stderr = _run_discovery(
                "secret",
                "delete",
                "--resource-dir",
                str(root),
                "--backend",
                "session-memory",
                "--secret",
                "github_pat",
                "--json",
            )
            self.assertEqual(delete_exit, 0, msg=delete_stderr)
            delete_payload = json.loads(delete_stdout)
            self.assertFalse(delete_payload["result"]["exists"])

    def test_secret_set_inspect_delete_roundtrip_for_encrypted_file_backend(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            storage_path = root / "secrets.enc"
            _write_secret_backend(
                root,
                name="local-store",
                backend_type="encrypted-file",
                durability="local-persistent",
                config={"storagePath": str(storage_path), "passphraseEnvVar": "CCP_TEST_FILE_KEY"},
            )
            value_file = root / "secret.txt"
            value_file.write_text("super-secret-value\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {"CCP_TEST_FILE_KEY": "correct horse battery staple"}, clear=False):
                set_exit, set_stdout, set_stderr = _run_discovery(
                    "secret",
                    "set",
                    "--resource-dir",
                    str(root),
                    "--backend",
                    "local-store",
                    "--secret",
                    "github_pat",
                    "--value-file",
                    str(value_file),
                    "--json",
                )

                self.assertEqual(set_exit, 0, msg=set_stderr)
                self.assertTrue(storage_path.exists())
                self.assertNotIn("super-secret-value", storage_path.read_text(encoding="utf-8"))

                inspect_exit, inspect_stdout, inspect_stderr = _run_discovery(
                    "secret",
                    "inspect",
                    "--resource-dir",
                    str(root),
                    "--backend",
                    "local-store",
                    "--secret",
                    "github_pat",
                    "--json",
                )
                self.assertEqual(inspect_exit, 0, msg=inspect_stderr)
                inspect_payload = json.loads(inspect_stdout)
                self.assertTrue(inspect_payload["result"]["exists"])

                delete_exit, delete_stdout, delete_stderr = _run_discovery(
                    "secret",
                    "delete",
                    "--resource-dir",
                    str(root),
                    "--backend",
                    "local-store",
                    "--secret",
                    "github_pat",
                    "--json",
                )
                self.assertEqual(delete_exit, 0, msg=delete_stderr)
                delete_payload = json.loads(delete_stdout)
                self.assertFalse(delete_payload["result"]["exists"])

    def test_secret_set_rejects_direct_value_argument(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            storage_path = root / "secrets.enc"
            _write_secret_backend(
                root,
                name="local-store",
                backend_type="encrypted-file",
                durability="local-persistent",
                config={"storagePath": str(storage_path), "passphraseEnvVar": "CCP_TEST_FILE_KEY"},
            )
            with mock.patch.dict(os.environ, {"CCP_TEST_FILE_KEY": "correct horse battery staple"}, clear=False):
                exit_code, stdout, stderr = _run_discovery(
                    "secret",
                    "set",
                    "--resource-dir",
                    str(root),
                    "--backend",
                    "local-store",
                    "--secret",
                    "github_pat",
                    "--value",
                    "super-secret-value",
                    "--json",
                )

        self.assertEqual(exit_code, 1)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "error")
        self.assertIn("direct --value is disabled", payload["reason"])

    def test_macos_keychain_store_keeps_secret_out_of_command_line_args(self) -> None:
        profile = SecretBackendProfile(
            name="os-store",
            namespace="default",
            backend_type="os-keychain",
            durability=SecretDurability.LOCAL_PERSISTENT,
            provider="os-keychain",
            managed=False,
            config={"servicePrefix": "ccp-core"},
            source="test",
        )
        adapter = OSKeychainSecretBackendAdapter()
        completed = mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch("context_control_plane.adapters.secret_backends.platform.system", return_value="Darwin"):
            with mock.patch("context_control_plane.adapters.secret_backends.subprocess.run", return_value=completed) as run_mock:
                adapter.store(profile, "github_pat", "super-secret-value")

        args = run_mock.call_args.args[0]
        self.assertIn("security", args[0])
        self.assertNotIn("super-secret-value", args)
        self.assertEqual(run_mock.call_args.kwargs["input"], "super-secret-value")


if __name__ == "__main__":
    unittest.main()
