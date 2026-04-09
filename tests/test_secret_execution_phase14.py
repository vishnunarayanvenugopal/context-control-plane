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

from context_control_plane.adapters.secret_backends import read_secret_value  # noqa: E402
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


def _write_connection_profile(
    root: Path,
    *,
    name: str,
    secret_backend_ref: str,
    secret_refs: list[str],
    output_policy: dict | None = None,
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{name}.json"
    path.write_text(
        json.dumps(
            {
                "apiVersion": CORE_DEFAULT_API_VERSION,
                "kind": "ConnectionProfile",
                "metadata": {"name": name},
                "spec": {
                    "adapter": "mock",
                    "endpoint": "https://api.example.test",
                    "classification": "internal",
                    "allowedAccess": ["read"],
                    "allowedModes": ["connect"],
                    "defaultMode": "connect",
                    "secretBackendRef": secret_backend_ref,
                    "secretRefs": secret_refs,
                    "outputPolicy": output_policy
                    or {"allowFields": ["summary", "secretRefCount", "secretRefNames", "session_cookie"]},
                },
            }
        ),
        encoding="utf-8",
    )
    return path


class SecretExecutionPhaseFourteenTests(unittest.TestCase):
    def test_exec_run_resolves_secret_refs_without_leaking_secret_values(self) -> None:
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
            connection_path = _write_connection_profile(
                root,
                name="repo-reader",
                secret_backend_ref="local-store",
                secret_refs=["api_token"],
            )
            value_file = root / "secret.txt"
            value_file.write_text("super-secret-token-value\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {"CCP_TEST_FILE_KEY": "correct horse battery staple"}, clear=False):
                set_exit, _set_stdout, set_stderr = _run_discovery(
                    "secret",
                    "set",
                    "--resource-dir",
                    str(root),
                    "--backend",
                    "local-store",
                    "--secret",
                    "api_token",
                    "--value-file",
                    str(value_file),
                    "--json",
                )
                self.assertEqual(set_exit, 0, msg=set_stderr)

                exit_code, stdout, stderr = _run_discovery(
                    "exec",
                    "run",
                    "--resource-dir",
                    str(root),
                    "--name",
                    "repo-reader",
                    "--operation",
                    "list repositories",
                    "--json",
                )

        self.assertEqual(exit_code, 0, msg=stderr)
        self.assertNotIn("super-secret-token-value", stdout)
        payload = json.loads(stdout)
        output = payload["result"]["output"]
        self.assertEqual(output["secretRefCount"], 1)
        self.assertEqual(output["secretRefNames"], ["api_token"])
        started_event = payload["result"]["trace"]["spec"]["events"][0]
        self.assertEqual(started_event["payload"]["secretRefs"], ["api_token"])
        self.assertEqual(started_event["payload"]["secretRefCount"], 1)
        self.assertNotIn("super-secret-token-value", json.dumps(payload))

    def test_vault_read_uses_configured_headers_namespace_and_timeout(self) -> None:
        profile = SecretBackendProfile(
            name="team-vault",
            namespace="default",
            backend_type="vault",
            durability=SecretDurability.SERVICE_PERSISTENT,
            provider="vault",
            managed=False,
            config={
                "address": "https://vault.example.test",
                "namespace": "engineering",
                "timeoutSeconds": 7,
            },
            source="test",
        )

        class _Response:
            length = 1

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps({"data": {"data": {"value": "top-secret"}}}).encode("utf-8")

        with mock.patch.dict(os.environ, {"VAULT_TOKEN": "vault-token-value"}, clear=False):
            with mock.patch("context_control_plane.adapters.secret_backends.urllib.request.urlopen", return_value=_Response()) as open_mock:
                value = read_secret_value(profile, "github_pat")

        self.assertEqual(value, "top-secret")
        request = open_mock.call_args.args[0]
        timeout = open_mock.call_args.kwargs["timeout"]
        headers = {key.lower(): value for key, value in request.header_items()}
        self.assertEqual(timeout, 7)
        self.assertEqual(headers["x-vault-token"], "vault-token-value")
        self.assertEqual(headers["x-vault-namespace"], "engineering")


if __name__ == "__main__":
    unittest.main()
