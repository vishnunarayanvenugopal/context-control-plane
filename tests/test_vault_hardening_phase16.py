from __future__ import annotations

import json
import os
import ssl
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "sdk" / "python"))

from context_control_plane.adapters.secret_backends import read_secret_value  # noqa: E402
from context_control_plane.kernel import SecretBackendProfile, SecretDurability  # noqa: E402


class VaultHardeningPhaseSixteenTests(unittest.TestCase):
    def test_vault_approle_auth_fetches_client_token_before_secret_read(self) -> None:
        profile = SecretBackendProfile(
            name="team-vault",
            namespace="default",
            backend_type="vault",
            durability=SecretDurability.SERVICE_PERSISTENT,
            provider="vault",
            managed=False,
            config={
                "address": "https://vault.example.test",
                "authMethod": "approle",
                "authMount": "approle",
            },
            source="test",
        )

        class _Response:
            def __init__(self, payload: dict):
                self._payload = payload
                self.length = len(json.dumps(payload).encode("utf-8"))

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps(self._payload).encode("utf-8")

        with mock.patch.dict(
            os.environ,
            {
                "VAULT_ROLE_ID": "role-id-123",
                "VAULT_SECRET_ID": "secret-id-456",
            },
            clear=False,
        ):
            with mock.patch(
                "context_control_plane.adapters.secret_backends.urllib.request.urlopen",
                side_effect=[
                    _Response({"auth": {"client_token": "vault-session-token"}}),
                    _Response({"data": {"data": {"value": "top-secret"}}}),
                ],
            ) as open_mock:
                value = read_secret_value(profile, "github_pat")

        self.assertEqual(value, "top-secret")
        auth_request = open_mock.call_args_list[0].args[0]
        secret_request = open_mock.call_args_list[1].args[0]
        self.assertTrue(auth_request.full_url.endswith("/v1/auth/approle/login"))
        self.assertEqual(secret_request.get_header("X-vault-token"), "vault-session-token")

    def test_vault_verify_tls_false_uses_unverified_context(self) -> None:
        profile = SecretBackendProfile(
            name="team-vault",
            namespace="default",
            backend_type="vault",
            durability=SecretDurability.SERVICE_PERSISTENT,
            provider="vault",
            managed=False,
            config={
                "address": "https://vault.example.test",
                "verifyTls": False,
            },
            source="test",
        )

        class _Response:
            length = len(json.dumps({"data": {"data": {"value": "top-secret"}}}).encode("utf-8"))

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps({"data": {"data": {"value": "top-secret"}}}).encode("utf-8")

        sentinel = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        with mock.patch.dict(os.environ, {"VAULT_TOKEN": "vault-token"}, clear=False):
            with mock.patch("context_control_plane.adapters.secret_backends.ssl._create_unverified_context", return_value=sentinel) as ctx_mock:
                with mock.patch("context_control_plane.adapters.secret_backends.urllib.request.urlopen", return_value=_Response()) as open_mock:
                    read_secret_value(profile, "github_pat")

        ctx_mock.assert_called_once()
        self.assertIs(open_mock.call_args.kwargs["context"], sentinel)

    def test_vault_ca_cert_path_builds_named_context(self) -> None:
        profile = SecretBackendProfile(
            name="team-vault",
            namespace="default",
            backend_type="vault",
            durability=SecretDurability.SERVICE_PERSISTENT,
            provider="vault",
            managed=False,
            config={
                "address": "https://vault.example.test",
                "caCertPath": "/tmp/demo-ca.pem",
            },
            source="test",
        )

        class _Response:
            length = len(json.dumps({"data": {"data": {"value": "top-secret"}}}).encode("utf-8"))

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps({"data": {"data": {"value": "top-secret"}}}).encode("utf-8")

        sentinel = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        with mock.patch.dict(os.environ, {"VAULT_TOKEN": "vault-token"}, clear=False):
            with mock.patch("context_control_plane.adapters.secret_backends.ssl.create_default_context", return_value=sentinel) as ctx_mock:
                with mock.patch("context_control_plane.adapters.secret_backends.urllib.request.urlopen", return_value=_Response()) as open_mock:
                    read_secret_value(profile, "github_pat")

        ctx_mock.assert_called_once_with(cafile="/tmp/demo-ca.pem")
        self.assertIs(open_mock.call_args.kwargs["context"], sentinel)

    def test_vault_ignores_config_embedded_credentials(self) -> None:
        profile = SecretBackendProfile(
            name="team-vault",
            namespace="default",
            backend_type="vault",
            durability=SecretDurability.SERVICE_PERSISTENT,
            provider="vault",
            managed=False,
            config={
                "address": "https://vault.example.test",
                "token": "should-be-ignored",
            },
            source="test",
        )

        with self.assertRaisesRegex(Exception, "VAULT_TOKEN"):
            read_secret_value(profile, "github_pat")


if __name__ == "__main__":
    unittest.main()
