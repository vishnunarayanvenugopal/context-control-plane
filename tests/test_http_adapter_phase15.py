from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
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


def _write_secret_backend(root: Path, *, storage_path: Path) -> None:
    (root / "local-store.backend.json").write_text(
        json.dumps(
            {
                "apiVersion": CORE_DEFAULT_API_VERSION,
                "kind": "SecretBackend",
                "metadata": {"name": "local-store"},
                "spec": {
                    "type": "encrypted-file",
                    "durability": "local-persistent",
                    "provider": "encrypted-file",
                    "config": {
                        "storagePath": str(storage_path),
                        "passphraseEnvVar": "CCP_TEST_FILE_KEY",
                    },
                },
            }
        ),
        encoding="utf-8",
    )


def _write_http_connection(
    root: Path,
    *,
    name: str,
    endpoint: str,
    auth: dict,
    output_policy: dict,
    allowed_modes: list[str] | None = None,
    default_mode: str = "connect",
    materialization: dict | None = None,
) -> None:
    spec = {
        "adapter": "http-json",
        "endpoint": endpoint,
        "classification": "internal",
        "allowedAccess": ["read"],
        "allowedModes": allowed_modes or ["connect"],
        "defaultMode": default_mode,
        "secretBackendRef": "local-store",
        "secretRefs": ["api_token"],
        "auth": auth,
        "request": {"path": "/status", "method": "GET"},
        "outputPolicy": output_policy,
    }
    if materialization is not None:
        spec["materialization"] = materialization
    (root / f"{name}.json").write_text(
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


class _ApiHandler(BaseHTTPRequestHandler):
    authorization = ""

    def do_GET(self) -> None:  # noqa: N802
        payload = {
            "ok": True,
            "authorizationSeen": self.headers.get("Authorization", ""),
            "path": self.path,
        }
        encoded = json.dumps(payload).encode("utf-8")
        type(self).authorization = self.headers.get("Authorization", "")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


class HttpAdapterPhaseFifteenTests(unittest.TestCase):
    def _start_server(self) -> tuple[HTTPServer, threading.Thread]:
        server = HTTPServer(("127.0.0.1", 0), _ApiHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread

    def test_http_json_adapter_uses_secret_ref_bearer_auth_without_leaking_secret(self) -> None:
        server, thread = self._start_server()
        try:
            with tempfile.TemporaryDirectory() as tmp_dir:
                root = Path(tmp_dir) / "resources"
                root.mkdir(parents=True, exist_ok=True)
                value_file = root / "token.txt"
                value_file.write_text("super-secret-token-value\n", encoding="utf-8")
                _write_secret_backend(root, storage_path=root / "secrets.enc")
                _write_http_connection(
                    root,
                    name="repo-api",
                    endpoint=f"http://127.0.0.1:{server.server_port}",
                    auth={"type": "bearer", "secretRef": "api_token"},
                    output_policy={"allowFields": ["statusCode", "json", "summary"]},
                )
                with unittest.mock.patch.dict(os.environ, {"CCP_TEST_FILE_KEY": "correct horse battery staple"}, clear=False):
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
                        "repo-api",
                        "--operation",
                        "fetch status",
                        "--json",
                    )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1.0)

        self.assertEqual(exit_code, 0, msg=stderr)
        self.assertEqual(_ApiHandler.authorization, "Bearer super-secret-token-value")
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "ok")
        self.assertNotIn("super-secret-token-value", stdout)
        self.assertEqual(payload["result"]["output"]["statusCode"], 200)
        self.assertEqual(payload["result"]["output"]["json"]["authorizationSeen"], "[redacted]")

    def test_materialized_http_auth_cleans_files_and_expired_leases(self) -> None:
        server, thread = self._start_server()
        try:
            with tempfile.TemporaryDirectory() as tmp_dir:
                root = Path(tmp_dir) / "resources"
                root.mkdir(parents=True, exist_ok=True)
                materialization_root = Path(tmp_dir) / "runtime-materializations"
                os.environ["CCP_MATERIALIZATION_DIR"] = str(materialization_root)
                _write_secret_backend(root, storage_path=root / "secrets.enc")
                _write_http_connection(
                    root,
                    name="repo-api-materialized",
                    endpoint=f"http://127.0.0.1:{server.server_port}",
                    auth={"type": "bearer", "secretRef": "api_token", "source": "materialized-file"},
                    output_policy={"allowFields": ["statusCode", "summary"]},
                    allowed_modes=["materialize"],
                    default_mode="materialize",
                    materialization={"delivery": "temp-file", "ttlSeconds": 120, "cleanupOnRead": True, "cleanupOnExit": True},
                )
                stale_dir = materialization_root / "mtl_stale"
                stale_dir.mkdir(parents=True, exist_ok=True)
                value_file = root / "token.txt"
                value_file.write_text("super-secret-token-value\n", encoding="utf-8")
                (stale_dir / "lease.json").write_text(
                    json.dumps(
                        {
                            "lease": {
                                "leaseId": "mtl_stale",
                                "issuedAt": "2026-01-01T00:00:00Z",
                                "expiresAt": (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat().replace("+00:00", "Z"),
                                "delivery": "temp-file",
                                "backend": {"name": "local-store", "namespace": "default"},
                                "cleanupOnExit": True,
                                "cleanupOnRead": True,
                            },
                            "secretFiles": {},
                        }
                    ),
                    encoding="utf-8",
                )
                with unittest.mock.patch.dict(os.environ, {"CCP_TEST_FILE_KEY": "correct horse battery staple"}, clear=False):
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
                        "repo-api-materialized",
                        "--mode",
                        "materialize",
                        "--operation",
                        "fetch status",
                        "--json",
                    )
        finally:
            os.environ.pop("CCP_MATERIALIZATION_DIR", None)
            server.shutdown()
            server.server_close()
            thread.join(timeout=1.0)

        self.assertEqual(exit_code, 0, msg=stderr)
        payload = json.loads(stdout)
        started = payload["result"]["trace"]["spec"]["events"][0]["payload"]
        finished = payload["result"]["trace"]["spec"]["events"][-1]["payload"]
        self.assertEqual(started["expiredMaterializationsRemoved"], 1)
        self.assertEqual(started["materializationRuntime"]["secretRefCount"], 1)
        self.assertTrue(finished["materializationCleanup"]["cleanupOnExitApplied"])
        self.assertTrue(finished["materializationCleanup"]["bundleRemoved"])
        self.assertTrue((not materialization_root.exists()) or (not any(materialization_root.iterdir())))

    def test_http_json_adapter_rejects_absolute_url_retarget(self) -> None:
        server, thread = self._start_server()
        try:
            with tempfile.TemporaryDirectory() as tmp_dir:
                root = Path(tmp_dir) / "resources"
                root.mkdir(parents=True, exist_ok=True)
                value_file = root / "token.txt"
                value_file.write_text("super-secret-token-value\n", encoding="utf-8")
                _write_secret_backend(root, storage_path=root / "secrets.enc")
                _write_http_connection(
                    root,
                    name="repo-api",
                    endpoint=f"http://127.0.0.1:{server.server_port}",
                    auth={"type": "bearer", "secretRef": "api_token"},
                    output_policy={"allowFields": ["statusCode", "json", "summary"]},
                )
                with unittest.mock.patch.dict(os.environ, {"CCP_TEST_FILE_KEY": "correct horse battery staple"}, clear=False):
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
                        "repo-api",
                        "--operation",
                        "fetch status",
                        "--params",
                        json.dumps({"path": "https://example.com/steal"}),
                        "--json",
                    )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1.0)

        self.assertEqual(exit_code, 1)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "error")
        self.assertIn("configured endpoint origin", payload["reason"])


if __name__ == "__main__":
    unittest.main()
