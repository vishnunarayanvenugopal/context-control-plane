from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "sdk" / "python"))

from context_control_plane.kernel import PACK_API_VERSION, PackLoadError, load_pack_manifest_file  # noqa: E402
from context_control_plane.surfaces import cli as discovery_cli  # noqa: E402


def _run_discovery(*argv: str) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    exit_code = discovery_cli.run(list(argv), stdout=stdout, stderr=stderr)
    return exit_code, stdout.getvalue(), stderr.getvalue()


class UpgradePhaseFourTests(unittest.TestCase):
    def test_load_pack_manifest_file_reads_generic_pack_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            manifest_path = Path(tmp_dir) / "pack.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "apiVersion": PACK_API_VERSION,
                        "kind": "Pack",
                        "metadata": {"name": "github-readonly-starter", "version": "0.1.0"},
                        "spec": {
                            "displayName": "GitHub Read-Only Starter",
                            "requiresCore": ">=0.1 <0.3",
                            "requiresCapabilities": ["command-api/v1beta1", "resource-registry/v1beta1"],
                            "defaultActivation": "disabled",
                            "stability": "beta",
                        },
                    }
                ),
                encoding="utf-8",
            )

            manifest = load_pack_manifest_file(manifest_path)

        self.assertEqual(manifest.name, "github-readonly-starter")
        self.assertEqual(manifest.pack_id, "github-readonly-starter@0.1.0")
        self.assertEqual(manifest.requires_core, ">=0.1 <0.3")

    def test_upgrade_plan_checks_pack_manifest_compatibility(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            manifest_path = Path(tmp_dir) / "pack.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "apiVersion": PACK_API_VERSION,
                        "kind": "Pack",
                        "metadata": {"name": "github-readonly-starter", "version": "0.1.0"},
                        "spec": {
                            "requiresCore": ">=0.1 <0.3",
                            "requiresCapabilities": ["command-api/v1beta1", "resource-registry/v1beta1"],
                            "defaultActivation": "disabled",
                            "stability": "beta",
                        },
                    }
                ),
                encoding="utf-8",
            )

            exit_code, stdout, stderr = _run_discovery(
                "upgrade",
                "plan",
                "--target-version",
                "0.2.0",
                "--pack-manifest",
                str(manifest_path),
                "--json",
            )

        self.assertEqual(exit_code, 0, msg=stderr)
        payload = json.loads(stdout)
        self.assertEqual(payload["result"]["summary"]["autoMigrations"], 1)
        self.assertEqual(payload["result"]["summary"]["blockedItems"], 0)
        self.assertEqual(payload["result"]["packs"][0]["name"], "github-readonly-starter")
        self.assertEqual(payload["result"]["actions"][0]["disposition"], "auto")

    def test_upgrade_plan_returns_error_for_invalid_pack_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            manifest_path = Path(tmp_dir) / "pack.json"
            manifest_path.write_text(json.dumps({"kind": "Pack"}), encoding="utf-8")

            exit_code, stdout, stderr = _run_discovery(
                "upgrade",
                "plan",
                "--pack-manifest",
                str(manifest_path),
                "--json",
            )

        self.assertEqual(exit_code, 1)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "error")
        self.assertIn("pack manifest", payload["reason"])

    def test_invalid_pack_manifest_file_raises_load_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            manifest_path = Path(tmp_dir) / "pack.json"
            manifest_path.write_text(json.dumps({"kind": "Pack"}), encoding="utf-8")

            with self.assertRaises(PackLoadError):
                load_pack_manifest_file(manifest_path)

if __name__ == "__main__":
    unittest.main()
