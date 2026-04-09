from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "sdk" / "python"))

from context_control_plane.kernel import CORE_DEFAULT_API_VERSION, PACK_API_VERSION  # noqa: E402
from context_control_plane.surfaces import cli as discovery_cli  # noqa: E402


def _run_discovery(*argv: str) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    exit_code = discovery_cli.run(list(argv), stdout=stdout, stderr=stderr)
    return exit_code, stdout.getvalue(), stderr.getvalue()


def _write_pack_manifest(root: Path, *, name: str, version: str = "0.1.0", default_activation: str = "disabled") -> Path:
    pack_dir = root / name
    pack_dir.mkdir(parents=True, exist_ok=True)
    path = pack_dir / "pack.json"
    path.write_text(
        json.dumps(
            {
                "apiVersion": PACK_API_VERSION,
                "kind": "Pack",
                "metadata": {"name": name, "version": version},
                "spec": {
                    "requiresCore": ">=0.1 <1.0",
                    "defaultActivation": default_activation,
                    "stability": "beta",
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def _write_activation(
    root: Path,
    *,
    name: str,
    state: str,
    target_pack: str | None = None,
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{name}.json"
    spec = {"state": state}
    if target_pack is not None:
        spec["pack"] = target_pack
    path.write_text(
        json.dumps(
            {
                "apiVersion": CORE_DEFAULT_API_VERSION,
                "kind": "PackActivation",
                "metadata": {"name": name},
                "spec": spec,
            }
        ),
        encoding="utf-8",
    )
    return path


class ActivationPhaseFiveTests(unittest.TestCase):
    def test_pack_status_defaults_to_manifest_state_without_activation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            manifest_path = _write_pack_manifest(root, name="github-readonly-starter")

            exit_code, stdout, stderr = _run_discovery(
                "pack",
                "status",
                "--pack-manifest",
                str(manifest_path),
                "--json",
            )

        self.assertEqual(exit_code, 0, msg=stderr)
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["result"]["summary"]["packs"], 1)
        self.assertEqual(payload["result"]["summary"]["enabledPacks"], 0)
        self.assertEqual(payload["result"]["pack_status"][0]["effective_state"], "disabled")

    def test_pack_status_uses_activation_directory_to_enable_pack(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            packs_dir = root / "packs"
            activations_dir = root / "activations"
            _write_pack_manifest(packs_dir, name="github-readonly-starter")
            _write_activation(activations_dir, name="github-readonly-starter", state="enabled")

            exit_code, stdout, stderr = _run_discovery(
                "pack",
                "status",
                "--pack-dir",
                str(packs_dir),
                "--activation-dir",
                str(activations_dir),
                "--json",
            )

        self.assertEqual(exit_code, 0, msg=stderr)
        payload = json.loads(stdout)
        self.assertEqual(payload["result"]["summary"]["enabledPacks"], 1)
        self.assertEqual(payload["result"]["pack_status"][0]["effective_state"], "enabled")
        self.assertTrue(payload["result"]["pack_status"][0]["activation_source"].endswith("github-readonly-starter.json"))

    def test_validate_reports_unknown_pack_activation_as_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            activation_path = _write_activation(root / "activations", name="ghost-pack", state="enabled")

            exit_code, stdout, stderr = _run_discovery(
                "validate",
                "--activation-resource",
                str(activation_path),
                "--json",
            )

        self.assertEqual(exit_code, 1)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "error")
        issue_codes = {item["code"] for item in payload["result"]["issues"]}
        self.assertIn("unknown-pack-activation", issue_codes)

    def test_validate_reports_invalid_pack_activation_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            manifest_path = _write_pack_manifest(root / "packs", name="github-readonly-starter")
            activation_path = _write_activation(
                root / "activations",
                name="github-readonly-starter",
                state="maybe",
            )

            exit_code, stdout, stderr = _run_discovery(
                "validate",
                "--pack-manifest",
                str(manifest_path),
                "--activation-resource",
                str(activation_path),
                "--json",
            )

        self.assertEqual(exit_code, 1)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "error")
        issue_codes = {item["code"] for item in payload["result"]["issues"]}
        self.assertIn("invalid-pack-activation-state", issue_codes)

    def test_doctor_returns_recommendations_for_activation_issues(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            manifest_path = _write_pack_manifest(root / "packs", name="github-readonly-starter")
            activation_path = _write_activation(
                root / "activations",
                name="github-activation",
                state="enabled",
                target_pack="ghost-pack",
            )

            exit_code, stdout, stderr = _run_discovery(
                "doctor",
                "--pack-manifest",
                str(manifest_path),
                "--activation-resource",
                str(activation_path),
                "--json",
            )

        self.assertEqual(exit_code, 1)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["result"]["health"], "attention_needed")
        self.assertIn(
            "Remove or rename PackActivation resources that point at missing packs.",
            payload["result"]["recommendations"],
        )
        self.assertIn(
            "Align PackActivation metadata.name with the target pack name to keep precedence simple.",
            payload["result"]["recommendations"],
        )

    def test_validate_text_mode_prints_summary_and_issues(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            activation_path = _write_activation(root / "activations", name="ghost-pack", state="enabled")

            exit_code, stdout, stderr = _run_discovery(
                "validate",
                "--activation-resource",
                str(activation_path),
            )

        self.assertEqual(exit_code, 1)
        self.assertEqual(stderr, "")
        self.assertIn("Validation: packs=0 enabled=0 errors=1 warnings=0", stdout)
        self.assertIn("unknown-pack-activation", stdout)


if __name__ == "__main__":
    unittest.main()
