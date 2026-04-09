from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = REPO_ROOT / "sdk" / "python" / "context_control_plane"
sys.path.insert(0, str(REPO_ROOT / "sdk" / "python"))

import context_control_plane  # noqa: E402


class CoreBoundaryPhaseFourTests(unittest.TestCase):
    def test_root_package_exposes_core_metadata_only(self) -> None:
        self.assertEqual(context_control_plane.CORE_PACKAGE_NAME, "ccp-core")
        self.assertEqual(context_control_plane.__version__, "0.1.0")
        self.assertTrue(callable(context_control_plane.build_version_payload))

    def test_root_package_no_longer_exports_distribution_helpers(self) -> None:
        self.assertFalse(hasattr(context_control_plane, "resolve_context"))
        self.assertFalse(hasattr(context_control_plane, "build_operator_snapshot"))
        self.assertFalse(hasattr(context_control_plane, "workflow_authoring_catalog"))

    def test_public_package_surface_is_physically_small(self) -> None:
        entries = {path.name for path in PACKAGE_ROOT.iterdir() if path.name != "__pycache__"}
        self.assertEqual(entries, {"__init__.py", "adapters", "cli.py", "kernel", "surfaces"})

    def test_repo_root_does_not_ship_legacy_distribution_directories(self) -> None:
        banned = {
            ".cursor",
            ".githooks",
            "context",
            "docs",
            "evals",
            "integrations",
            "mcps",
            "schemas",
            "scripts",
            "templates",
            "ui",
        }
        for name in banned:
            self.assertFalse((REPO_ROOT / name).exists(), msg=f"{name} should not be present in the public repo")

    def test_repo_root_surface_is_small_and_public_facing(self) -> None:
        entries = {path.name for path in REPO_ROOT.iterdir() if path.name not in {".git", ".ccp", "__pycache__", ".pytest_cache"}}
        self.assertEqual(
            entries,
            {
                ".gitignore",
                ".pre-commit-config.yaml",
                "CONTRIBUTING.md",
                "LICENSE",
                "README.md",
                "SECURITY.md",
                "context_control_plane",
                "pyproject.toml",
                "sdk",
                "tests",
            },
        )


if __name__ == "__main__":
    unittest.main()
