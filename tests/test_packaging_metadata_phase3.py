from __future__ import annotations

import sys
import unittest
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised only on older interpreters.
    tomllib = None

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "sdk" / "python"))

from context_control_plane.kernel.discovery import CORE_PACKAGE_NAME  # noqa: E402


class PackagingMetadataPhaseThreeTests(unittest.TestCase):
    def test_pyproject_uses_generic_core_metadata(self) -> None:
        if tomllib is None:
            self.skipTest("tomllib requires Python 3.11+ and matches the packaged ccp-core runtime floor")
        payload = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        project = payload["project"]

        self.assertEqual(project["name"], "ccp-core")
        self.assertEqual(project["name"], CORE_PACKAGE_NAME)
        self.assertEqual(project["authors"], [{"name": "CCP Core Contributors"}])
        self.assertEqual(project["readme"], "README.md")
        self.assertEqual(project["license"], {"file": "LICENSE"})
        self.assertIn("License :: OSI Approved :: Apache Software License", project["classifiers"])
        self.assertNotIn("License :: Other/Proprietary License", project["classifiers"])

    def test_pyproject_does_not_leak_company_specific_identity(self) -> None:
        pyproject_text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8").lower()

        self.assertNotIn("proprietary", pyproject_text)
        self.assertNotIn("internal only", pyproject_text)


if __name__ == "__main__":
    unittest.main()
