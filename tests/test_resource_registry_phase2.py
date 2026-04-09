from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "sdk" / "python"))

from context_control_plane.kernel import (  # noqa: E402
    InMemoryResourceRegistry,
    ResourceLoadError,
    load_resource_file,
    load_resources_from_dir,
)
from context_control_plane.kernel.resource_registry import (  # noqa: E402
    ResourceCompatibility,
    ResourceDocument,
    ResourceIdentifier,
    ResourceProvenance,
)
from context_control_plane.kernel.versioning import CompatibilityLevel  # noqa: E402


class ResourceRegistryPhaseTwoTests(unittest.TestCase):
    def test_load_resource_file_reads_native_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            resource_path = Path(tmp_dir) / "github.json"
            resource_path.write_text(
                json.dumps(
                    {
                        "apiVersion": "ccp.io/v1beta1",
                        "kind": "McpServer",
                        "metadata": {"name": "github"},
                        "spec": {"transport": "stdio"},
                        "compatibility": {"stability": "beta"},
                    }
                ),
                encoding="utf-8",
            )

            document = load_resource_file(resource_path, layer="local")

        self.assertEqual(document.identifier.kind, "McpServer")
        self.assertEqual(document.identifier.name, "github")
        self.assertEqual(document.provenance[0].layer, "local")
        self.assertTrue(document.provenance[0].native)

    def test_load_resources_from_dir_reads_all_json_resources(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "mcp").mkdir()
            (root / "policies").mkdir()
            (root / "mcp" / "github.json").write_text(
                json.dumps(
                    {
                        "apiVersion": "ccp.io/v1beta1",
                        "kind": "McpServer",
                        "metadata": {"name": "github"},
                        "spec": {"transport": "stdio"},
                    }
                ),
                encoding="utf-8",
            )
            (root / "policies" / "default.json").write_text(
                json.dumps(
                    {
                        "apiVersion": "ccp.io/v1beta1",
                        "kind": "GatewayPolicy",
                        "metadata": {"name": "default"},
                        "spec": {"mode": "strict"},
                    }
                ),
                encoding="utf-8",
            )

            documents = load_resources_from_dir(root, layer="builtin")

        self.assertEqual(
            sorted((doc.identifier.kind, doc.identifier.name) for doc in documents),
            [("GatewayPolicy", "default"), ("McpServer", "github")],
        )

    def test_registry_prefers_highest_precedence_layer_and_keeps_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            common_path = root / "common.json"
            local_path = root / "local.json"
            common_path.write_text(
                json.dumps(
                    {
                        "apiVersion": "ccp.io/v1beta1",
                        "kind": "McpServer",
                        "metadata": {"name": "github"},
                        "spec": {"transport": "stdio", "mode": "readonly"},
                    }
                ),
                encoding="utf-8",
            )
            local_path.write_text(
                json.dumps(
                    {
                        "apiVersion": "ccp.io/v1beta1",
                        "kind": "McpServer",
                        "metadata": {"name": "github"},
                        "spec": {"transport": "stdio", "mode": "write"},
                    }
                ),
                encoding="utf-8",
            )

            registry = InMemoryResourceRegistry(
                [
                    load_resource_file(common_path, layer="common"),
                    load_resource_file(local_path, layer="local"),
                ]
            )

            document = registry.get_resource(kind="McpServer", name="github")
            explanation = registry.explain_resource(kind="McpServer", name="github")

        self.assertIsNotNone(document)
        assert document is not None
        self.assertEqual(document.spec["mode"], "write")
        self.assertEqual(explanation["effective_layer"], "local")
        self.assertEqual(explanation["provenance"][0]["layer"], "local")
        self.assertEqual(explanation["provenance"][1]["layer"], "common")

    def test_registry_keeps_capabilities_generic_when_generated_documents_exist(self) -> None:
        generated = ResourceDocument(
            identifier=ResourceIdentifier(api_version="ccp.io/v1beta1", kind="McpServer", name="github"),
            spec={"transport": "stdio", "mode": "generated"},
            compatibility=ResourceCompatibility(stability=CompatibilityLevel.BETA),
            provenance=(ResourceProvenance(source="generated.json", layer="common", native=False),),
        )

        registry = InMemoryResourceRegistry([generated])

        capability_ids = [item.capability_id for item in registry.list_capabilities()]
        self.assertIn("resource-registry/v1beta1", capability_ids)
        self.assertNotIn("legacy-context-adapter/v1beta1", capability_ids)

    def test_registry_prefers_file_backed_over_generated_on_equal_layer(self) -> None:
        file_backed = ResourceDocument(
            identifier=ResourceIdentifier(api_version="ccp.io/v1beta1", kind="McpServer", name="github"),
            spec={"transport": "stdio", "mode": "native"},
            compatibility=ResourceCompatibility(stability=CompatibilityLevel.BETA),
            provenance=(ResourceProvenance(source="native.json", layer="common", native=True),),
        )
        generated = ResourceDocument(
            identifier=ResourceIdentifier(api_version="ccp.io/v1beta1", kind="McpServer", name="github"),
            metadata={"title": "Generated GitHub"},
            spec={"transport": "http", "mode": "generated"},
            compatibility=ResourceCompatibility(introduced_in="0.1", stability=CompatibilityLevel.BETA),
            provenance=(ResourceProvenance(source="generated.json", layer="common", native=False),),
        )

        registry = InMemoryResourceRegistry([generated, file_backed])
        explanation = registry.explain_resource(kind="McpServer", name="github")

        self.assertEqual(explanation["effective_layer"], "common")
        self.assertEqual(explanation["effective_source"], "native.json")
        self.assertTrue(explanation["native"])
        self.assertEqual(explanation["resource"]["spec"]["mode"], "native")
        self.assertEqual(explanation["provenance"][1]["source"], "generated.json")

    def test_registry_merges_partial_higher_layer_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            common_path = root / "common.json"
            local_path = root / "local.json"
            common_path.write_text(
                json.dumps(
                    {
                        "apiVersion": "ccp.io/v1beta1",
                        "kind": "McpServer",
                        "metadata": {"name": "github"},
                        "spec": {"transport": "stdio", "command": "gh-mcp", "mode": "readonly"},
                    }
                ),
                encoding="utf-8",
            )
            local_path.write_text(
                json.dumps(
                    {
                        "apiVersion": "ccp.io/v1beta1",
                        "kind": "McpServer",
                        "metadata": {"name": "github"},
                        "spec": {"mode": "write"},
                    }
                ),
                encoding="utf-8",
            )

            registry = InMemoryResourceRegistry(
                [
                    load_resource_file(common_path, layer="common"),
                    load_resource_file(local_path, layer="local"),
                ]
            )

            document = registry.get_resource(kind="McpServer", name="github")

        self.assertIsNotNone(document)
        assert document is not None
        self.assertEqual(document.spec["transport"], "stdio")
        self.assertEqual(document.spec["command"], "gh-mcp")
        self.assertEqual(document.spec["mode"], "write")

    def test_registry_uses_source_order_as_final_tiebreak_within_layer(self) -> None:
        alpha = ResourceDocument(
            identifier=ResourceIdentifier(api_version="ccp.io/v1beta1", kind="McpServer", name="github"),
            spec={"transport": "stdio", "mode": "readonly"},
            compatibility=ResourceCompatibility(stability=CompatibilityLevel.BETA),
            provenance=(ResourceProvenance(source="alpha.json", layer="local", native=True),),
        )
        omega = ResourceDocument(
            identifier=ResourceIdentifier(api_version="ccp.io/v1beta1", kind="McpServer", name="github"),
            spec={"mode": "write", "command": "gh-mcp"},
            compatibility=ResourceCompatibility(stability=CompatibilityLevel.BETA),
            provenance=(ResourceProvenance(source="omega.json", layer="local", native=True),),
        )

        registry = InMemoryResourceRegistry([omega, alpha])
        explanation = registry.explain_resource(kind="McpServer", name="github")

        self.assertEqual(explanation["effective_layer"], "local")
        self.assertEqual(explanation["effective_source"], "omega.json")
        self.assertEqual(explanation["resource"]["spec"]["transport"], "stdio")
        self.assertEqual(explanation["resource"]["spec"]["command"], "gh-mcp")
        self.assertEqual(explanation["resource"]["spec"]["mode"], "write")

    def test_resource_document_rejects_reserved_metadata_fields(self) -> None:
        with self.assertRaisesRegex(ValueError, "reserved fields"):
            ResourceDocument(
                identifier=ResourceIdentifier(api_version="ccp.io/v1beta1", kind="McpServer", name="github"),
                metadata={"name": "shadow"},
                spec={"transport": "stdio"},
            )

    def test_invalid_resource_file_fails_clearly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            resource_path = Path(tmp_dir) / "broken.json"
            resource_path.write_text(json.dumps({"kind": "McpServer", "metadata": {"name": "github"}, "spec": {}}), encoding="utf-8")

            with self.assertRaisesRegex(ResourceLoadError, "missing apiVersion"):
                load_resource_file(resource_path, layer="local")


if __name__ == "__main__":
    unittest.main()
