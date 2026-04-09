from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "sdk" / "python"))

from context_control_plane import cli as top_level_cli  # noqa: E402
from context_control_plane.surfaces import cli as discovery_cli  # noqa: E402


def _run_discovery(*argv: str) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    exit_code = discovery_cli.run(list(argv), stdout=stdout, stderr=stderr)
    return exit_code, stdout.getvalue(), stderr.getvalue()


class CliPhaseThreeTests(unittest.TestCase):
    def test_version_json_uses_stable_command_envelope(self) -> None:
        exit_code, stdout, stderr = _run_discovery("version", "--json")

        self.assertEqual(exit_code, 0, msg=stderr)
        payload = json.loads(stdout)
        self.assertEqual(payload["apiVersion"], "ccp.io/runtime/v1beta1")
        self.assertEqual(payload["kind"], "CommandEnvelope")
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["result"]["package"]["name"], "ccp-core")
        self.assertEqual(payload["result"]["package"]["version"], "0.1.0")
        contract_names = {item["name"] for item in payload["result"]["contracts"]}
        self.assertIn("command-api", contract_names)

    def test_capabilities_json_lists_core_surface_and_registry_capabilities(self) -> None:
        exit_code, stdout, stderr = _run_discovery("capabilities", "--json")

        self.assertEqual(exit_code, 0, msg=stderr)
        payload = json.loads(stdout)
        capability_ids = {item["capability_id"] for item in payload["result"]["capabilities"]}
        self.assertIn("command-api/v1beta1", capability_ids)
        self.assertIn("resource-registry/v1beta1", capability_ids)
        self.assertIn("cli-discovery/v1beta1", capability_ids)
        self.assertIn("pack-manifest/v1beta1", capability_ids)
        self.assertIn("pack-health/v1beta1", capability_ids)
        self.assertIn("connection-safety/v1beta1", capability_ids)
        self.assertIn("secret-backend/v1beta1", capability_ids)
        self.assertIn("secret-backend-health/v1beta1", capability_ids)
        self.assertIn("secret-sanitization/v1beta1", capability_ids)
        self.assertIn("materialization-lifecycle/v1beta1", capability_ids)
        self.assertIn("secret-binding-resolution/v1beta1", capability_ids)
        self.assertIn("approval-receipt/v1beta1", capability_ids)
        self.assertIn("execution-plan/v1beta1", capability_ids)
        self.assertIn("execution-run/v1beta1", capability_ids)
        self.assertIn("gateway-policy-evaluation/v1beta1", capability_ids)
        self.assertIn("mcp-management/v1beta1", capability_ids)
        self.assertIn("mcp-security-report/v1beta1", capability_ids)
        self.assertIn("mcp-runtime-observation/v1beta1", capability_ids)
        self.assertIn("mcp-runtime-enforcement/v1beta1", capability_ids)
        self.assertIn("trace-inspection/v1beta1", capability_ids)
        self.assertIn("trace-record/v1beta1", capability_ids)
        self.assertIn("upgrade-plan/v1beta1", capability_ids)

    def test_resource_kinds_json_lists_supported_kinds(self) -> None:
        exit_code, stdout, stderr = _run_discovery("resource", "kinds", "--json")

        self.assertEqual(exit_code, 0, msg=stderr)
        payload = json.loads(stdout)
        kind_names = {item["kind"] for item in payload["result"]["resource_kinds"]}
        self.assertIn("McpServer", kind_names)
        self.assertIn("SecretBackend", kind_names)
        self.assertIn("TracePolicy", kind_names)
        self.assertIn("PackActivation", kind_names)
        self.assertIn("Pack", kind_names)
        self.assertIn("ApprovalReceipt", kind_names)
        self.assertIn("TraceRecord", kind_names)

    def test_schema_get_json_returns_compact_schema(self) -> None:
        exit_code, stdout, stderr = _run_discovery("schema", "get", "McpServer", "--json")

        self.assertEqual(exit_code, 0, msg=stderr)
        payload = json.loads(stdout)
        schema = payload["result"]["schema"]
        self.assertEqual(schema["kind"], "McpServer")
        self.assertIn("metadata.name", schema["required_fields"])
        self.assertIn("transport", schema["spec_fields"])

    def test_schema_get_supports_pack_manifest_contract(self) -> None:
        exit_code, stdout, stderr = _run_discovery("schema", "get", "Pack", "--json")

        self.assertEqual(exit_code, 0, msg=stderr)
        payload = json.loads(stdout)
        schema = payload["result"]["schema"]
        self.assertEqual(schema["kind"], "Pack")
        self.assertEqual(schema["apiVersion"], "ccp.io/pack/v1beta1")
        self.assertIn("metadata.version", schema["required_fields"])
        self.assertIn("requiresCore", schema["spec_fields"])

    def test_schema_get_supports_approval_receipt_contract(self) -> None:
        exit_code, stdout, stderr = _run_discovery("schema", "get", "ApprovalReceipt", "--json")

        self.assertEqual(exit_code, 0, msg=stderr)
        payload = json.loads(stdout)
        schema = payload["result"]["schema"]
        self.assertEqual(schema["kind"], "ApprovalReceipt")
        self.assertEqual(schema["apiVersion"], "ccp.io/runtime/v1beta1")
        self.assertIn("spec.operation", schema["required_fields"])
        self.assertIn("approvedBy", schema["spec_fields"])

    def test_schema_get_supports_trace_record_contract(self) -> None:
        exit_code, stdout, stderr = _run_discovery("schema", "get", "TraceRecord", "--json")

        self.assertEqual(exit_code, 0, msg=stderr)
        payload = json.loads(stdout)
        schema = payload["result"]["schema"]
        self.assertEqual(schema["kind"], "TraceRecord")
        self.assertEqual(schema["apiVersion"], "ccp.io/runtime/v1beta1")
        self.assertIn("spec.executionId", schema["required_fields"])
        self.assertIn("events", schema["spec_fields"])

    def test_unknown_schema_kind_returns_structured_error(self) -> None:
        exit_code, stdout, stderr = _run_discovery("schema", "get", "BananaServer", "--json")

        self.assertEqual(exit_code, 1)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "error")
        self.assertIn("unknown resource kind", payload["reason"])
        self.assertEqual(payload["next_action"]["command"], "ccp resource kinds --json")

    def test_resource_list_get_and_explain_use_default_resource_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            workspace = Path(tmp_dir)
            resource_root = workspace / "resources"
            resource_root.mkdir(parents=True, exist_ok=True)
            (resource_root / "github.json").write_text(
                json.dumps(
                    {
                        "apiVersion": "ccp.io/v1beta1",
                        "kind": "ConnectionProfile",
                        "metadata": {"name": "github"},
                        "spec": {
                            "adapter": "mock",
                            "endpoint": "https://api.example.test",
                            "classification": "internal",
                            "allowedAccess": ["read"],
                            "allowedModes": ["connect"],
                            "defaultMode": "connect",
                        },
                    }
                ),
                encoding="utf-8",
            )

            with mock.patch.object(Path, "cwd", return_value=workspace):
                list_exit, list_stdout, list_stderr = _run_discovery("resource", "list", "--json")
                get_exit, get_stdout, get_stderr = _run_discovery(
                    "resource",
                    "get",
                    "--kind",
                    "ConnectionProfile",
                    "--name",
                    "github",
                    "--json",
                )
                explain_exit, explain_stdout, explain_stderr = _run_discovery(
                    "resource",
                    "explain",
                    "--kind",
                    "ConnectionProfile",
                    "--name",
                    "github",
                    "--json",
                )

        self.assertEqual(list_exit, 0, msg=list_stderr)
        self.assertEqual(get_exit, 0, msg=get_stderr)
        self.assertEqual(explain_exit, 0, msg=explain_stderr)
        self.assertEqual(json.loads(list_stdout)["result"]["summary"]["count"], 1)
        self.assertEqual(json.loads(get_stdout)["result"]["resource"]["metadata"]["name"], "github")
        self.assertTrue(json.loads(explain_stdout)["result"]["found"])

    def test_upgrade_plan_json_returns_stable_summary(self) -> None:
        exit_code, stdout, stderr = _run_discovery("upgrade", "plan", "--target-version", "0.2.0", "--json")

        self.assertEqual(exit_code, 0, msg=stderr)
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["result"]["currentCoreVersion"], "0.1.0")
        self.assertEqual(payload["result"]["targetCoreVersion"], "0.2.0")
        self.assertEqual(payload["result"]["summary"]["blockedItems"], 0)

    def test_top_level_help_mentions_only_core_discovery_commands(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        previous_stdout, previous_stderr = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = stdout, stderr
        try:
            exit_code = top_level_cli.main(["--help"])
        finally:
            sys.stdout, sys.stderr = previous_stdout, previous_stderr

        self.assertEqual(exit_code, 0)
        help_text = stdout.getvalue()
        self.assertIn("approval", help_text)
        self.assertIn("capabilities", help_text)
        self.assertIn("connection", help_text)
        self.assertIn("doctor", help_text)
        self.assertIn("exec", help_text)
        self.assertIn("gateway", help_text)
        self.assertIn("mcp", help_text)
        self.assertIn("pack", help_text)
        self.assertIn("secret", help_text)
        self.assertIn("trace", help_text)
        self.assertIn("upgrade", help_text)
        self.assertIn("validate", help_text)
        self.assertNotIn("Legacy commands:", help_text)
        self.assertNotIn("access", help_text)
        self.assertEqual(stderr.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
