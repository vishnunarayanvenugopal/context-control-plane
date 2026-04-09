from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "sdk" / "python"))

from context_control_plane.adapters import ConnectionAdapter, IdentityAdapter, McpAdapter, RuntimeAdapter  # noqa: E402
from context_control_plane.kernel import (  # noqa: E402
    ApprovalRef,
    Capability,
    CommandEnvelope,
    CommandStatus,
    CompatibilityLevel,
    JobEvent,
    JobHandle,
    JobStatus,
    NextAction,
    ResourceCompatibility,
    ResourceDocument,
    ResourceIdentifier,
    ResourceProvenance,
    ResourceRef,
)


class KernelPhaseOneTests(unittest.TestCase):
    def test_command_envelope_serializes_stable_shape(self) -> None:
        envelope = CommandEnvelope(
            status=CommandStatus.APPROVAL_REQUIRED,
            reason="write requires approval",
            next_action=NextAction(
                command="ccp approval request --tool github --access write",
                description="Request approval for the governed write action.",
            ),
            trace_id="trc_123",
            approval=ApprovalRef(approval_id="apr_123", mode="explicit"),
            resource_refs=(ResourceRef(kind="McpServer", name="github"),),
            result={"allowed": False},
        )

        payload = envelope.to_dict()

        self.assertEqual(payload["status"], "approval_required")
        self.assertEqual(payload["trace_id"], "trc_123")
        self.assertEqual(payload["approval"]["approval_id"], "apr_123")
        self.assertEqual(payload["resource_refs"][0]["name"], "github")
        self.assertEqual(payload["result"]["allowed"], False)

    def test_job_models_serialize_cleanly(self) -> None:
        handle = JobHandle(job_id="job_123", status=JobStatus.RUNNING, trace_id="trc_123", correlation_id="corr_123")
        event = JobEvent(job_id="job_123", event_type="progress", payload={"step": "poll"})

        self.assertEqual(handle.to_dict()["status"], "running")
        self.assertEqual(event.to_dict()["payload"]["step"], "poll")

    def test_resource_document_builds_public_envelope(self) -> None:
        document = ResourceDocument(
            identifier=ResourceIdentifier(
                api_version="ccp.io/v1beta1",
                kind="McpServer",
                name="github",
            ),
            metadata={"labels": {"ccp.io/layer": "local"}},
            spec={"transport": "stdio"},
            compatibility=ResourceCompatibility(
                introduced_in="0.1",
                stability=CompatibilityLevel.BETA,
            ),
            provenance=(ResourceProvenance(source="resources/mcpservers/github.json", layer="local"),),
        )

        payload = document.to_dict()

        self.assertEqual(payload["apiVersion"], "ccp.io/v1beta1")
        self.assertEqual(payload["kind"], "McpServer")
        self.assertEqual(payload["metadata"]["name"], "github")
        self.assertEqual(payload["compatibility"]["stability"], "beta")
        self.assertEqual(payload["provenance"][0]["layer"], "local")

    def test_capability_builds_stable_capability_id(self) -> None:
        capability = Capability(
            name="command-api",
            version="v1",
            stability=CompatibilityLevel.STABLE,
            description="Stable command envelope for northbound callers.",
        )

        payload = capability.to_dict()

        self.assertEqual(payload["capability_id"], "command-api/v1")
        self.assertEqual(payload["stability"], "stable")

    def test_adapter_protocols_are_publicly_importable(self) -> None:
        self.assertTrue(RuntimeAdapter)
        self.assertTrue(ConnectionAdapter)
        self.assertTrue(McpAdapter)
        self.assertTrue(IdentityAdapter)

    def test_kernel_imports_without_scripts_path(self) -> None:
        script = (
            "import json, sys\n"
            f"sdk_path = {str(REPO_ROOT / 'sdk' / 'python')!r}\n"
            "sys.path = [sdk_path] + [item for item in sys.path if '/scripts' not in item]\n"
            "import context_control_plane.kernel as kernel\n"
            "print(json.dumps(sorted(kernel.__all__)))\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", script],
            check=False,
            capture_output=True,
            text=True,
            env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("CommandEnvelope", result.stdout)


if __name__ == "__main__":
    unittest.main()
