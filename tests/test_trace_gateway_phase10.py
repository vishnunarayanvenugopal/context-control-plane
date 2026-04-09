from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "sdk" / "python"))

from context_control_plane.kernel import (  # noqa: E402
    CORE_DEFAULT_API_VERSION,
    TraceRecord,
    make_trace_event,
    save_trace_record,
)
from context_control_plane.surfaces import cli as discovery_cli  # noqa: E402


def _run_discovery(*argv: str) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    exit_code = discovery_cli.run(list(argv), stdout=stdout, stderr=stderr)
    return exit_code, stdout.getvalue(), stderr.getvalue()


def _write_gateway_policy(
    root: Path,
    *,
    name: str,
    default_decision: str = "allow",
    rules: list[dict] | None = None,
    classifications: dict | None = None,
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{name}.json"
    path.write_text(
        json.dumps(
            {
                "apiVersion": CORE_DEFAULT_API_VERSION,
                "kind": "GatewayPolicy",
                "metadata": {"name": name},
                "spec": {
                    "defaults": {"decision": default_decision},
                    "rules": rules or [],
                    "classifications": classifications or {},
                },
            }
        ),
        encoding="utf-8",
    )
    return path


class TraceGatewayPhaseTenTests(unittest.TestCase):
    def test_trace_list_get_and_explain_work_from_trace_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            traces = root / "traces"
            trace = TraceRecord(
                trace_id="trc_demo_001",
                execution_id="exe_demo_001",
                status="ok",
                operation="list repositories",
                connection_name="github-readonly",
                namespace="default",
                adapter="mock",
                events=(
                    make_trace_event("governed_execution_started", {"token": "super-secret", "phase": "start"}),
                    make_trace_event("governed_execution_finished", {"result": "ok", "cookie": "session-cookie"}),
                ),
            )
            trace_path = save_trace_record(trace, traces)

            list_exit, list_stdout, list_stderr = _run_discovery("trace", "list", "--trace-dir", str(traces), "--json")
            get_exit, get_stdout, get_stderr = _run_discovery("trace", "get", "--trace", str(trace_path), "--json")
            explain_exit, explain_stdout, explain_stderr = _run_discovery(
                "trace",
                "explain",
                "--trace-dir",
                str(traces),
                "--id",
                "trc_demo_001",
                "--json",
            )

        self.assertEqual(list_exit, 0, msg=list_stderr)
        self.assertEqual(get_exit, 0, msg=get_stderr)
        self.assertEqual(explain_exit, 0, msg=explain_stderr)

        list_payload = json.loads(list_stdout)
        self.assertEqual(list_payload["result"]["summary"]["traces"], 1)
        self.assertEqual(list_payload["result"]["traces"][0]["traceId"], "trc_demo_001")

        get_payload = json.loads(get_stdout)
        self.assertEqual(get_payload["result"]["trace"]["metadata"]["name"], "trc_demo_001")

        explain_payload = json.loads(explain_stdout)
        self.assertEqual(explain_payload["trace_id"], "trc_demo_001")
        self.assertEqual(explain_payload["result"]["eventCount"], 2)
        self.assertEqual(explain_payload["result"]["redactedFieldCount"], 2)
        self.assertEqual(explain_payload["result"]["timeline"][0]["eventType"], "governed_execution_started")

    def test_gateway_status_and_explain_show_decision_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            _write_gateway_policy(
                root,
                name="default-gateway",
                default_decision="approval_required",
                rules=[
                    {"match": {"access": "write"}, "decision": "approval_required", "reason": "writes need approval"},
                    {"match": {"classification": "restricted"}, "decision": "deny", "reason": "restricted data is blocked"},
                ],
                classifications={
                    "confidential": {"decision": "approval_required", "warning": "confidential actions should stay reviewable"}
                },
            )

            status_exit, status_stdout, status_stderr = _run_discovery(
                "gateway",
                "status",
                "--resource-dir",
                str(root),
                "--json",
            )
            explain_exit, explain_stdout, explain_stderr = _run_discovery(
                "gateway",
                "explain",
                "--resource-dir",
                str(root),
                "--name",
                "default-gateway",
                "--access",
                "write",
                "--classification",
                "confidential",
                "--mode",
                "materialize",
                "--operation",
                "update repository",
                "--json",
            )

        self.assertEqual(status_exit, 0, msg=status_stderr)
        self.assertEqual(explain_exit, 1)
        self.assertEqual(explain_stderr, "")

        status_payload = json.loads(status_stdout)
        self.assertEqual(status_payload["result"]["summary"]["policies"], 1)
        self.assertEqual(status_payload["result"]["policies"][0]["defaultDecision"], "approval_required")

        explain_payload = json.loads(explain_stdout)
        self.assertEqual(explain_payload["status"], "approval_required")
        self.assertEqual(explain_payload["result"]["decision"], "approval_required")
        self.assertEqual(explain_payload["result"]["matchedRuleIndex"], 0)
        self.assertIn("writes need approval", explain_payload["reason"])
        self.assertEqual(explain_payload["approval"]["mode"], "explicit")


if __name__ == "__main__":
    unittest.main()
