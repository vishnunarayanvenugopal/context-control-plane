from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ..adapters import HttpJsonConnectionAdapter, MockConnectionAdapter
from ..adapters.interfaces import ConnectionAdapter
from .command_api import CommandStatus
from .execution import GovernedExecutionDecision
from .materialization import (
    cleanup_expired_materializations,
    cleanup_materialization_bundle,
    prepare_materialization_bundle,
)
from .secret_store import resolve_secret_bindings
from .secrets import sanitize_adapter_payload
from .tracing import TraceRecord, make_trace_event, sanitize_trace_value, save_trace_record


@dataclass(frozen=True)
class GovernedExecutionResult:
    status: CommandStatus
    reason: str
    operation: str
    adapter_id: str
    output: Mapping[str, Any]
    trace: TraceRecord | None = None
    trace_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "reason": self.reason,
            "operation": self.operation,
            "adapterId": self.adapter_id,
            "output": dict(self.output),
            "trace": None if self.trace is None else self.trace.to_dict(),
            "tracePath": self.trace_path,
        }


def _builtin_connection_adapters() -> dict[str, ConnectionAdapter]:
    mock = MockConnectionAdapter()
    http_json = HttpJsonConnectionAdapter()
    return {
        "http-json": http_json,
        "mock": mock,
    }


def _resolve_adapter(adapter_id: str, adapter_registry: Mapping[str, ConnectionAdapter] | None) -> ConnectionAdapter | None:
    registry = dict(_builtin_connection_adapters())
    if adapter_registry:
        registry.update(adapter_registry)
    return registry.get(str(adapter_id or "").strip())


def run_governed_execution(
    planning: GovernedExecutionDecision,
    *,
    params: Mapping[str, Any] | None = None,
    trace_dir: str = "",
    adapter_registry: Mapping[str, ConnectionAdapter] | None = None,
) -> GovernedExecutionResult:
    if planning.plan is None:
        return GovernedExecutionResult(
            status=planning.status,
            reason=planning.reason,
            operation=planning.operation,
            adapter_id="",
            output={},
        )

    plan = planning.plan
    adapter = _resolve_adapter(plan.adapter, adapter_registry)
    if adapter is None:
        return GovernedExecutionResult(
            status=CommandStatus.ERROR,
            reason=f"unsupported connection adapter {plan.adapter!r} for governed execution",
            operation=planning.operation,
            adapter_id=plan.adapter,
            output={},
        )

    params_payload = dict(params or {})
    response_allowlist = tuple(getattr(adapter, "response_allowlist", ())) or plan.response_allowlist
    if plan.response_allowlist:
        response_allowlist = plan.response_allowlist
    expired_cleanup = cleanup_expired_materializations()
    try:
        secret_bindings = (
            resolve_secret_bindings(plan.secret_backend_profile, secret_refs=plan.secret_refs)
            if plan.secret_backend_profile is not None and plan.secret_refs
            else {}
        )
    except Exception as exc:
        started_event = make_trace_event(
            "governed_execution_started",
            {
                "executionId": plan.execution_id,
                "operation": plan.operation,
                "adapter": plan.adapter,
                "connection": plan.connection_name,
                "access": plan.access,
                "mode": plan.mode,
                "approvalId": plan.approval_id,
                "secretBackend": plan.secret_backend,
                "secretRefs": list(plan.secret_refs),
            },
        )
        failed_event = make_trace_event(
            "governed_execution_failed",
            {
                "executionId": plan.execution_id,
                "status": "error",
                "reason": str(exc),
                "secretRefCount": len(plan.secret_refs),
                "expiredMaterializationsRemoved": expired_cleanup["expiredLeasesRemoved"],
            },
        )
        trace = TraceRecord(
            trace_id=plan.trace_id,
            execution_id=plan.execution_id,
            status=CommandStatus.ERROR.value,
            operation=plan.operation,
            connection_name=plan.connection_name,
            namespace=plan.namespace,
            adapter=plan.adapter,
            events=(started_event, failed_event),
        )
        trace_path = save_trace_record(trace, Path(trace_dir)) if trace_dir else ""
        return GovernedExecutionResult(
            status=CommandStatus.ERROR,
            reason=str(exc),
            operation=planning.operation,
            adapter_id=plan.adapter,
            output={},
            trace=trace,
            trace_path=trace_path,
        )
    materialization_bundle = None
    materialization_context: dict[str, Any] | None = None
    if plan.mode == "materialize" and plan.materialization_lease is not None:
        materialization_bundle = prepare_materialization_bundle(
            plan.materialization_lease,
            secret_bindings=secret_bindings,
        )
        materialization_context = materialization_bundle.to_adapter_context()
    started_event = make_trace_event(
        "governed_execution_started",
        {
            "executionId": plan.execution_id,
            "operation": plan.operation,
            "adapter": plan.adapter,
            "connection": plan.connection_name,
            "access": plan.access,
            "mode": plan.mode,
            "approvalId": plan.approval_id,
            "secretBackend": plan.secret_backend,
            "secretRefs": list(plan.secret_refs),
            "secretRefCount": len(secret_bindings),
            "expiredMaterializationsRemoved": expired_cleanup["expiredLeasesRemoved"],
            "materializationRuntime": None if materialization_bundle is None else materialization_bundle.to_runtime_summary(),
            "materializationLease": None if plan.materialization_lease is None else plan.materialization_lease.to_dict(),
        },
    )

    cleanup_summary = {"cleanupOnExitApplied": False, "bundleRemoved": False}
    try:
        envelope = adapter.execute(
            plan.connection_name,
            plan.operation,
            params_payload,
            secret_bindings=secret_bindings,
            connection=plan.connection_settings,
            materialization=materialization_context,
        )
    finally:
        if materialization_bundle is not None and materialization_bundle.lease.cleanup_on_exit:
            cleanup_summary = {
                "cleanupOnExitApplied": True,
                "bundleRemoved": bool(cleanup_materialization_bundle(materialization_bundle)["removed"]),
            }
    output_payload = envelope.result if isinstance(envelope.result, Mapping) else {"result": envelope.result}
    allowlisted_output = sanitize_adapter_payload(output_payload, allow_fields=response_allowlist)
    sanitized_output = sanitize_trace_value(allowlisted_output) if plan.sanitize_output else allowlisted_output
    finished_event = make_trace_event(
        "governed_execution_finished",
        {
            "executionId": plan.execution_id,
            "status": envelope.status.value,
            "adapter": plan.adapter,
            "output": sanitized_output,
            "materializationCleanup": cleanup_summary,
        },
    )
    trace = TraceRecord(
        trace_id=plan.trace_id,
        execution_id=plan.execution_id,
        status=envelope.status.value,
        operation=plan.operation,
        connection_name=plan.connection_name,
        namespace=plan.namespace,
        adapter=plan.adapter,
        events=(started_event, finished_event),
    )
    trace_path = ""
    if trace_dir:
        trace_path = save_trace_record(trace, Path(trace_dir))

    if envelope.status is not CommandStatus.OK:
        return GovernedExecutionResult(
            status=CommandStatus.ERROR,
            reason=envelope.reason or "adapter execution failed",
            operation=planning.operation,
            adapter_id=plan.adapter,
            output=dict(sanitized_output if isinstance(sanitized_output, Mapping) else {"result": sanitized_output}),
            trace=trace,
            trace_path=trace_path,
        )

    normalized_output = sanitized_output if isinstance(sanitized_output, Mapping) else {"result": sanitized_output}
    return GovernedExecutionResult(
        status=CommandStatus.OK,
        reason="governed execution completed",
        operation=planning.operation,
        adapter_id=plan.adapter,
        output=dict(normalized_output),
        trace=trace,
        trace_path=trace_path,
    )
