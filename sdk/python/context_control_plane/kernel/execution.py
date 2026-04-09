from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Mapping
from uuid import uuid4

from .approvals import ApprovalReceiptRecord, validate_approval_receipt
from .command_api import CommandStatus
from .resource_registry import ResourceDocument
from .secrets import MaterializationLease, SecretBackendProfile, issue_materialization_lease
from .security import ConnectionMode, ConnectionSafetyDecision


@dataclass(frozen=True)
class ExecutionPlan:
    execution_id: str
    trace_id: str
    operation: str
    connection_name: str
    namespace: str
    adapter: str
    endpoint: str
    access: str
    mode: str
    classification: str
    brokered: bool
    sanitize_input: bool
    sanitize_output: bool
    credential_delivery: str
    secret_exposure: str
    env_var_injection: bool
    secret_backend: dict[str, Any]
    secret_refs: tuple[str, ...] = field(default_factory=tuple)
    response_allowlist: tuple[str, ...] = field(default_factory=tuple)
    materialization: dict[str, Any] = field(default_factory=dict)
    materialization_lease: MaterializationLease | None = None
    approval_id: str = ""
    notes: tuple[str, ...] = field(default_factory=tuple)
    secret_backend_profile: SecretBackendProfile | None = field(default=None, repr=False, compare=False)
    connection_settings: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "executionId": self.execution_id,
            "traceId": self.trace_id,
            "operation": self.operation,
            "connection": {
                "name": self.connection_name,
                "namespace": self.namespace,
                "adapter": self.adapter,
                "endpoint": self.endpoint,
            },
            "access": self.access,
            "mode": self.mode,
            "classification": self.classification,
            "brokered": self.brokered,
            "sanitizeInput": self.sanitize_input,
            "sanitizeOutput": self.sanitize_output,
            "credentialDelivery": self.credential_delivery,
            "secretExposure": self.secret_exposure,
            "envVarInjection": self.env_var_injection,
            "secretBackend": dict(self.secret_backend),
            "secretRefs": list(self.secret_refs),
            "responseAllowlist": list(self.response_allowlist),
            "materialization": dict(self.materialization),
            "materializationLease": None if self.materialization_lease is None else self.materialization_lease.to_dict(),
            "approvalId": self.approval_id,
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class GovernedExecutionDecision:
    status: CommandStatus
    reason: str
    connection: ConnectionSafetyDecision
    operation: str
    approval_required: bool
    approval_satisfied: bool
    approval_receipt: ApprovalReceiptRecord | None = None
    plan: ExecutionPlan | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "reason": self.reason,
            "operation": self.operation,
            "approvalRequired": self.approval_required,
            "approvalSatisfied": self.approval_satisfied,
            "connection": self.connection.to_dict(),
            "approvalReceipt": None if self.approval_receipt is None else self.approval_receipt.to_dict(),
            "plan": None if self.plan is None else self.plan.to_dict(),
        }


def build_connection_approval_binding(
    *,
    decision: ConnectionSafetyDecision,
    operation: str,
    connection_document: ResourceDocument | None = None,
) -> dict[str, Any]:
    document_payload: dict[str, Any] = {}
    if connection_document is not None:
        document_payload = deepcopy(connection_document.to_dict())
        document_payload.pop("provenance", None)
    return {
        "subject": {
            "kind": "ConnectionProfile",
            "name": decision.connection_name,
            "namespace": decision.namespace,
        },
        "operation": str(operation or "").strip(),
        "access": decision.requested_access.value,
        "mode": decision.requested_mode.value,
        "connection": {
            "adapter": decision.adapter,
            "endpoint": decision.endpoint,
            "classification": decision.classification.value,
        },
        "gateway": {
            "policyName": decision.gateway_policy_name,
            "decision": decision.gateway_decision,
            "reason": decision.gateway_reason,
        },
        "resource": document_payload,
    }


def _credential_delivery(decision: ConnectionSafetyDecision) -> str:
    if decision.requested_mode is ConnectionMode.CONNECT:
        return "brokered"
    if decision.requested_mode is ConnectionMode.MATERIALIZE:
        return decision.secret_controls.materialization.delivery.value
    return "explicit-reveal"


def _secret_exposure(decision: ConnectionSafetyDecision) -> str:
    if decision.requested_mode is ConnectionMode.CONNECT:
        return "sanitized-result-only"
    if decision.requested_mode is ConnectionMode.MATERIALIZE:
        return "ephemeral-materialization-no-chat-secret"
    return "explicit-reveal"


def _notes_for_plan(decision: ConnectionSafetyDecision) -> tuple[str, ...]:
    notes: list[str] = ["governed execution must record a trace for this request"]
    if decision.secret_handling.brokered:
        notes.append("credentials stay brokered and should not be copied into chat or shell history")
    if decision.requested_mode is ConnectionMode.MATERIALIZE:
        notes.append("materialized credentials should stay ephemeral and avoid environment-variable sprawl")
        notes.append(
            f"materialization TTL is {decision.secret_controls.materialization.ttl_seconds}s via "
            f"{decision.secret_controls.materialization.delivery.value}"
        )
    if decision.secret_controls.secret_refs:
        notes.append(
            "secret_refs are resolved inside ccp-core and should never be copied into chat, stdout, or broad shell state"
        )
    if decision.requested_mode is ConnectionMode.REVEAL:
        notes.append("explicit reveal should be exceptional and tightly scoped")
    notes.extend(decision.warnings)
    return tuple(notes)


def build_connection_execution_plan(
    decision: ConnectionSafetyDecision,
    *,
    operation: str,
    approval_receipt: ApprovalReceiptRecord | None = None,
    connection_document: ResourceDocument | None = None,
) -> GovernedExecutionDecision:
    requested_operation = str(operation or "").strip()
    if not requested_operation:
        raise ValueError("execution operation is required")

    if not decision.allowed:
        return GovernedExecutionDecision(
            status=CommandStatus.DENIED,
            reason=decision.reason,
            connection=decision,
            operation=requested_operation,
            approval_required=False,
            approval_satisfied=False,
        )

    if decision.approval_required:
        approval_binding = build_connection_approval_binding(
            decision=decision,
            operation=requested_operation,
            connection_document=connection_document,
        )
        if approval_receipt is None:
            return GovernedExecutionDecision(
                status=CommandStatus.APPROVAL_REQUIRED,
                reason="one explicit approval receipt is required before governed execution",
                connection=decision,
                operation=requested_operation,
                approval_required=True,
                approval_satisfied=False,
            )
        valid, receipt_reason = validate_approval_receipt(
            approval_receipt,
            subject_kind="ConnectionProfile",
            subject_name=decision.connection_name,
            namespace=decision.namespace,
            access=decision.requested_access.value,
            mode=decision.requested_mode.value,
            operation=requested_operation,
            binding=approval_binding,
        )
        if not valid:
            return GovernedExecutionDecision(
                status=CommandStatus.DENIED,
                reason=receipt_reason,
                connection=decision,
                operation=requested_operation,
                approval_required=True,
                approval_satisfied=False,
                approval_receipt=approval_receipt,
            )

    materialization_lease = None
    if decision.requested_mode is ConnectionMode.MATERIALIZE:
        materialization_lease = issue_materialization_lease(
            backend=decision.secret_controls.backend,
            policy=decision.secret_controls.materialization,
        )

    plan = ExecutionPlan(
        execution_id=f"exe_{uuid4().hex[:12]}",
        trace_id=f"trc_{uuid4().hex[:12]}",
        operation=requested_operation,
        connection_name=decision.connection_name,
        namespace=decision.namespace,
        adapter=decision.adapter,
        endpoint=decision.endpoint,
        access=decision.requested_access.value,
        mode=decision.requested_mode.value,
        classification=decision.classification.value,
        brokered=decision.secret_handling.brokered,
        sanitize_input=decision.secret_handling.sanitize_input,
        sanitize_output=decision.secret_handling.sanitize_output,
        credential_delivery=_credential_delivery(decision),
        secret_exposure=_secret_exposure(decision),
        env_var_injection=False,
        secret_backend=decision.secret_controls.backend.to_dict(),
        secret_refs=decision.secret_controls.secret_refs,
        response_allowlist=decision.secret_controls.response_allowlist.allow_fields,
        materialization=decision.secret_controls.materialization.to_dict(),
        materialization_lease=materialization_lease,
        approval_id="" if approval_receipt is None else approval_receipt.approval_id,
        notes=_notes_for_plan(decision),
        secret_backend_profile=decision.secret_controls.backend,
        connection_settings=_extract_connection_settings(connection_document, decision),
    )
    return GovernedExecutionDecision(
        status=CommandStatus.OK,
        reason="execution plan is ready",
        connection=decision,
        operation=requested_operation,
        approval_required=decision.approval_required,
        approval_satisfied=approval_receipt is not None if decision.approval_required else True,
        approval_receipt=approval_receipt,
        plan=plan,
    )


def _extract_connection_settings(
    document: ResourceDocument | None,
    decision: ConnectionSafetyDecision,
) -> Mapping[str, Any]:
    if document is None:
        return {
            "endpoint": decision.endpoint,
            "adapter": decision.adapter,
        }
    spec = document.spec
    return {
        "endpoint": decision.endpoint,
        "adapter": decision.adapter,
        "auth": dict(spec.get("auth", {})) if isinstance(spec.get("auth"), Mapping) else {},
        "headers": dict(spec.get("headers", {})) if isinstance(spec.get("headers"), Mapping) else {},
        "timeouts": dict(spec.get("timeouts", {})) if isinstance(spec.get("timeouts"), Mapping) else {},
        "request": dict(spec.get("request", {})) if isinstance(spec.get("request"), Mapping) else {},
        "mode": decision.requested_mode.value,
    }
