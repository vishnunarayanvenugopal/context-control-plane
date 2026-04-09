from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

COMMAND_ENVELOPE_API_VERSION = "ccp.io/runtime/v1beta1"
COMMAND_ENVELOPE_KIND = "CommandEnvelope"


class CommandStatus(str, Enum):
    OK = "ok"
    DENIED = "denied"
    APPROVAL_REQUIRED = "approval_required"
    ACCEPTED = "accepted"
    ERROR = "error"


@dataclass(frozen=True)
class NextAction:
    command: str = ""
    description: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "command": self.command,
            "description": self.description,
        }


@dataclass(frozen=True)
class ApprovalRef:
    approval_id: str = ""
    mode: str = ""
    reference_kind: str = "receipt"

    def to_dict(self) -> dict[str, str]:
        return {
            "approvalId": self.approval_id,
            "mode": self.mode,
            "referenceKind": self.reference_kind,
            "approval_id": self.approval_id,
        }


@dataclass(frozen=True)
class ResourceRef:
    kind: str
    name: str
    namespace: str = "default"

    def to_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "name": self.name,
            "namespace": self.namespace,
        }


def _normalize_result(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _normalize_result(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_normalize_result(item) for item in value]
    if isinstance(value, list):
        return [_normalize_result(item) for item in value]
    return value


@dataclass(frozen=True)
class CommandEnvelope:
    status: CommandStatus
    reason: str = ""
    next_action: NextAction | None = None
    trace_id: str = ""
    approval: ApprovalRef | None = None
    resource_refs: tuple[ResourceRef, ...] = field(default_factory=tuple)
    result: Any = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        next_action = None if self.next_action is None else self.next_action.to_dict()
        approval = None if self.approval is None else self.approval.to_dict()
        resource_refs = [item.to_dict() for item in self.resource_refs]
        return {
            "apiVersion": COMMAND_ENVELOPE_API_VERSION,
            "kind": COMMAND_ENVELOPE_KIND,
            "status": self.status.value,
            "reason": self.reason,
            "nextAction": next_action,
            "traceId": self.trace_id,
            "approval": approval,
            "resourceRefs": resource_refs,
            "result": _normalize_result(self.result),
            "next_action": next_action,
            "trace_id": self.trace_id,
            "resource_refs": resource_refs,
        }
