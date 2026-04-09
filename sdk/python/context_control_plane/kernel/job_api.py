from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


class JobStatus(str, Enum):
    ACCEPTED = "accepted"
    QUEUED = "queued"
    RUNNING = "running"
    WAITING_APPROVAL = "waiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class JobHandle:
    job_id: str
    status: JobStatus
    trace_id: str = ""
    correlation_id: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "job_id": self.job_id,
            "status": self.status.value,
            "trace_id": self.trace_id,
            "correlation_id": self.correlation_id,
        }


@dataclass(frozen=True)
class JobEvent:
    job_id: str
    event_type: str
    payload: Mapping[str, Any] = field(default_factory=dict)
    event_id: str = ""
    trace_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "event_type": self.event_type,
            "payload": dict(self.payload),
            "event_id": self.event_id,
            "trace_id": self.trace_id,
        }
