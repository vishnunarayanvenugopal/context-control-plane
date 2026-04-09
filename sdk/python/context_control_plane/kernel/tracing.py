from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping
from uuid import uuid4

TRACE_API_VERSION = "ccp.io/runtime/v1beta1"
TRACE_KIND = "TraceRecord"

_SENSITIVE_KEY_PARTS = (
    "token",
    "secret",
    "password",
    "cookie",
    "authorization",
    "api_key",
    "apikey",
    "access_key",
    "session",
)

_SAFE_TRACE_METADATA_KEYS = frozenset({"secretrefcount", "secretrefnames", "secretrefs"})


class TraceLoadError(ValueError):
    """Raised when a trace record cannot be loaded."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _looks_sensitive(key: str) -> bool:
    lowered = str(key or "").strip().lower()
    if lowered in _SAFE_TRACE_METADATA_KEYS:
        return False
    return any(part in lowered for part in _SENSITIVE_KEY_PARTS)


def sanitize_trace_value(value: Any, *, field_name: str = "") -> Any:
    if field_name and _looks_sensitive(field_name):
        return "[redacted]"
    if isinstance(value, Mapping):
        return {
            str(key): sanitize_trace_value(item, field_name=str(key))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [sanitize_trace_value(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_trace_value(item) for item in value]
    return value


@dataclass(frozen=True)
class TraceEventRecord:
    event_id: str
    event_type: str
    recorded_at: str
    payload: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "eventId": self.event_id,
            "eventType": self.event_type,
            "recordedAt": self.recorded_at,
            "payload": sanitize_trace_value(self.payload),
        }


@dataclass(frozen=True)
class TraceRecord:
    trace_id: str
    execution_id: str
    status: str
    operation: str
    connection_name: str
    namespace: str
    adapter: str
    events: tuple[TraceEventRecord, ...]
    stored_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "apiVersion": TRACE_API_VERSION,
            "kind": TRACE_KIND,
            "metadata": {
                "name": self.trace_id,
                "namespace": self.namespace,
            },
            "spec": {
                "executionId": self.execution_id,
                "status": self.status,
                "operation": self.operation,
                "connection": {
                    "name": self.connection_name,
                    "namespace": self.namespace,
                    "adapter": self.adapter,
                },
                "events": [event.to_dict() for event in self.events],
                "storedAt": self.stored_at,
            },
        }


def make_trace_event(event_type: str, payload: Mapping[str, Any]) -> TraceEventRecord:
    return TraceEventRecord(
        event_id=f"evt_{uuid4().hex[:12]}",
        event_type=event_type,
        recorded_at=_utc_now(),
        payload=dict(payload),
    )


def save_trace_record(trace: TraceRecord, directory: str | Path) -> str:
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{trace.trace_id}.json"
    stored = TraceRecord(
        trace_id=trace.trace_id,
        execution_id=trace.execution_id,
        status=trace.status,
        operation=trace.operation,
        connection_name=trace.connection_name,
        namespace=trace.namespace,
        adapter=trace.adapter,
        events=trace.events,
        stored_at=_utc_now(),
    )
    path.write_text(json.dumps(stored.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    return str(path)


def load_trace_record_file(path: str | Path) -> TraceRecord:
    file_path = Path(path)
    try:
        payload = json.loads(file_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise TraceLoadError(f"trace file does not exist: {file_path}") from exc
    except json.JSONDecodeError as exc:
        raise TraceLoadError(f"invalid JSON in trace file {file_path}: {exc}") from exc

    if not isinstance(payload, Mapping):
        raise TraceLoadError("trace document must be a JSON object")
    if str(payload.get("kind", "") or "").strip() != TRACE_KIND:
        raise TraceLoadError(f"trace document kind must be {TRACE_KIND!r}")

    metadata = payload.get("metadata", {})
    if not isinstance(metadata, Mapping):
        raise TraceLoadError("trace metadata must be a JSON object")
    spec = payload.get("spec", {})
    if not isinstance(spec, Mapping):
        raise TraceLoadError("trace spec must be a JSON object")
    connection = spec.get("connection", {})
    if not isinstance(connection, Mapping):
        raise TraceLoadError("trace spec.connection must be a JSON object")
    events_raw = spec.get("events", [])
    if not isinstance(events_raw, list):
        raise TraceLoadError("trace spec.events must be a JSON array")

    events: list[TraceEventRecord] = []
    for item in events_raw:
        if not isinstance(item, Mapping):
            raise TraceLoadError("trace events must be JSON objects")
        payload_value = item.get("payload", {})
        if payload_value in (None, ""):
            payload_value = {}
        if not isinstance(payload_value, Mapping):
            raise TraceLoadError("trace event payload must be a JSON object")
        events.append(
            TraceEventRecord(
                event_id=str(item.get("eventId", "") or "").strip(),
                event_type=str(item.get("eventType", "") or "").strip(),
                recorded_at=str(item.get("recordedAt", "") or "").strip(),
                payload={str(key): payload_value[key] for key in payload_value},
            )
        )

    return TraceRecord(
        trace_id=str(metadata.get("name", "") or "").strip(),
        execution_id=str(spec.get("executionId", "") or "").strip(),
        status=str(spec.get("status", "") or "").strip(),
        operation=str(spec.get("operation", "") or "").strip(),
        connection_name=str(connection.get("name", "") or "").strip(),
        namespace=str(metadata.get("namespace", "default") or "default").strip() or "default",
        adapter=str(connection.get("adapter", "") or "").strip(),
        events=tuple(events),
        stored_at=str(spec.get("storedAt", "") or "").strip(),
    )


def load_trace_records_from_dir(path: str | Path) -> list[TraceRecord]:
    root = Path(path)
    if not root.exists():
        return []
    if not root.is_dir():
        raise TraceLoadError(f"trace directory does not exist: {root}")
    records: list[TraceRecord] = []
    for file_path in sorted(root.glob("*.json")):
        try:
            records.append(load_trace_record_file(file_path))
        except TraceLoadError:
            continue
    return sorted(records, key=lambda item: (item.stored_at, item.trace_id), reverse=True)


def summarize_trace_record(trace: TraceRecord) -> dict[str, Any]:
    return {
        "traceId": trace.trace_id,
        "executionId": trace.execution_id,
        "status": trace.status,
        "operation": trace.operation,
        "connection": {
            "name": trace.connection_name,
            "namespace": trace.namespace,
            "adapter": trace.adapter,
        },
        "eventCount": len(trace.events),
        "eventTypes": [event.event_type for event in trace.events],
        "storedAt": trace.stored_at,
    }


def explain_trace_record(trace: TraceRecord) -> dict[str, Any]:
    redacted_fields = 0
    for event in trace.events:
        redacted_fields += _count_redacted_values(event.payload)
    return {
        **summarize_trace_record(trace),
        "timeline": [
            {
                "eventId": event.event_id,
                "eventType": event.event_type,
                "recordedAt": event.recorded_at,
            }
            for event in trace.events
        ],
        "redactedFieldCount": redacted_fields,
        "finalEvent": None if not trace.events else trace.events[-1].to_dict(),
    }


def _count_redacted_values(value: Any) -> int:
    if isinstance(value, Mapping):
        return sum(_count_redacted_values(item) for item in value.values())
    if isinstance(value, list):
        return sum(_count_redacted_values(item) for item in value)
    return 1 if value == "[redacted]" else 0
