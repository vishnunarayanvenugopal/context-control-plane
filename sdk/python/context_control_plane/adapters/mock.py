from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from ..kernel.command_api import CommandEnvelope, CommandStatus


@dataclass(frozen=True)
class MockConnectionAdapter:
    adapter_id: str = "mock"
    response_allowlist: tuple[str, ...] = (
        "adapter",
        "profile",
        "summary",
        "echoedParams",
        "session_cookie",
        "secretRefCount",
        "secretRefNames",
    )

    def test_connection(self, profile_name: str) -> CommandEnvelope:
        return CommandEnvelope(
            status=CommandStatus.OK,
            result={
                "adapter": self.adapter_id,
                "profile": profile_name,
                "message": "mock connection is available",
            },
        )

    def execute(
        self,
        profile_name: str,
        action: str,
        params: Mapping[str, Any] | None = None,
        secret_bindings: Mapping[str, str] | None = None,
        connection: Mapping[str, Any] | None = None,
        materialization: Mapping[str, Any] | None = None,
    ) -> CommandEnvelope:
        request = dict(params or {})
        bindings = dict(secret_bindings or {})
        return CommandEnvelope(
            status=CommandStatus.OK,
            result={
                "adapter": self.adapter_id,
                "profile": profile_name,
                "summary": f"mock adapter executed {action}",
                "echoedParams": request,
                "session_cookie": "mock-session-cookie",
                "secretRefCount": len(bindings),
                "secretRefNames": sorted(bindings),
                "materialized": bool(materialization),
            },
        )
