from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any, Protocol, runtime_checkable

from ..kernel.command_api import CommandEnvelope
from ..kernel.job_api import JobEvent, JobHandle
from ..kernel.secrets import SecretBackendProfile


@runtime_checkable
class RuntimeAdapter(Protocol):
    adapter_id: str

    def start(self, request: Mapping[str, Any]) -> JobHandle:
        ...

    def poll(self, job_id: str) -> JobHandle:
        ...

    def cancel(self, job_id: str) -> JobHandle:
        ...

    def stream(self, job_id: str) -> Iterable[JobEvent]:
        ...


@runtime_checkable
class ConnectionAdapter(Protocol):
    adapter_id: str

    def test_connection(self, profile_name: str) -> CommandEnvelope:
        ...

    def execute(
        self,
        profile_name: str,
        action: str,
        params: Mapping[str, Any] | None = None,
        secret_bindings: Mapping[str, str] | None = None,
        connection: Mapping[str, Any] | None = None,
        materialization: Mapping[str, Any] | None = None,
    ) -> CommandEnvelope:
        ...


@runtime_checkable
class McpAdapter(Protocol):
    adapter_id: str

    def call_tool(
        self,
        server_name: str,
        tool_name: str,
        arguments: Mapping[str, Any] | None = None,
    ) -> CommandEnvelope:
        ...

    def read_resource(self, server_name: str, resource_uri: str) -> CommandEnvelope:
        ...


@runtime_checkable
class IdentityAdapter(Protocol):
    adapter_id: str

    def resolve_identity(
        self,
        subject: str,
        scopes: Iterable[str] = (),
    ) -> Mapping[str, Any]:
        ...


@runtime_checkable
class SecretBackendAdapter(Protocol):
    adapter_id: str

    def probe(self, profile: SecretBackendProfile) -> Mapping[str, Any]:
        ...
