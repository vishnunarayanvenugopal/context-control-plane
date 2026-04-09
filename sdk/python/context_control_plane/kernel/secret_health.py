from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..adapters import probe_secret_backend
from .resource_registry import ResourceRegistry
from .secrets import SecretBackendProfile, SecretConfigurationError


@dataclass(frozen=True)
class SecretBackendStatusRecord:
    name: str
    namespace: str
    backend_type: str
    durability: str
    health: str
    reason: str
    capabilities: tuple[str, ...]
    warnings: tuple[str, ...]
    source: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "namespace": self.namespace,
            "type": self.backend_type,
            "durability": self.durability,
            "health": self.health,
            "reason": self.reason,
            "capabilities": list(self.capabilities),
            "warnings": list(self.warnings),
            "source": self.source,
        }


def build_secret_backend_status_records(
    registry: ResourceRegistry,
    *,
    namespace: str = "default",
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for document in registry.list_resources(kind="SecretBackend", namespace=namespace):
        profile = SecretBackendProfile.from_document(document)
        report = probe_secret_backend(profile)
        records.append(
            SecretBackendStatusRecord(
                name=profile.name,
                namespace=profile.namespace,
                backend_type=profile.backend_type,
                durability=profile.durability.value,
                health=str(report["health"]),
                reason=str(report["reason"]),
                capabilities=tuple(str(item) for item in report.get("capabilities", [])),
                warnings=tuple(str(item) for item in report.get("warnings", [])),
                source=profile.source,
            ).to_dict()
        )
    return records


def explain_secret_backend(
    registry: ResourceRegistry,
    *,
    name: str,
    namespace: str = "default",
) -> dict[str, Any]:
    document = registry.get_resource(kind="SecretBackend", name=name, namespace=namespace)
    if document is None:
        raise SecretConfigurationError(f"SecretBackend {name!r} was not found in namespace {namespace!r}")
    profile = SecretBackendProfile.from_document(document)
    return probe_secret_backend(profile)

