from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol, runtime_checkable

from .versioning import Capability, CompatibilityLevel


@dataclass(frozen=True)
class ResourceIdentifier:
    api_version: str
    kind: str
    name: str
    namespace: str = "default"

    def to_dict(self) -> dict[str, str]:
        return {
            "apiVersion": self.api_version,
            "kind": self.kind,
            "name": self.name,
            "namespace": self.namespace,
        }


@dataclass(frozen=True)
class ResourceProvenance:
    source: str
    layer: str = ""
    native: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "layer": self.layer,
            "native": self.native,
        }


@dataclass(frozen=True)
class ResourceCompatibility:
    introduced_in: str = ""
    deprecated_in: str = ""
    replaced_by: str = ""
    stability: CompatibilityLevel = CompatibilityLevel.EXPERIMENTAL

    def to_dict(self) -> dict[str, str]:
        return {
            "introducedIn": self.introduced_in,
            "deprecatedIn": self.deprecated_in,
            "replacedBy": self.replaced_by,
            "stability": self.stability.value,
        }


@dataclass(frozen=True)
class ResourceDocument:
    identifier: ResourceIdentifier
    spec: Mapping[str, Any]
    metadata: Mapping[str, Any] = field(default_factory=dict)
    compatibility: ResourceCompatibility = field(default_factory=ResourceCompatibility)
    provenance: tuple[ResourceProvenance, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        reserved = {"name", "namespace"} & set(self.metadata)
        if reserved:
            reserved_text = ", ".join(sorted(reserved))
            raise ValueError(f"resource metadata must not override reserved fields: {reserved_text}")

    def to_dict(self) -> dict[str, Any]:
        metadata = {
            "name": self.identifier.name,
            "namespace": self.identifier.namespace,
        }
        metadata.update(dict(self.metadata))
        return {
            "apiVersion": self.identifier.api_version,
            "kind": self.identifier.kind,
            "metadata": metadata,
            "spec": dict(self.spec),
            "compatibility": self.compatibility.to_dict(),
            "provenance": [item.to_dict() for item in self.provenance],
        }


@runtime_checkable
class ResourceRegistry(Protocol):
    def list_resources(self, *, kind: str | None = None, namespace: str | None = None) -> list[ResourceDocument]:
        ...

    def get_resource(self, *, kind: str, name: str, namespace: str = "default") -> ResourceDocument | None:
        ...

    def list_capabilities(self) -> list[Capability]:
        ...

    def explain_resource(self, *, kind: str, name: str, namespace: str = "default") -> Mapping[str, Any]:
        ...
