from __future__ import annotations

from dataclasses import replace
from typing import Any, Iterable, Mapping

from .resource_registry import ResourceDocument, ResourceProvenance, ResourceRegistry
from .versioning import Capability, CompatibilityLevel

_LAYER_PRIORITY = {
    "builtin": 10,
    "common": 20,
    "pack": 30,
    "workspace": 40,
    "user": 50,
    "local": 60,
}


def _layer_priority(layer: str) -> int:
    return _LAYER_PRIORITY.get(str(layer or "").strip().lower(), 0)


def _primary_provenance(document: ResourceDocument) -> ResourceProvenance | None:
    return document.provenance[0] if document.provenance else None


def _native_score(item: object | None) -> int:
    return 1 if (getattr(item, "native", True) if item is not None else True) else 0


def _winner_sort_key(document: ResourceDocument) -> tuple[int, int, str]:
    provenance = _primary_provenance(document)
    layer = provenance.layer if provenance else ""
    source = provenance.source if provenance else ""
    return (_layer_priority(layer), _native_score(provenance), source)


def _document_key(document: ResourceDocument) -> tuple[str, str, str]:
    identifier = document.identifier
    return (identifier.kind, identifier.namespace, identifier.name)


def _resource_sort_key(document: ResourceDocument) -> tuple[str, str, str]:
    identifier = document.identifier
    return (identifier.kind, identifier.namespace, identifier.name)


def _provenance_sort_key(item: Any) -> tuple[int, int, str]:
    return (
        -_layer_priority(getattr(item, "layer", "")),
        -_native_score(item),
        str(getattr(item, "source", "")),
    )


def _deep_merge_mapping(base: Mapping[str, Any], overlay: Mapping[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = {str(key): value for key, value in base.items()}
    for key, value in overlay.items():
        existing = merged.get(str(key))
        if isinstance(existing, Mapping) and isinstance(value, Mapping):
            merged[str(key)] = _deep_merge_mapping(existing, value)
        else:
            merged[str(key)] = value
    return merged


def _merge_compatibility(documents: list[ResourceDocument]):
    compatibility = documents[0].compatibility
    for document in documents[1:]:
        candidate = document.compatibility
        compatibility = replace(
            compatibility,
            introduced_in=candidate.introduced_in or compatibility.introduced_in,
            deprecated_in=candidate.deprecated_in or compatibility.deprecated_in,
            replaced_by=candidate.replaced_by or compatibility.replaced_by,
            stability=(
                candidate.stability
                if (
                    candidate.introduced_in
                    or candidate.deprecated_in
                    or candidate.replaced_by
                    or candidate.stability != CompatibilityLevel.EXPERIMENTAL
                )
                else compatibility.stability
            ),
        )
    return compatibility


def _ordered_provenance(documents: list[ResourceDocument], winner: ResourceDocument) -> tuple[ResourceProvenance, ...]:
    flattened = [entry for document in documents for entry in document.provenance]
    if not flattened:
        return ()

    sorted_entries = sorted(flattened, key=_provenance_sort_key)
    winner_entry = _primary_provenance(winner)
    if winner_entry is None:
        return tuple(sorted_entries)

    ordered = [winner_entry]
    for entry in sorted_entries:
        if entry != winner_entry:
            ordered.append(entry)
    return tuple(ordered)


class InMemoryResourceRegistry(ResourceRegistry):
    def __init__(
        self,
        documents: Iterable[ResourceDocument] = (),
        *,
        capabilities: Iterable[Capability] = (),
    ) -> None:
        self._documents_by_key: dict[tuple[str, str, str], list[ResourceDocument]] = {}
        for document in documents:
            self._documents_by_key.setdefault(_document_key(document), []).append(document)
        self._capabilities = list(capabilities)

    def _merged_document(self, key: tuple[str, str, str]) -> ResourceDocument | None:
        variants = self._documents_by_key.get(key, [])
        if not variants:
            return None
        # Merge from lowest to highest precedence. Within the same layer,
        # file-backed resources override generated ones, then lexical source
        # order provides a deterministic final tie-break.
        ordered = sorted(variants, key=_winner_sort_key)
        winner = ordered[-1]
        merged_metadata: dict[str, Any] = {}
        merged_spec: dict[str, Any] = {}
        for document in ordered:
            merged_metadata = _deep_merge_mapping(merged_metadata, document.metadata)
            merged_spec = _deep_merge_mapping(merged_spec, document.spec)
        merged_provenance = _ordered_provenance(ordered, winner)
        return ResourceDocument(
            identifier=winner.identifier,
            metadata=merged_metadata,
            spec=merged_spec,
            compatibility=_merge_compatibility(ordered),
            provenance=merged_provenance,
        )

    def list_resources(self, *, kind: str | None = None, namespace: str | None = None) -> list[ResourceDocument]:
        documents: list[ResourceDocument] = []
        for key in sorted(self._documents_by_key):
            document = self._merged_document(key)
            if document is None:
                continue
            if kind and document.identifier.kind != kind:
                continue
            if namespace and document.identifier.namespace != namespace:
                continue
            documents.append(document)
        return sorted(documents, key=_resource_sort_key)

    def get_resource(self, *, kind: str, name: str, namespace: str = "default") -> ResourceDocument | None:
        return self._merged_document((kind, namespace, name))

    def list_capabilities(self) -> list[Capability]:
        capabilities = [
            Capability(
                name="resource-registry",
                version="v1beta1",
                stability=CompatibilityLevel.BETA,
                description="Lists, resolves, and explains effective resources with provenance.",
            ),
            Capability(
                name="resource-provenance",
                version="v1beta1",
                stability=CompatibilityLevel.BETA,
                description="Reports resource source and layer provenance for effective configuration.",
            ),
        ]
        capabilities.extend(self._capabilities)
        deduped: dict[str, Capability] = {}
        for capability in capabilities:
            deduped[capability.capability_id] = capability
        return [deduped[key] for key in sorted(deduped)]

    def explain_resource(self, *, kind: str, name: str, namespace: str = "default") -> dict[str, Any]:
        document = self.get_resource(kind=kind, name=name, namespace=namespace)
        if document is None:
            return {
                "found": False,
                "kind": kind,
                "name": name,
                "namespace": namespace,
            }
        return {
            "found": True,
            "resource": document.to_dict(),
            "effective_layer": document.provenance[0].layer if document.provenance else "",
            "effective_source": document.provenance[0].source if document.provenance else "",
            "native": document.provenance[0].native if document.provenance else True,
            "provenance": [item.to_dict() for item in document.provenance],
        }
