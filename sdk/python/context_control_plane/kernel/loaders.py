from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from .resource_registry import (
    ResourceCompatibility,
    ResourceDocument,
    ResourceIdentifier,
    ResourceProvenance,
)
from .versioning import CompatibilityLevel


class ResourceLoadError(ValueError):
    """Raised when a resource document is invalid."""


def _coerce_stability(value: Any) -> CompatibilityLevel:
    raw = str(value or "").strip().lower()
    if not raw:
        return CompatibilityLevel.EXPERIMENTAL
    try:
        return CompatibilityLevel(raw)
    except ValueError as exc:
        raise ResourceLoadError(f"unsupported compatibility stability {raw!r}") from exc


def build_resource_document(
    payload: Mapping[str, Any],
    *,
    source: str,
    layer: str,
    native: bool,
) -> ResourceDocument:
    if not isinstance(payload, Mapping):
        raise ResourceLoadError("resource document must be a JSON object")

    api_version = str(payload.get("apiVersion", "") or "").strip()
    if not api_version:
        raise ResourceLoadError("resource document is missing apiVersion")

    kind = str(payload.get("kind", "") or "").strip()
    if not kind:
        raise ResourceLoadError("resource document is missing kind")

    metadata = payload.get("metadata", {})
    if not isinstance(metadata, Mapping):
        raise ResourceLoadError("resource document metadata must be a JSON object")
    name = str(metadata.get("name", "") or "").strip()
    if not name:
        raise ResourceLoadError("resource document metadata.name is required")
    namespace = str(metadata.get("namespace", "default") or "default").strip() or "default"

    spec = payload.get("spec", {})
    if not isinstance(spec, Mapping):
        raise ResourceLoadError("resource document spec must be a JSON object")

    compatibility_payload = payload.get("compatibility", {})
    if compatibility_payload is None:
        compatibility_payload = {}
    if not isinstance(compatibility_payload, Mapping):
        raise ResourceLoadError("resource document compatibility must be a JSON object when provided")

    document_metadata = dict(metadata)
    document_metadata.pop("name", None)
    document_metadata.pop("namespace", None)

    compatibility = ResourceCompatibility(
        introduced_in=str(compatibility_payload.get("introducedIn", "") or "").strip(),
        deprecated_in=str(compatibility_payload.get("deprecatedIn", "") or "").strip(),
        replaced_by=str(compatibility_payload.get("replacedBy", "") or "").strip(),
        stability=_coerce_stability(compatibility_payload.get("stability", "")),
    )

    return ResourceDocument(
        identifier=ResourceIdentifier(
            api_version=api_version,
            kind=kind,
            name=name,
            namespace=namespace,
        ),
        metadata=document_metadata,
        spec=dict(spec),
        compatibility=compatibility,
        provenance=(ResourceProvenance(source=source, layer=layer, native=native),),
    )


def load_resource_file(path: str | Path, *, layer: str, native: bool = True) -> ResourceDocument:
    file_path = Path(path)
    try:
        payload = json.loads(file_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ResourceLoadError(f"resource file does not exist: {file_path}") from exc
    except json.JSONDecodeError as exc:
        raise ResourceLoadError(f"invalid JSON in resource file {file_path}: {exc}") from exc
    return build_resource_document(payload, source=str(file_path), layer=layer, native=native)


def load_resources_from_dir(path: str | Path, *, layer: str, native: bool = True) -> list[ResourceDocument]:
    root = Path(path)
    if not root.exists():
        return []
    if not root.is_dir():
        raise ResourceLoadError(f"resource directory does not exist: {root}")
    documents: list[ResourceDocument] = []
    for file_path in sorted(root.rglob("*.json")):
        documents.append(load_resource_file(file_path, layer=layer, native=native))
    return documents
