from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

from .loaders import ResourceLoadError
from .versioning import CompatibilityLevel

PACK_API_VERSION = "ccp.io/pack/v1beta1"
PACK_KIND = "Pack"


class PackLoadError(ResourceLoadError):
    """Raised when a pack manifest is invalid."""


def _coerce_string_list(value: Any, *, field_name: str) -> tuple[str, ...]:
    if value in (None, ""):
        return ()
    if not isinstance(value, list):
        raise PackLoadError(f"pack manifest field {field_name!r} must be an array")
    return tuple(str(item).strip() for item in value if str(item).strip())


def _coerce_stability(value: Any) -> CompatibilityLevel:
    raw = str(value or "beta").strip().lower()
    try:
        return CompatibilityLevel(raw)
    except ValueError as exc:
        raise PackLoadError(f"unsupported pack stability {raw!r}") from exc


@dataclass(frozen=True)
class PackManifest:
    name: str
    version: str
    display_name: str = ""
    description: str = ""
    requires_core: str = ""
    requires_capabilities: tuple[str, ...] = field(default_factory=tuple)
    depends_on: tuple[str, ...] = field(default_factory=tuple)
    installs_resources: tuple[str, ...] = field(default_factory=tuple)
    optional_resources: tuple[str, ...] = field(default_factory=tuple)
    migrations: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)
    default_activation: str = "disabled"
    stability: CompatibilityLevel = CompatibilityLevel.BETA
    source: str = ""

    @property
    def pack_id(self) -> str:
        return f"{self.name}@{self.version}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "apiVersion": PACK_API_VERSION,
            "kind": PACK_KIND,
            "metadata": {
                "name": self.name,
                "version": self.version,
            },
            "spec": {
                "displayName": self.display_name,
                "description": self.description,
                "requiresCore": self.requires_core,
                "requiresCapabilities": list(self.requires_capabilities),
                "dependsOn": list(self.depends_on),
                "installsResources": list(self.installs_resources),
                "optionalResources": list(self.optional_resources),
                "migrations": [dict(item) for item in self.migrations],
                "defaultActivation": self.default_activation,
                "stability": self.stability.value,
            },
            "source": self.source,
            "pack_id": self.pack_id,
        }


def build_pack_manifest(payload: Mapping[str, Any], *, source: str) -> PackManifest:
    if not isinstance(payload, Mapping):
        raise PackLoadError("pack manifest must be a JSON object")

    api_version = str(payload.get("apiVersion", "") or "").strip()
    if api_version != PACK_API_VERSION:
        raise PackLoadError(f"pack manifest must declare apiVersion {PACK_API_VERSION!r}")

    kind = str(payload.get("kind", "") or "").strip()
    if kind != PACK_KIND:
        raise PackLoadError(f"pack manifest must declare kind {PACK_KIND!r}")

    metadata = payload.get("metadata", {})
    if not isinstance(metadata, Mapping):
        raise PackLoadError("pack manifest metadata must be a JSON object")
    name = str(metadata.get("name", "") or "").strip()
    version = str(metadata.get("version", "") or "").strip()
    if not name:
        raise PackLoadError("pack manifest metadata.name is required")
    if not version:
        raise PackLoadError("pack manifest metadata.version is required")

    spec = payload.get("spec", {})
    if not isinstance(spec, Mapping):
        raise PackLoadError("pack manifest spec must be a JSON object")

    migrations_raw = spec.get("migrations", [])
    if migrations_raw in (None, ""):
        migrations_raw = []
    if not isinstance(migrations_raw, list):
        raise PackLoadError("pack manifest field 'migrations' must be an array")
    migrations: list[Mapping[str, Any]] = []
    for item in migrations_raw:
        if not isinstance(item, Mapping):
            raise PackLoadError("pack manifest migrations entries must be objects")
        migrations.append(dict(item))

    return PackManifest(
        name=name,
        version=version,
        display_name=str(spec.get("displayName", "") or "").strip(),
        description=str(spec.get("description", "") or "").strip(),
        requires_core=str(spec.get("requiresCore", "") or "").strip(),
        requires_capabilities=_coerce_string_list(spec.get("requiresCapabilities", []), field_name="requiresCapabilities"),
        depends_on=_coerce_string_list(spec.get("dependsOn", []), field_name="dependsOn"),
        installs_resources=_coerce_string_list(spec.get("installsResources", []), field_name="installsResources"),
        optional_resources=_coerce_string_list(spec.get("optionalResources", []), field_name="optionalResources"),
        migrations=tuple(migrations),
        default_activation=str(spec.get("defaultActivation", "disabled") or "disabled").strip() or "disabled",
        stability=_coerce_stability(spec.get("stability", "beta")),
        source=source,
    )


def load_pack_manifest_file(path: str | Path) -> PackManifest:
    file_path = Path(path)
    try:
        payload = json.loads(file_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PackLoadError(f"pack manifest file does not exist: {file_path}") from exc
    except json.JSONDecodeError as exc:
        raise PackLoadError(f"invalid JSON in pack manifest {file_path}: {exc}") from exc
    return build_pack_manifest(payload, source=str(file_path))


def load_pack_manifests_from_dir(path: str | Path) -> list[PackManifest]:
    root = Path(path)
    if not root.exists():
        return []
    if not root.is_dir():
        raise PackLoadError(f"pack manifest directory does not exist: {root}")
    manifests: list[PackManifest] = []
    for manifest_path in sorted(root.rglob("pack.json")):
        manifests.append(load_pack_manifest_file(manifest_path))
    return manifests
