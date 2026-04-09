from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from .discovery import list_core_capabilities, list_resource_kind_schemas, resolve_package_version
from .packs import PACK_API_VERSION, PACK_KIND, PackManifest
from .registry import InMemoryResourceRegistry


def _version_tuple(raw: str) -> tuple[int, ...]:
    parts = [part for part in str(raw or "").strip().split(".") if part != ""]
    if not parts:
        return (0,)
    return tuple(int(part) for part in parts)


def _compare_versions(left: str, right: str) -> int:
    left_tuple = _version_tuple(left)
    right_tuple = _version_tuple(right)
    size = max(len(left_tuple), len(right_tuple))
    padded_left = left_tuple + (0,) * (size - len(left_tuple))
    padded_right = right_tuple + (0,) * (size - len(right_tuple))
    if padded_left < padded_right:
        return -1
    if padded_left > padded_right:
        return 1
    return 0


def _satisfies_range(version: str, requirement: str) -> bool:
    requirement_text = str(requirement or "").strip()
    if not requirement_text:
        return True
    for token in requirement_text.split():
        if token.startswith(">="):
            if _compare_versions(version, token[2:]) < 0:
                return False
        elif token.startswith("<="):
            if _compare_versions(version, token[2:]) > 0:
                return False
        elif token.startswith(">"):
            if _compare_versions(version, token[1:]) <= 0:
                return False
        elif token.startswith("<"):
            if _compare_versions(version, token[1:]) >= 0:
                return False
        elif token.startswith("=="):
            if _compare_versions(version, token[2:]) != 0:
                return False
        else:
            return False
    return True


@dataclass(frozen=True)
class UpgradePlanItem:
    category: str
    item_id: str
    disposition: str
    reason: str
    details: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "item_id": self.item_id,
            "disposition": self.disposition,
            "reason": self.reason,
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class UpgradePlan:
    current_core_version: str
    target_core_version: str
    summary: Mapping[str, int]
    packs: tuple[Mapping[str, Any], ...]
    resources: tuple[Mapping[str, Any], ...]
    actions: tuple[UpgradePlanItem, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "currentCoreVersion": self.current_core_version,
            "targetCoreVersion": self.target_core_version,
            "summary": dict(self.summary),
            "packs": [dict(item) for item in self.packs],
            "resources": [dict(item) for item in self.resources],
            "actions": [item.to_dict() for item in self.actions],
        }


def build_upgrade_plan(
    *,
    target_version: str | None = None,
    pack_manifests: Iterable[PackManifest] = (),
) -> UpgradePlan:
    current_version = resolve_package_version()
    effective_target = str(target_version or current_version).strip() or current_version
    capability_ids = {
        cap.capability_id
        for cap in [*list_core_capabilities(), *InMemoryResourceRegistry().list_capabilities()]
    }
    resource_kinds = [schema.kind for schema in list_resource_kind_schemas()]

    pack_entries: list[Mapping[str, Any]] = []
    actions: list[UpgradePlanItem] = []
    for pack in pack_manifests:
        missing_capabilities = sorted(cap for cap in pack.requires_capabilities if cap not in capability_ids)
        core_compatible = _satisfies_range(effective_target, pack.requires_core)
        if missing_capabilities:
            disposition = "blocked"
            reason = "pack requires capabilities that are not exposed by this core"
        elif not core_compatible:
            disposition = "blocked"
            reason = "pack core version requirement does not match the target core version"
        elif effective_target != current_version and pack.migrations:
            disposition = "manual"
            reason = "pack declares migrations that should be reviewed before upgrade"
        else:
            disposition = "auto"
            reason = "pack is compatible with the target core version"
        details = {
            "requiresCore": pack.requires_core,
            "requiresCapabilities": list(pack.requires_capabilities),
            "missingCapabilities": missing_capabilities,
            "source": pack.source,
        }
        actions.append(
            UpgradePlanItem(
                category="pack",
                item_id=pack.pack_id,
                disposition=disposition,
                reason=reason,
                details=details,
            )
        )
        pack_entries.append(
            {
                "name": pack.name,
                "version": pack.version,
                "pack_id": pack.pack_id,
                "requiresCore": pack.requires_core,
                "requiresCapabilities": list(pack.requires_capabilities),
                "defaultActivation": pack.default_activation,
                "stability": pack.stability.value,
                "source": pack.source,
            }
        )

    resource_entries = [
        {
            "kind": kind,
            "apiVersion": "ccp.io/v1beta1",
            "status": "supported",
        }
        for kind in resource_kinds
    ]

    summary = {
        "autoMigrations": sum(1 for item in actions if item.disposition == "auto"),
        "manualActions": sum(1 for item in actions if item.disposition == "manual"),
        "blockedItems": sum(1 for item in actions if item.disposition == "blocked"),
    }

    return UpgradePlan(
        current_core_version=current_version,
        target_core_version=effective_target,
        summary=summary,
        packs=tuple(pack_entries),
        resources=tuple(resource_entries),
        actions=tuple(actions),
    )
