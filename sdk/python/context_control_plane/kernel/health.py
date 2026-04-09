from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from .loaders import ResourceLoadError, load_resource_file, load_resources_from_dir
from .packs import PackManifest
from .registry import InMemoryResourceRegistry
from .resource_registry import ResourceDocument
from .upgrade import build_upgrade_plan

_VALID_ACTIVATION_STATES = {"enabled", "disabled"}


def _normalize_activation_state(raw: str) -> str:
    value = str(raw or "").strip().lower()
    if not value:
        return "disabled"
    return value


@dataclass(frozen=True)
class ValidationIssue:
    level: str
    code: str
    subject: str
    message: str
    details: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "code": self.code,
            "subject": self.subject,
            "message": self.message,
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class PackStatusRecord:
    name: str
    version: str
    pack_id: str
    effective_state: str
    default_activation: str
    enabled: bool
    manifest_source: str
    activation_source: str = ""
    activation_layer: str = ""
    activation_native: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "pack_id": self.pack_id,
            "effective_state": self.effective_state,
            "default_activation": self.default_activation,
            "enabled": self.enabled,
            "manifest_source": self.manifest_source,
            "activation_source": self.activation_source,
            "activation_layer": self.activation_layer,
            "activation_native": self.activation_native,
        }


@dataclass(frozen=True)
class ValidationReport:
    summary: Mapping[str, int]
    issues: tuple[ValidationIssue, ...]
    pack_status: tuple[PackStatusRecord, ...]
    upgrade: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": dict(self.summary),
            "issues": [item.to_dict() for item in self.issues],
            "pack_status": [item.to_dict() for item in self.pack_status],
            "upgrade": dict(self.upgrade),
        }


@dataclass(frozen=True)
class DoctorReport:
    health: str
    summary: Mapping[str, int]
    issues: tuple[ValidationIssue, ...]
    recommendations: tuple[str, ...]
    pack_status: tuple[PackStatusRecord, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "health": self.health,
            "summary": dict(self.summary),
            "issues": [item.to_dict() for item in self.issues],
            "recommendations": list(self.recommendations),
            "pack_status": [item.to_dict() for item in self.pack_status],
        }


def load_activation_documents(
    *,
    resource_paths: Iterable[str] = (),
    resource_dirs: Iterable[str] = (),
    layer: str = "local",
) -> list[ResourceDocument]:
    documents: list[ResourceDocument] = []
    for path in resource_paths:
        document = load_resource_file(path, layer=layer)
        if document.identifier.kind == "PackActivation":
            documents.append(document)
    for directory in resource_dirs:
        for document in load_resources_from_dir(directory, layer=layer):
            if document.identifier.kind == "PackActivation":
                documents.append(document)
    return documents


def _activation_target(document: ResourceDocument) -> str:
    return str(document.spec.get("pack", document.identifier.name) or document.identifier.name).strip()


def _activation_state(document: ResourceDocument, default_state: str) -> str:
    return _normalize_activation_state(document.spec.get("state", default_state))


def build_pack_status(
    *,
    pack_manifests: Iterable[PackManifest] = (),
    activation_documents: Iterable[ResourceDocument] = (),
) -> tuple[tuple[PackStatusRecord, ...], tuple[ValidationIssue, ...]]:
    manifests = sorted(pack_manifests, key=lambda item: (item.name, item.version, item.source))
    manifest_by_name = {item.name: item for item in manifests}
    activation_registry = InMemoryResourceRegistry(activation_documents)

    issues: list[ValidationIssue] = []
    seen_manifest_names: set[str] = set()
    for manifest in manifests:
        if manifest.name in seen_manifest_names:
            issues.append(
                ValidationIssue(
                    level="error",
                    code="duplicate-pack-manifest",
                    subject=manifest.pack_id,
                    message="multiple pack manifests with the same name were provided",
                    details={"source": manifest.source},
                )
            )
        seen_manifest_names.add(manifest.name)

    for activation in activation_registry.list_resources(kind="PackActivation"):
        target = _activation_target(activation)
        if not target:
            issues.append(
                ValidationIssue(
                    level="error",
                    code="invalid-pack-activation",
                    subject=activation.identifier.name,
                    message="PackActivation must target a pack by metadata.name or spec.pack",
                    details={"source": activation.provenance[0].source if activation.provenance else ""},
                )
            )
            continue
        if target != activation.identifier.name:
            issues.append(
                ValidationIssue(
                    level="warning",
                    code="pack-activation-name-mismatch",
                    subject=activation.identifier.name,
                    message="PackActivation metadata.name should match the target pack name",
                    details={"target_pack": target},
                )
            )
        if target not in manifest_by_name:
            issues.append(
                ValidationIssue(
                    level="error",
                    code="unknown-pack-activation",
                    subject=target,
                    message="PackActivation references a pack manifest that is not installed",
                    details={"activation_name": activation.identifier.name},
                )
            )

    status_records: list[PackStatusRecord] = []
    for manifest in manifests:
        activation = activation_registry.get_resource(kind="PackActivation", name=manifest.name)
        effective_state = _normalize_activation_state(manifest.default_activation)
        activation_source = ""
        activation_layer = ""
        activation_native = True
        if activation is not None:
            effective_state = _activation_state(activation, manifest.default_activation)
            activation_source = activation.provenance[0].source if activation.provenance else ""
            activation_layer = activation.provenance[0].layer if activation.provenance else ""
            activation_native = activation.provenance[0].native if activation.provenance else True
            if effective_state not in _VALID_ACTIVATION_STATES:
                issues.append(
                    ValidationIssue(
                        level="error",
                        code="invalid-pack-activation-state",
                        subject=manifest.name,
                        message="PackActivation state must be either enabled or disabled",
                        details={"state": effective_state, "source": activation_source},
                    )
                )
        status_records.append(
            PackStatusRecord(
                name=manifest.name,
                version=manifest.version,
                pack_id=manifest.pack_id,
                effective_state=effective_state,
                default_activation=_normalize_activation_state(manifest.default_activation),
                enabled=effective_state == "enabled",
                manifest_source=manifest.source,
                activation_source=activation_source,
                activation_layer=activation_layer,
                activation_native=activation_native,
            )
        )
    return tuple(status_records), tuple(issues)


def build_validation_report(
    *,
    pack_manifests: Iterable[PackManifest] = (),
    activation_documents: Iterable[ResourceDocument] = (),
) -> ValidationReport:
    pack_status, issues = build_pack_status(
        pack_manifests=pack_manifests,
        activation_documents=activation_documents,
    )
    upgrade = build_upgrade_plan(pack_manifests=pack_manifests).to_dict()
    upgrade_issues = []
    for action in upgrade["actions"]:
        if action["disposition"] == "blocked":
            upgrade_issues.append(
                ValidationIssue(
                    level="error",
                    code="pack-core-incompatible",
                    subject=action["item_id"],
                    message=action["reason"],
                    details=action["details"],
                )
            )
        elif action["disposition"] == "manual":
            upgrade_issues.append(
                ValidationIssue(
                    level="warning",
                    code="pack-migration-review",
                    subject=action["item_id"],
                    message=action["reason"],
                    details=action["details"],
                )
            )
    all_issues = (*issues, *upgrade_issues)
    summary = {
        "packs": len(pack_status),
        "enabledPacks": sum(1 for item in pack_status if item.enabled),
        "errors": sum(1 for item in all_issues if item.level == "error"),
        "warnings": sum(1 for item in all_issues if item.level == "warning"),
    }
    return ValidationReport(
        summary=summary,
        issues=tuple(all_issues),
        pack_status=pack_status,
        upgrade=upgrade,
    )


def build_doctor_report(
    *,
    pack_manifests: Iterable[PackManifest] = (),
    activation_documents: Iterable[ResourceDocument] = (),
) -> DoctorReport:
    validation = build_validation_report(
        pack_manifests=pack_manifests,
        activation_documents=activation_documents,
    )
    recommendations: list[str] = []
    issue_codes = {item.code for item in validation.issues}
    if "unknown-pack-activation" in issue_codes:
        recommendations.append("Remove or rename PackActivation resources that point at missing packs.")
    if "invalid-pack-activation-state" in issue_codes:
        recommendations.append("Use `enabled` or `disabled` for PackActivation.spec.state values.")
    if "pack-core-incompatible" in issue_codes:
        recommendations.append("Review requiresCore ranges or upgrade ccp-core before enabling the affected pack.")
    if "pack-activation-name-mismatch" in issue_codes:
        recommendations.append("Align PackActivation metadata.name with the target pack name to keep precedence simple.")
    health = "healthy" if validation.summary["errors"] == 0 and validation.summary["warnings"] == 0 else "attention_needed"
    return DoctorReport(
        health=health,
        summary=validation.summary,
        issues=validation.issues,
        recommendations=tuple(recommendations),
        pack_status=validation.pack_status,
    )
