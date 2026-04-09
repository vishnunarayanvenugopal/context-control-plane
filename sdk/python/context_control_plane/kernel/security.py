from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Mapping

from .gateway import GatewayConfigurationError, GatewayPolicyProfile, evaluate_gateway_policy
from .resource_registry import ResourceDocument
from .secrets import (
    ConnectionSecretControls,
    ResponseAllowlistPolicy,
    SecretBackendProfile,
    SecretConfigurationError,
    resolve_connection_secret_controls,
)


class DataClassification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class ConnectionMode(str, Enum):
    CONNECT = "connect"
    MATERIALIZE = "materialize"
    REVEAL = "reveal"


class AccessLevel(str, Enum):
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"


def _normalize_string_set(value: Any, *, default: tuple[str, ...]) -> tuple[str, ...]:
    if value in (None, ""):
        return default
    if isinstance(value, str):
        values = (value,)
    elif isinstance(value, (list, tuple, set)):
        values = tuple(str(item or "").strip().lower() for item in value)
    else:
        raise ValueError("expected a string or array of strings")
    cleaned = tuple(item for item in values if item)
    return cleaned or default


def _parse_classification(raw: Any) -> DataClassification:
    value = str(raw or DataClassification.INTERNAL.value).strip().lower() or DataClassification.INTERNAL.value
    try:
        return DataClassification(value)
    except ValueError as exc:
        raise ValueError(f"unsupported connection classification {value!r}") from exc


def _parse_mode(raw: Any, *, default: ConnectionMode | None = None) -> ConnectionMode:
    value = str(raw or (default.value if default is not None else "")).strip().lower()
    if not value and default is not None:
        return default
    try:
        return ConnectionMode(value)
    except ValueError as exc:
        raise ValueError(f"unsupported connection mode {value!r}") from exc


def _parse_access(raw: Any) -> AccessLevel:
    value = str(raw or AccessLevel.READ.value).strip().lower() or AccessLevel.READ.value
    try:
        return AccessLevel(value)
    except ValueError as exc:
        raise ValueError(f"unsupported connection access {value!r}") from exc


@dataclass(frozen=True)
class SecretHandlingPolicy:
    brokered: bool = True
    sanitize_input: bool = True
    sanitize_output: bool = True
    allow_raw_secret_reveal: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "brokered": self.brokered,
            "sanitizeInput": self.sanitize_input,
            "sanitizeOutput": self.sanitize_output,
            "allowRawSecretReveal": self.allow_raw_secret_reveal,
        }


@dataclass(frozen=True)
class ApprovalPolicy:
    required_for_access: tuple[str, ...] = field(default_factory=tuple)
    required_for_modes: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "requiredForAccess": list(self.required_for_access),
            "requiredForModes": list(self.required_for_modes),
        }


@dataclass(frozen=True)
class ConnectionSafetyDecision:
    connection_name: str
    namespace: str
    adapter: str
    endpoint: str
    classification: DataClassification
    requested_access: AccessLevel
    requested_mode: ConnectionMode
    effective_mode: ConnectionMode
    allowed_access: tuple[str, ...]
    allowed_modes: tuple[str, ...]
    secret_handling: SecretHandlingPolicy
    secret_controls: ConnectionSecretControls
    approval_policy: ApprovalPolicy
    approval_required: bool
    allowed: bool
    reason: str
    gateway_policy_name: str = ""
    gateway_decision: str = ""
    gateway_reason: str = ""
    warnings: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "connection": {
                "name": self.connection_name,
                "namespace": self.namespace,
                "adapter": self.adapter,
                "endpoint": self.endpoint,
            },
            "classification": self.classification.value,
            "requestedAccess": self.requested_access.value,
            "requestedMode": self.requested_mode.value,
            "effectiveMode": self.effective_mode.value,
            "allowedAccess": list(self.allowed_access),
            "allowedModes": list(self.allowed_modes),
            "secretHandling": self.secret_handling.to_dict(),
            "secretControls": self.secret_controls.to_dict(),
            "approval": {
                "required": self.approval_required,
                "policy": self.approval_policy.to_dict(),
            },
            "gateway": {
                "policyName": self.gateway_policy_name,
                "decision": self.gateway_decision,
                "reason": self.gateway_reason,
            },
            "allowed": self.allowed,
            "reason": self.reason,
            "warnings": list(self.warnings),
        }


def _parse_secret_handling(spec: Mapping[str, Any]) -> SecretHandlingPolicy:
    handling_raw = spec.get("secretHandling", {})
    if handling_raw in (None, ""):
        handling_raw = {}
    if not isinstance(handling_raw, Mapping):
        raise ValueError("ConnectionProfile spec.secretHandling must be an object when provided")
    return SecretHandlingPolicy(
        brokered=bool(handling_raw.get("brokered", True)),
        sanitize_input=bool(handling_raw.get("sanitizeInput", True)),
        sanitize_output=bool(handling_raw.get("sanitizeOutput", True)),
        allow_raw_secret_reveal=bool(handling_raw.get("allowRawSecretReveal", False)),
    )


def _parse_approval_policy(spec: Mapping[str, Any]) -> ApprovalPolicy:
    approval_raw = spec.get("approval", {})
    if approval_raw in (None, ""):
        approval_raw = {}
    if not isinstance(approval_raw, Mapping):
        raise ValueError("ConnectionProfile spec.approval must be an object when provided")
    return ApprovalPolicy(
        required_for_access=_normalize_string_set(approval_raw.get("requiredForAccess", ()), default=()),
        required_for_modes=_normalize_string_set(approval_raw.get("requiredForModes", ()), default=()),
    )


def _resolve_gateway_policy(
    document: ResourceDocument,
    registry,
) -> GatewayPolicyProfile | None:
    if registry is None:
        return None

    ref_raw = document.spec.get("gatewayPolicyRef")
    if ref_raw in (None, ""):
        candidates = registry.list_resources(kind="GatewayPolicy", namespace=document.identifier.namespace)
        if not candidates:
            return None
        if len(candidates) > 1:
            raise ValueError(
                "multiple GatewayPolicy resources are available; set spec.gatewayPolicyRef on the ConnectionProfile"
            )
        return GatewayPolicyProfile.from_document(candidates[0])

    if isinstance(ref_raw, str):
        ref_name = ref_raw.strip()
        ref_namespace = document.identifier.namespace
    else:
        if not isinstance(ref_raw, Mapping):
            raise ValueError("ConnectionProfile spec.gatewayPolicyRef must be a string or object when provided")
        ref_name = str(ref_raw.get("name", "") or "").strip()
        ref_namespace = str(ref_raw.get("namespace", document.identifier.namespace) or document.identifier.namespace).strip()
    if not ref_name:
        raise ValueError("ConnectionProfile spec.gatewayPolicyRef requires a policy name")

    gateway_document = registry.get_resource(kind="GatewayPolicy", name=ref_name, namespace=ref_namespace)
    if gateway_document is None:
        raise ValueError(f"GatewayPolicy {ref_name!r} was not found in namespace {ref_namespace!r}")
    return GatewayPolicyProfile.from_document(gateway_document)


def evaluate_connection_profile(
    document: ResourceDocument,
    *,
    requested_access: str = AccessLevel.READ.value,
    requested_mode: str = "",
    requested_operation: str = "",
    registry=None,
) -> ConnectionSafetyDecision:
    if document.identifier.kind != "ConnectionProfile":
        raise ValueError(f"resource {document.identifier.name!r} is not a ConnectionProfile")

    spec = document.spec
    classification = _parse_classification(spec.get("classification", DataClassification.INTERNAL.value))
    allowed_access = _normalize_string_set(spec.get("allowedAccess", (AccessLevel.READ.value,)), default=(AccessLevel.READ.value,))
    allowed_modes = _normalize_string_set(spec.get("allowedModes", (ConnectionMode.CONNECT.value,)), default=(ConnectionMode.CONNECT.value,))
    default_mode = _parse_mode(spec.get("defaultMode", allowed_modes[0]), default=ConnectionMode.CONNECT)
    mode = _parse_mode(requested_mode, default=default_mode)
    access = _parse_access(requested_access)
    secret_handling = _parse_secret_handling(spec)
    approval_policy = _parse_approval_policy(spec)
    try:
        secret_controls = resolve_connection_secret_controls(document, registry=registry)
    except SecretConfigurationError as exc:
        raise ValueError(str(exc)) from exc

    adapter = str(spec.get("adapter", "") or "").strip()
    endpoint = str(spec.get("endpoint", "") or "").strip()
    warnings: list[str] = []

    if access.value not in allowed_access:
        return ConnectionSafetyDecision(
            connection_name=document.identifier.name,
            namespace=document.identifier.namespace,
            adapter=adapter,
            endpoint=endpoint,
            classification=classification,
            requested_access=access,
            requested_mode=mode,
            effective_mode=default_mode,
            allowed_access=allowed_access,
            allowed_modes=allowed_modes,
            secret_handling=secret_handling,
            secret_controls=secret_controls,
            approval_policy=approval_policy,
            approval_required=False,
            allowed=False,
            reason=f"access level {access.value!r} is not permitted by this connection profile",
        )

    if mode.value not in allowed_modes:
        return ConnectionSafetyDecision(
            connection_name=document.identifier.name,
            namespace=document.identifier.namespace,
            adapter=adapter,
            endpoint=endpoint,
            classification=classification,
            requested_access=access,
            requested_mode=mode,
            effective_mode=default_mode,
            allowed_access=allowed_access,
            allowed_modes=allowed_modes,
            secret_handling=secret_handling,
            secret_controls=secret_controls,
            approval_policy=approval_policy,
            approval_required=False,
            allowed=False,
            reason=f"connection mode {mode.value!r} is not enabled for this profile",
        )

    if mode is ConnectionMode.REVEAL and not secret_handling.allow_raw_secret_reveal:
        return ConnectionSafetyDecision(
            connection_name=document.identifier.name,
            namespace=document.identifier.namespace,
            adapter=adapter,
            endpoint=endpoint,
            classification=classification,
            requested_access=access,
            requested_mode=mode,
            effective_mode=default_mode,
            allowed_access=allowed_access,
            allowed_modes=allowed_modes,
            secret_handling=secret_handling,
            secret_controls=secret_controls,
            approval_policy=approval_policy,
            approval_required=False,
            allowed=False,
            reason="raw secret reveal is disabled for this connection profile",
        )

    approval_required = False
    if access.value in approval_policy.required_for_access:
        approval_required = True
    if mode.value in approval_policy.required_for_modes:
        approval_required = True
    if mode is ConnectionMode.MATERIALIZE and classification in {DataClassification.CONFIDENTIAL, DataClassification.RESTRICTED}:
        approval_required = True
    if mode is ConnectionMode.REVEAL:
        approval_required = True
        warnings.append("raw secret reveal should stay exceptional and short-lived")
    if access in {AccessLevel.WRITE, AccessLevel.ADMIN} and classification in {
        DataClassification.INTERNAL,
        DataClassification.CONFIDENTIAL,
        DataClassification.RESTRICTED,
    }:
        approval_required = True
    if not secret_handling.brokered:
        warnings.append("connection is not brokered; review downstream secret handling carefully")
    if secret_controls.backend.durability.value == "ephemeral":
        warnings.append("secret backend is ephemeral; credentials may disappear when the backing service stops")
    if (
        requested_mode == ConnectionMode.MATERIALIZE.value
        and secret_controls.materialization.ttl_seconds > 900
    ):
        warnings.append("materialization TTL is long; keep short-lived delivery where possible")

    reason = "connection request is allowed"
    if approval_required:
        reason = "requested connection usage requires one explicit approval receipt"
    decision = ConnectionSafetyDecision(
        connection_name=document.identifier.name,
        namespace=document.identifier.namespace,
        adapter=adapter,
        endpoint=endpoint,
        classification=classification,
        requested_access=access,
        requested_mode=mode,
        effective_mode=mode,
        allowed_access=allowed_access,
        allowed_modes=allowed_modes,
        secret_handling=secret_handling,
        secret_controls=secret_controls,
        approval_policy=approval_policy,
        approval_required=approval_required,
        allowed=True,
        reason=reason,
        warnings=tuple(warnings),
    )
    try:
        gateway_profile = _resolve_gateway_policy(document, registry)
    except (GatewayConfigurationError, ValueError) as exc:
        raise ValueError(str(exc)) from exc
    if gateway_profile is None:
        return decision

    gateway_decision = evaluate_gateway_policy(
        gateway_profile,
        access=access.value,
        classification=classification.value,
        mode=mode.value,
        operation=requested_operation,
    )
    combined_warnings = tuple([*decision.warnings, *gateway_decision.warnings])
    if gateway_decision.decision == "deny":
        return replace(
            decision,
            approval_required=False,
            allowed=False,
            reason=gateway_decision.reason,
            gateway_policy_name=gateway_profile.name,
            gateway_decision=gateway_decision.decision,
            gateway_reason=gateway_decision.reason,
            warnings=combined_warnings,
        )
    if gateway_decision.decision == "approval_required":
        return replace(
            decision,
            approval_required=True,
            reason=gateway_decision.reason or decision.reason,
            gateway_policy_name=gateway_profile.name,
            gateway_decision=gateway_decision.decision,
            gateway_reason=gateway_decision.reason,
            warnings=combined_warnings,
        )
    return replace(
        decision,
        gateway_policy_name=gateway_profile.name,
        gateway_decision=gateway_decision.decision,
        gateway_reason=gateway_decision.reason,
        warnings=combined_warnings,
    )
