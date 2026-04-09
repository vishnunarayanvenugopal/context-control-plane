from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Mapping
from uuid import uuid4

from .resource_registry import ResourceDocument, ResourceRegistry

_SENSITIVE_KEY_PARTS = (
    "token",
    "secret",
    "password",
    "passphrase",
    "cookie",
    "authorization",
    "api_key",
    "apikey",
    "access_key",
    "encryption_key",
    "session",
    "private_key",
    "client_secret",
)

_SECRET_VALUE_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|github_pat)_[A-Za-z0-9_]{10,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{12,}\b", re.IGNORECASE),
    re.compile(r"\beyJ[A-Za-z0-9_\-]+?\.[A-Za-z0-9._\-]+?\.[A-Za-z0-9._\-]+\b"),
)
_SECRET_REF_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

_SAFE_SECRET_METADATA_KEYS = frozenset({"secretrefcount", "secretrefnames", "secretrefs"})


class SecretConfigurationError(ValueError):
    """Raised when secret backend or redaction configuration is malformed."""


class SecretBackendType(str, Enum):
    OS_KEYCHAIN = "os-keychain"
    VAULT = "vault"
    ENCRYPTED_FILE = "encrypted-file"
    MEMORY = "memory"
    CUSTOM = "custom"


class SecretDurability(str, Enum):
    EPHEMERAL = "ephemeral"
    LOCAL_PERSISTENT = "local-persistent"
    SERVICE_PERSISTENT = "service-persistent"


class MaterializationDelivery(str, Enum):
    EPHEMERAL_HANDLE = "ephemeral-handle"
    TEMP_FILE = "temp-file"


def _string_list(value: Any) -> tuple[str, ...]:
    if value in (None, ""):
        return ()
    if isinstance(value, str):
        values = (value,)
    elif isinstance(value, (list, tuple, set)):
        values = tuple(str(item or "").strip() for item in value)
    else:
        raise SecretConfigurationError("expected a string or array of strings")
    return tuple(item for item in values if item)


def normalize_secret_ref(value: Any, *, field_name: str = "secretRef") -> str:
    ref = str(value or "").strip()
    if not ref:
        raise SecretConfigurationError(f"{field_name} requires a non-empty string")
    if not _SECRET_REF_PATTERN.fullmatch(ref):
        raise SecretConfigurationError(
            f"{field_name} {ref!r} is invalid; use only letters, numbers, dot, underscore, or dash"
        )
    return ref


def _mapping(value: Any, *, field_name: str) -> Mapping[str, Any]:
    if value in (None, ""):
        return {}
    if not isinstance(value, Mapping):
        raise SecretConfigurationError(f"{field_name} must be a JSON object when provided")
    return value


def _parse_backend_type(raw: Any) -> SecretBackendType:
    value = str(raw or SecretBackendType.OS_KEYCHAIN.value).strip().lower() or SecretBackendType.OS_KEYCHAIN.value
    try:
        return SecretBackendType(value)
    except ValueError:
        if value:
            return SecretBackendType.CUSTOM
        raise


def _parse_durability(raw: Any) -> SecretDurability:
    value = str(raw or SecretDurability.LOCAL_PERSISTENT.value).strip().lower() or SecretDurability.LOCAL_PERSISTENT.value
    try:
        return SecretDurability(value)
    except ValueError as exc:
        raise SecretConfigurationError(f"unsupported secret backend durability {value!r}") from exc


def _parse_delivery(raw: Any) -> MaterializationDelivery:
    value = (
        str(raw or MaterializationDelivery.EPHEMERAL_HANDLE.value).strip().lower()
        or MaterializationDelivery.EPHEMERAL_HANDLE.value
    )
    try:
        return MaterializationDelivery(value)
    except ValueError as exc:
        raise SecretConfigurationError(f"unsupported materialization delivery {value!r}") from exc


def _utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _utc_now_text() -> str:
    return _utc_now().isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class SecretBackendProfile:
    name: str
    namespace: str
    backend_type: str
    durability: SecretDurability
    provider: str = ""
    managed: bool = False
    config: Mapping[str, Any] = field(default_factory=dict)
    source: str = ""

    @classmethod
    def from_document(cls, document: ResourceDocument) -> "SecretBackendProfile":
        if document.identifier.kind != "SecretBackend":
            raise SecretConfigurationError("expected a SecretBackend resource")
        spec = document.spec
        return cls(
            name=document.identifier.name,
            namespace=document.identifier.namespace,
            backend_type=_parse_backend_type(spec.get("type")).value,
            durability=_parse_durability(spec.get("durability")),
            provider=str(spec.get("provider", "") or "").strip(),
            managed=bool(spec.get("managed", False)),
            config=dict(_mapping(spec.get("config"), field_name="config")),
            source=document.provenance[0].source if document.provenance else "",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "namespace": self.namespace,
            "type": self.backend_type,
            "durability": self.durability.value,
            "provider": self.provider,
            "managed": self.managed,
            "config": sanitize_secret_value(dict(self.config)),
            "source": self.source,
        }


@dataclass(frozen=True)
class ResponseAllowlistPolicy:
    allow_fields: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {"allowFields": list(self.allow_fields)}


@dataclass(frozen=True)
class MaterializationPolicy:
    delivery: MaterializationDelivery = MaterializationDelivery.EPHEMERAL_HANDLE
    ttl_seconds: int = 300
    cleanup_on_exit: bool = True
    cleanup_on_read: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "delivery": self.delivery.value,
            "ttlSeconds": self.ttl_seconds,
            "cleanupOnExit": self.cleanup_on_exit,
            "cleanupOnRead": self.cleanup_on_read,
        }


@dataclass(frozen=True)
class MaterializationLease:
    lease_id: str
    issued_at: str
    expires_at: str
    delivery: str
    backend_name: str
    backend_namespace: str
    cleanup_on_exit: bool
    cleanup_on_read: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "leaseId": self.lease_id,
            "issuedAt": self.issued_at,
            "expiresAt": self.expires_at,
            "delivery": self.delivery,
            "backend": {
                "name": self.backend_name,
                "namespace": self.backend_namespace,
            },
            "cleanupOnExit": self.cleanup_on_exit,
            "cleanupOnRead": self.cleanup_on_read,
        }


@dataclass(frozen=True)
class ConnectionSecretControls:
    backend: SecretBackendProfile
    response_allowlist: ResponseAllowlistPolicy
    materialization: MaterializationPolicy
    secret_refs: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend.to_dict(),
            "responseAllowlist": self.response_allowlist.to_dict(),
            "materialization": self.materialization.to_dict(),
            "secretRefs": list(self.secret_refs),
        }


def _default_backend(namespace: str) -> SecretBackendProfile:
    return SecretBackendProfile(
        name="local-secure-store",
        namespace=namespace,
        backend_type=SecretBackendType.OS_KEYCHAIN.value,
        durability=SecretDurability.LOCAL_PERSISTENT,
        provider="platform-default",
        managed=False,
        source="implicit-default",
    )


def _resolve_backend_ref(
    document: ResourceDocument,
    registry: ResourceRegistry | None,
) -> SecretBackendProfile:
    ref_raw = document.spec.get("secretBackendRef")
    if ref_raw in (None, ""):
        inline = _mapping(document.spec.get("secretBackend"), field_name="secretBackend")
        if not inline:
            return _default_backend(document.identifier.namespace)
        return SecretBackendProfile(
            name=str(inline.get("name", "inline-backend") or "inline-backend").strip(),
            namespace=str(inline.get("namespace", document.identifier.namespace) or document.identifier.namespace).strip()
            or document.identifier.namespace,
            backend_type=_parse_backend_type(inline.get("type")).value,
            durability=_parse_durability(inline.get("durability")),
            provider=str(inline.get("provider", "") or "").strip(),
            managed=bool(inline.get("managed", False)),
            config=dict(_mapping(inline.get("config"), field_name="secretBackend.config")),
            source=document.provenance[0].source if document.provenance else "",
        )

    if registry is None:
        raise SecretConfigurationError("secretBackendRef requires a registry with SecretBackend resources")
    if isinstance(ref_raw, str):
        name = ref_raw.strip()
        namespace = document.identifier.namespace
    else:
        ref = _mapping(ref_raw, field_name="secretBackendRef")
        name = str(ref.get("name", "") or "").strip()
        namespace = str(ref.get("namespace", document.identifier.namespace) or document.identifier.namespace).strip()
    if not name:
        raise SecretConfigurationError("secretBackendRef requires a backend name")
    backend_document = registry.get_resource(kind="SecretBackend", name=name, namespace=namespace)
    if backend_document is None:
        raise SecretConfigurationError(f"SecretBackend {name!r} was not found in namespace {namespace!r}")
    return SecretBackendProfile.from_document(backend_document)


def _resolve_response_allowlist(document: ResourceDocument) -> ResponseAllowlistPolicy:
    for field_name in ("outputPolicy", "responsePolicy", "responseAllowlist"):
        raw = document.spec.get(field_name)
        if raw not in (None, ""):
            value = _mapping(raw, field_name=field_name)
            return ResponseAllowlistPolicy(allow_fields=_string_list(value.get("allowFields")))
    return ResponseAllowlistPolicy()


def _resolve_materialization_policy(document: ResourceDocument) -> MaterializationPolicy:
    raw = _mapping(document.spec.get("materialization"), field_name="materialization")
    if not raw:
        return MaterializationPolicy()
    ttl_seconds = int(raw.get("ttlSeconds", 300) or 300)
    if ttl_seconds <= 0:
        raise SecretConfigurationError("materialization ttlSeconds must be positive")
    return MaterializationPolicy(
        delivery=_parse_delivery(raw.get("delivery")),
        ttl_seconds=ttl_seconds,
        cleanup_on_exit=bool(raw.get("cleanupOnExit", True)),
        cleanup_on_read=bool(raw.get("cleanupOnRead", False)),
    )


def resolve_connection_secret_controls(
    document: ResourceDocument,
    *,
    registry: ResourceRegistry | None = None,
) -> ConnectionSecretControls:
    if document.identifier.kind != "ConnectionProfile":
        raise SecretConfigurationError(f"resource {document.identifier.name!r} is not a ConnectionProfile")
    secret_refs: list[str] = []
    for index, secret_ref in enumerate(_string_list(document.spec.get("secret_refs") or document.spec.get("secretRefs"))):
        secret_refs.append(normalize_secret_ref(secret_ref, field_name=f"secretRefs[{index}]"))
    return ConnectionSecretControls(
        backend=_resolve_backend_ref(document, registry),
        response_allowlist=_resolve_response_allowlist(document),
        materialization=_resolve_materialization_policy(document),
        secret_refs=tuple(secret_refs),
    )


def issue_materialization_lease(
    *,
    backend: SecretBackendProfile,
    policy: MaterializationPolicy,
) -> MaterializationLease:
    issued_at = _utc_now()
    expires_at = issued_at + timedelta(seconds=policy.ttl_seconds)
    return MaterializationLease(
        lease_id=f"mtl_{uuid4().hex[:12]}",
        issued_at=issued_at.isoformat().replace("+00:00", "Z"),
        expires_at=expires_at.isoformat().replace("+00:00", "Z"),
        delivery=policy.delivery.value,
        backend_name=backend.name,
        backend_namespace=backend.namespace,
        cleanup_on_exit=policy.cleanup_on_exit,
        cleanup_on_read=policy.cleanup_on_read,
    )


def is_sensitive_key(key: str) -> bool:
    lowered = str(key or "").strip().lower()
    if lowered in _SAFE_SECRET_METADATA_KEYS:
        return False
    return any(part in lowered for part in _SENSITIVE_KEY_PARTS)


def looks_like_secret_value(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    text = value.strip()
    if len(text) < 12:
        return False
    return any(pattern.search(text) for pattern in _SECRET_VALUE_PATTERNS)


def apply_response_allowlist(
    payload: Mapping[str, Any],
    *,
    allow_fields: tuple[str, ...] = (),
) -> dict[str, Any]:
    if not allow_fields:
        return {str(key): payload[key] for key in payload}
    allowed = {field for field in allow_fields if field}
    return {str(key): payload[key] for key in payload if str(key) in allowed}


def sanitize_secret_value(value: Any, *, field_name: str = "") -> Any:
    if field_name and is_sensitive_key(field_name):
        return "[redacted]"
    if isinstance(value, Mapping):
        return {str(key): sanitize_secret_value(item, field_name=str(key)) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize_secret_value(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_secret_value(item) for item in value]
    if looks_like_secret_value(value):
        return "[redacted]"
    return value


def sanitize_adapter_payload(
    payload: Mapping[str, Any],
    *,
    allow_fields: tuple[str, ...] = (),
) -> dict[str, Any]:
    filtered = apply_response_allowlist(payload, allow_fields=allow_fields)
    return {str(key): sanitize_secret_value(value, field_name=str(key)) for key, value in filtered.items()}
