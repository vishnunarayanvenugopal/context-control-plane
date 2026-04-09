from __future__ import annotations

from ..adapters import (
    SecretBackendOperationError,
    delete_secret_value,
    inspect_secret_value,
    read_secret_value,
    store_secret_value,
)
from .resource_registry import ResourceRegistry
from .secrets import SecretBackendProfile, SecretConfigurationError


def resolve_secret_backend_profile(
    registry: ResourceRegistry,
    *,
    name: str,
    namespace: str = "default",
) -> SecretBackendProfile:
    document = registry.get_resource(kind="SecretBackend", name=name, namespace=namespace)
    if document is None:
        raise SecretConfigurationError(f"SecretBackend {name!r} was not found in namespace {namespace!r}")
    return SecretBackendProfile.from_document(document)


def set_secret_value(
    registry: ResourceRegistry,
    *,
    backend_name: str,
    secret_name: str,
    value: str,
    namespace: str = "default",
) -> dict[str, object]:
    profile = resolve_secret_backend_profile(registry, name=backend_name, namespace=namespace)
    return store_secret_value(profile, secret_name, value)


def inspect_secret_binding(
    registry: ResourceRegistry,
    *,
    backend_name: str,
    secret_name: str,
    namespace: str = "default",
) -> dict[str, object]:
    profile = resolve_secret_backend_profile(registry, name=backend_name, namespace=namespace)
    return inspect_secret_value(profile, secret_name)


def delete_secret_binding(
    registry: ResourceRegistry,
    *,
    backend_name: str,
    secret_name: str,
    namespace: str = "default",
) -> dict[str, object]:
    profile = resolve_secret_backend_profile(registry, name=backend_name, namespace=namespace)
    return delete_secret_value(profile, secret_name)


def resolve_secret_bindings(
    backend: SecretBackendProfile,
    *,
    secret_refs: tuple[str, ...],
) -> dict[str, str]:
    bindings: dict[str, str] = {}
    for secret_ref in secret_refs:
        ref_name = str(secret_ref or "").strip()
        if not ref_name:
            continue
        bindings[ref_name] = read_secret_value(backend, ref_name)
    return bindings
