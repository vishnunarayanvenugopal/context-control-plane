"""Public adapter interfaces for ccp-core southbound integrations."""

from .interfaces import ConnectionAdapter, IdentityAdapter, McpAdapter, RuntimeAdapter, SecretBackendAdapter
from .http_json import HttpJsonConnectionAdapter
from .mock import MockConnectionAdapter
from .secret_backends import (
    SecretBackendOperationError,
    delete_secret_value,
    inspect_secret_value,
    probe_secret_backend,
    read_secret_value,
    store_secret_value,
)

__all__ = [
    "ConnectionAdapter",
    "HttpJsonConnectionAdapter",
    "IdentityAdapter",
    "McpAdapter",
    "MockConnectionAdapter",
    "RuntimeAdapter",
    "SecretBackendAdapter",
    "SecretBackendOperationError",
    "delete_secret_value",
    "inspect_secret_value",
    "probe_secret_backend",
    "read_secret_value",
    "store_secret_value",
]
