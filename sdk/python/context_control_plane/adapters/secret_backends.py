from __future__ import annotations

import json
import os
import platform
import shutil
import ssl
import stat
import subprocess
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

from ..kernel.secrets import SecretBackendProfile, SecretDurability


@dataclass(frozen=True)
class SecretBackendStatus:
    backend: SecretBackendProfile
    health: str
    reason: str
    capabilities: tuple[str, ...] = field(default_factory=tuple)
    warnings: tuple[str, ...] = field(default_factory=tuple)
    details: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend.to_dict(),
            "health": self.health,
            "reason": self.reason,
            "capabilities": list(self.capabilities),
            "warnings": list(self.warnings),
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class SecretValueStatus:
    backend: SecretBackendProfile
    secret_name: str
    exists: bool
    reason: str
    details: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend.to_dict(),
            "secretName": self.secret_name,
            "exists": self.exists,
            "reason": self.reason,
            "details": dict(self.details),
        }


class SecretBackendOperationError(RuntimeError):
    pass


_MEMORY_SECRET_STORE: dict[tuple[str, str, str], str] = {}


class OSKeychainSecretBackendAdapter:
    adapter_id = "os-keychain"

    def probe(self, profile: SecretBackendProfile) -> Mapping[str, Any]:
        system = platform.system().lower()
        warnings: list[str] = []
        details = {
            "platform": system or "unknown",
            "securityCliAvailable": bool(shutil.which("security")),
            "secretToolAvailable": bool(shutil.which("secret-tool")),
        }
        if system == "darwin":
            health = "ok" if details["securityCliAvailable"] else "attention_needed"
            reason = "macOS secure storage is available" if health == "ok" else "macOS security CLI is not available"
            capabilities = ("brokered", "local-persistent", "materialize", "store", "inspect", "delete", "read")
        elif system == "linux":
            health = "ok" if details["secretToolAvailable"] else "attention_needed"
            reason = "Linux secret-tool is available" if health == "ok" else "Install libsecret/secret-tool for OS keyring support"
            capabilities = ("brokered", "local-persistent", "store", "inspect", "delete", "read")
            warnings.append("OS keychain support on Linux depends on the desktop keyring being available.")
        else:
            health = "attention_needed"
            reason = f"os-keychain support is not yet fully characterized on {system or 'this platform'}"
            capabilities = ("brokered",)
        return SecretBackendStatus(
            backend=profile,
            health=health,
            reason=reason,
            capabilities=capabilities,
            warnings=tuple(warnings),
            details=details,
        ).to_dict()

    def store(self, profile: SecretBackendProfile, secret_name: str, value: str) -> Mapping[str, Any]:
        service, account, label = _os_keychain_identity(profile, secret_name)
        system = platform.system().lower()
        if system == "darwin":
            result = subprocess.run(
                [
                    "security",
                    "add-generic-password",
                    "-U",
                    "-s",
                    service,
                    "-a",
                    account,
                    "-l",
                    label,
                    "-T",
                    "",
                    "-w",
                ],
                check=False,
                text=True,
                input=value,
                capture_output=True,
            )
            if result.returncode != 0:
                raise SecretBackendOperationError((result.stderr or result.stdout or "").strip() or "macOS keychain write failed")
        elif system == "linux":
            result = subprocess.run(
                ["secret-tool", "store", "--label", label, "service", service, "account", account],
                check=False,
                text=True,
                input=value,
                capture_output=True,
            )
            if result.returncode != 0:
                raise SecretBackendOperationError((result.stderr or result.stdout or "").strip() or "secret-tool write failed")
        else:
            raise SecretBackendOperationError("os-keychain write is not supported on this platform yet")
        return SecretValueStatus(
            backend=profile,
            secret_name=secret_name,
            exists=True,
            reason="secret value stored without exposing it to CLI output",
            details={"service": service, "account": account},
        ).to_dict()

    def inspect(self, profile: SecretBackendProfile, secret_name: str) -> Mapping[str, Any]:
        service, account, _label = _os_keychain_identity(profile, secret_name)
        system = platform.system().lower()
        if system == "darwin":
            result = subprocess.run(
                ["security", "find-generic-password", "-w", "-s", service, "-a", account],
                check=False,
                capture_output=True,
                text=True,
            )
            exists = result.returncode == 0
        elif system == "linux":
            result = subprocess.run(
                ["secret-tool", "lookup", "service", service, "account", account],
                check=False,
                capture_output=True,
                text=True,
            )
            exists = result.returncode == 0 and bool((result.stdout or "").strip())
        else:
            raise SecretBackendOperationError("os-keychain inspect is not supported on this platform yet")
        return SecretValueStatus(
            backend=profile,
            secret_name=secret_name,
            exists=exists,
            reason="secret value is present in the backend" if exists else "secret value was not found in the backend",
            details={"service": service, "account": account},
        ).to_dict()

    def read(self, profile: SecretBackendProfile, secret_name: str) -> str:
        service, account, _label = _os_keychain_identity(profile, secret_name)
        system = platform.system().lower()
        if system == "darwin":
            result = subprocess.run(
                ["security", "find-generic-password", "-w", "-s", service, "-a", account],
                check=False,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                raise SecretBackendOperationError((result.stderr or result.stdout or "").strip() or "macOS keychain read failed")
            value = result.stdout
        elif system == "linux":
            result = subprocess.run(
                ["secret-tool", "lookup", "service", service, "account", account],
                check=False,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                raise SecretBackendOperationError((result.stderr or result.stdout or "").strip() or "secret-tool read failed")
            value = result.stdout
        else:
            raise SecretBackendOperationError("os-keychain read is not supported on this platform yet")
        cleaned = str(value or "").rstrip("\n")
        if not cleaned:
            raise SecretBackendOperationError("secret value was not found in the backend")
        return cleaned

    def delete(self, profile: SecretBackendProfile, secret_name: str) -> Mapping[str, Any]:
        service, account, _label = _os_keychain_identity(profile, secret_name)
        system = platform.system().lower()
        if system == "darwin":
            result = subprocess.run(
                ["security", "delete-generic-password", "-s", service, "-a", account],
                check=False,
                capture_output=True,
                text=True,
            )
            if result.returncode not in {0, 44}:
                raise SecretBackendOperationError((result.stderr or result.stdout or "").strip() or "macOS keychain delete failed")
        elif system == "linux":
            result = subprocess.run(
                ["secret-tool", "clear", "service", service, "account", account],
                check=False,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                raise SecretBackendOperationError((result.stderr or result.stdout or "").strip() or "secret-tool delete failed")
        else:
            raise SecretBackendOperationError("os-keychain delete is not supported on this platform yet")
        return SecretValueStatus(
            backend=profile,
            secret_name=secret_name,
            exists=False,
            reason="secret value removed from the backend",
            details={"service": service, "account": account},
        ).to_dict()


class EncryptedFileSecretBackendAdapter:
    adapter_id = "encrypted-file"

    def probe(self, profile: SecretBackendProfile) -> Mapping[str, Any]:
        settings = _encrypted_file_settings(profile)
        path = settings["storagePath"]
        warnings: list[str] = []
        if settings["usingDefaultPath"]:
            warnings.append("storagePath was not configured, so the default encrypted-file location was assumed.")
        if settings["usingDefaultPassphraseEnv"]:
            warnings.append("passphraseEnvVar was not configured, so the default encrypted-file key environment variable was assumed.")
        if path.suffix == ".json":
            warnings.append("avoid .json storagePath values for encrypted secret stores because resource loaders may mistake them for config.")
        parent = path.parent
        parent_exists = parent.exists()
        writable = os.access(parent if parent_exists else parent.parent, os.W_OK) if parent.parent.exists() else False
        file_mode = oct(stat.S_IMODE(path.stat().st_mode)) if path.exists() else ""
        if path.exists() and stat.S_IMODE(path.stat().st_mode) != 0o600:
            warnings.append("encrypted-file backend should use 0600 permissions to reduce shoulder-surfing by the filesystem.")
        if not settings["opensslAvailable"]:
            health = "attention_needed"
            reason = "OpenSSL is required for encrypted-file secret storage operations"
        elif not settings["passphrase"]:
            health = "attention_needed"
            reason = f"encrypted-file backend passphrase is missing; set {settings['passphraseEnvVar']}"
        elif not writable:
            health = "attention_needed"
            reason = "encrypted-file backend path is not writable"
        else:
            health = "ok"
            reason = "encrypted-file backend is configured for encrypted local persistence"
        return SecretBackendStatus(
            backend=profile,
            health=health,
            reason=reason,
            capabilities=("brokered", "local-persistent", "materialize", "store", "inspect", "delete", "read"),
            warnings=tuple(warnings),
            details={
                "storagePath": str(path),
                "passphraseEnvVar": settings["passphraseEnvVar"],
                "parentExists": parent_exists,
                "writable": writable,
                "opensslAvailable": settings["opensslAvailable"],
                "fileMode": file_mode,
            },
        ).to_dict()

    def store(self, profile: SecretBackendProfile, secret_name: str, value: str) -> Mapping[str, Any]:
        secrets = _encrypted_file_load(profile)
        secrets[str(secret_name)] = str(value)
        _encrypted_file_store(profile, secrets)
        return SecretValueStatus(
            backend=profile,
            secret_name=secret_name,
            exists=True,
            reason="secret value stored in encrypted local file backend",
            details={"storagePath": str(_encrypted_file_settings(profile)["storagePath"])},
        ).to_dict()

    def inspect(self, profile: SecretBackendProfile, secret_name: str) -> Mapping[str, Any]:
        secrets = _encrypted_file_load(profile)
        exists = str(secret_name) in secrets
        return SecretValueStatus(
            backend=profile,
            secret_name=secret_name,
            exists=exists,
            reason="secret value is present in the encrypted backend" if exists else "secret value was not found in the encrypted backend",
            details={"storagePath": str(_encrypted_file_settings(profile)["storagePath"])},
        ).to_dict()

    def read(self, profile: SecretBackendProfile, secret_name: str) -> str:
        secrets = _encrypted_file_load(profile)
        try:
            return secrets[str(secret_name)]
        except KeyError as exc:
            raise SecretBackendOperationError("secret value was not found in the encrypted backend") from exc

    def delete(self, profile: SecretBackendProfile, secret_name: str) -> Mapping[str, Any]:
        secrets = _encrypted_file_load(profile)
        secrets.pop(str(secret_name), None)
        _encrypted_file_store(profile, secrets)
        return SecretValueStatus(
            backend=profile,
            secret_name=secret_name,
            exists=False,
            reason="secret value removed from the encrypted backend",
            details={"storagePath": str(_encrypted_file_settings(profile)["storagePath"])},
        ).to_dict()


class VaultSecretBackendAdapter:
    adapter_id = "vault"

    def probe(self, profile: SecretBackendProfile) -> Mapping[str, Any]:
        settings = _vault_settings(profile)
        config = dict(profile.config)
        warnings: list[str] = []
        if profile.durability is SecretDurability.EPHEMERAL:
            warnings.append("Vault backend is marked ephemeral; secrets may disappear when the backing service restarts.")
        parsed = urlparse(settings["address"]) if settings["address"] else None
        if settings["address"] and parsed and parsed.hostname in {"127.0.0.1", "localhost"}:
            warnings.append("Vault points to localhost; confirm this is acceptable for long-lived usage.")
        if any(str(config.get(field, "") or "").strip() for field in ("token", "roleId", "secretId")):
            warnings.append("Vault credentials embedded in backend config are ignored; use environment variables or workload identity instead.")
        if not settings["address"]:
            health = "attention_needed"
            reason = f"Vault address is not configured; set {settings['addressEnvVar']} or config.address"
        elif not settings["token"] and settings["authMethod"] != "approle":
            health = "attention_needed"
            reason = f"Vault token is not configured; set {settings['tokenEnvVar']} or provide a managed identity flow"
        elif settings["authMethod"] == "approle" and (not settings["roleId"] or not settings["secretId"]):
            health = "attention_needed"
            reason = (
                f"Vault AppRole auth is incomplete; set {settings['roleIdEnvVar']} and {settings['secretIdEnvVar']} "
                "or provide a managed identity flow"
            )
        else:
            health = "ok"
            reason = (
                "Vault AppRole configuration is present for brokered usage"
                if settings["authMethod"] == "approle"
                else "Vault configuration is present for brokered usage"
            )
        return SecretBackendStatus(
            backend=profile,
            health=health,
            reason=reason,
            capabilities=("brokered", "service-persistent", "materialize", "store", "inspect", "delete", "read"),
            warnings=tuple(warnings),
            details={
                "address": settings["address"],
                "addressEnvVar": settings["addressEnvVar"],
                "authMethod": settings["authMethod"],
                "authMount": settings["authMount"],
                "roleIdEnvVar": settings["roleIdEnvVar"],
                "secretIdEnvVar": settings["secretIdEnvVar"],
                "tokenEnvVar": settings["tokenEnvVar"],
                "tokenPresent": bool(settings["token"]),
            },
        ).to_dict()

    def store(self, profile: SecretBackendProfile, secret_name: str, value: str) -> Mapping[str, Any]:
        path, field = _vault_secret_path_and_field(profile, secret_name)
        _vault_request(profile, method="POST", path=path, payload={"data": {field: value}})
        return SecretValueStatus(
            backend=profile,
            secret_name=secret_name,
            exists=True,
            reason="secret value stored in Vault",
            details={"path": path, "field": field},
        ).to_dict()

    def inspect(self, profile: SecretBackendProfile, secret_name: str) -> Mapping[str, Any]:
        path, field = _vault_secret_path_and_field(profile, secret_name)
        payload = _vault_request(profile, method="GET", path=path, allow_missing=True)
        data = dict(payload.get("data", {}) or {}).get("data", {})
        exists = isinstance(data, dict) and isinstance(data.get(field), str)
        return SecretValueStatus(
            backend=profile,
            secret_name=secret_name,
            exists=exists,
            reason="secret value is present in Vault" if exists else "secret value was not found in Vault",
            details={"path": path, "field": field},
        ).to_dict()

    def read(self, profile: SecretBackendProfile, secret_name: str) -> str:
        path, field = _vault_secret_path_and_field(profile, secret_name)
        payload = _vault_request(profile, method="GET", path=path, allow_missing=True)
        data = dict(payload.get("data", {}) or {}).get("data", {})
        value = data.get(field) if isinstance(data, dict) else None
        if not isinstance(value, str) or not value:
            raise SecretBackendOperationError("secret value was not found in Vault")
        return value

    def delete(self, profile: SecretBackendProfile, secret_name: str) -> Mapping[str, Any]:
        path, _field = _vault_secret_path_and_field(profile, secret_name)
        _vault_request(profile, method="DELETE", path=path, allow_missing=True)
        return SecretValueStatus(
            backend=profile,
            secret_name=secret_name,
            exists=False,
            reason="secret value removed from Vault",
            details={"path": path},
        ).to_dict()


class MemorySecretBackendAdapter:
    adapter_id = "memory"

    def probe(self, profile: SecretBackendProfile) -> Mapping[str, Any]:
        return SecretBackendStatus(
            backend=profile,
            health="attention_needed",
            reason="memory backend is ephemeral and should stay limited to dev or test usage",
            capabilities=("brokered", "store", "inspect", "delete", "read"),
            warnings=("memory backend is not durable and should not be a default for day-to-day use.",),
            details={},
        ).to_dict()

    def store(self, profile: SecretBackendProfile, secret_name: str, value: str) -> Mapping[str, Any]:
        _MEMORY_SECRET_STORE[(profile.namespace, profile.name, secret_name)] = value
        return SecretValueStatus(
            backend=profile,
            secret_name=secret_name,
            exists=True,
            reason="secret value stored in ephemeral memory backend",
            details={},
        ).to_dict()

    def inspect(self, profile: SecretBackendProfile, secret_name: str) -> Mapping[str, Any]:
        exists = (profile.namespace, profile.name, secret_name) in _MEMORY_SECRET_STORE
        return SecretValueStatus(
            backend=profile,
            secret_name=secret_name,
            exists=exists,
            reason="secret value is present in memory" if exists else "secret value was not found in memory",
            details={},
        ).to_dict()

    def read(self, profile: SecretBackendProfile, secret_name: str) -> str:
        key = (profile.namespace, profile.name, secret_name)
        if key not in _MEMORY_SECRET_STORE:
            raise SecretBackendOperationError("secret value was not found in memory")
        return _MEMORY_SECRET_STORE[key]

    def delete(self, profile: SecretBackendProfile, secret_name: str) -> Mapping[str, Any]:
        _MEMORY_SECRET_STORE.pop((profile.namespace, profile.name, secret_name), None)
        return SecretValueStatus(
            backend=profile,
            secret_name=secret_name,
            exists=False,
            reason="secret value removed from the memory backend",
            details={},
        ).to_dict()


class GenericSecretBackendAdapter:
    adapter_id = "generic"

    def probe(self, profile: SecretBackendProfile) -> Mapping[str, Any]:
        return SecretBackendStatus(
            backend=profile,
            health="attention_needed",
            reason="custom backend type is not yet mapped to a native adapter",
            capabilities=("brokered",),
            warnings=("add a dedicated backend adapter for richer health checks and integration behavior.",),
            details={"type": profile.backend_type},
        ).to_dict()


def probe_secret_backend(profile: SecretBackendProfile) -> dict[str, Any]:
    adapter = _resolve_backend_adapter(profile.backend_type)
    return dict(adapter.probe(profile))


def store_secret_value(profile: SecretBackendProfile, secret_name: str, value: str) -> dict[str, Any]:
    if not str(secret_name or "").strip():
        raise SecretBackendOperationError("secret name is required")
    if value is None or value == "":
        raise SecretBackendOperationError("secret value is required")
    adapter = _resolve_backend_adapter(profile.backend_type)
    if not hasattr(adapter, "store"):
        raise SecretBackendOperationError(f"secret backend type {profile.backend_type!r} does not support write operations yet")
    return dict(adapter.store(profile, str(secret_name).strip(), str(value)))


def inspect_secret_value(profile: SecretBackendProfile, secret_name: str) -> dict[str, Any]:
    if not str(secret_name or "").strip():
        raise SecretBackendOperationError("secret name is required")
    adapter = _resolve_backend_adapter(profile.backend_type)
    if not hasattr(adapter, "inspect"):
        raise SecretBackendOperationError(f"secret backend type {profile.backend_type!r} does not support inspect operations yet")
    return dict(adapter.inspect(profile, str(secret_name).strip()))


def read_secret_value(profile: SecretBackendProfile, secret_name: str) -> str:
    if not str(secret_name or "").strip():
        raise SecretBackendOperationError("secret name is required")
    adapter = _resolve_backend_adapter(profile.backend_type)
    if not hasattr(adapter, "read"):
        raise SecretBackendOperationError(f"secret backend type {profile.backend_type!r} does not support read operations yet")
    return str(adapter.read(profile, str(secret_name).strip()))


def delete_secret_value(profile: SecretBackendProfile, secret_name: str) -> dict[str, Any]:
    if not str(secret_name or "").strip():
        raise SecretBackendOperationError("secret name is required")
    adapter = _resolve_backend_adapter(profile.backend_type)
    if not hasattr(adapter, "delete"):
        raise SecretBackendOperationError(f"secret backend type {profile.backend_type!r} does not support delete operations yet")
    return dict(adapter.delete(profile, str(secret_name).strip()))


def _resolve_backend_adapter(backend_type: str):
    normalized = str(backend_type or "").strip().lower()
    if normalized == "os-keychain":
        return OSKeychainSecretBackendAdapter()
    if normalized == "encrypted-file":
        return EncryptedFileSecretBackendAdapter()
    if normalized == "vault":
        return VaultSecretBackendAdapter()
    if normalized == "memory":
        return MemorySecretBackendAdapter()
    return GenericSecretBackendAdapter()


def _os_keychain_identity(profile: SecretBackendProfile, secret_name: str) -> tuple[str, str, str]:
    config = dict(profile.config)
    prefix = str(config.get("servicePrefix", "ccp-core") or "ccp-core").strip().strip("/")
    service = f"{prefix}/{profile.namespace}/{profile.name}/{secret_name}"
    account = str(config.get("account", secret_name) or secret_name).strip()
    label = f"ccp-core:{profile.namespace}:{profile.name}:{secret_name}"
    return service, account, label


def _vault_settings(profile: SecretBackendProfile) -> dict[str, Any]:
    config = dict(profile.config)
    address_env_var = str(config.get("addressEnvVar", "VAULT_ADDR") or "VAULT_ADDR").strip()
    token_env_var = str(config.get("tokenEnvVar", "VAULT_TOKEN") or "VAULT_TOKEN").strip()
    namespace_env_var = str(config.get("namespaceEnvVar", "VAULT_NAMESPACE") or "VAULT_NAMESPACE").strip()
    role_id_env_var = str(config.get("roleIdEnvVar", "VAULT_ROLE_ID") or "VAULT_ROLE_ID").strip()
    secret_id_env_var = str(config.get("secretIdEnvVar", "VAULT_SECRET_ID") or "VAULT_SECRET_ID").strip()
    auth_method = str(config.get("authMethod", "token") or "token").strip().lower() or "token"
    return {
        "address": str(os.environ.get(address_env_var, "") or config.get("address", "") or "").strip().rstrip("/"),
        "token": str(os.environ.get(token_env_var, "") or "").strip(),
        "namespace": str(os.environ.get(namespace_env_var, "") or config.get("namespace", "") or "").strip(),
        "kvMount": str(config.get("kvMount", "secret") or "secret").strip() or "secret",
        "kvPrefix": str(config.get("kvPrefix", f"ccp-core/{profile.namespace}/{profile.name}") or "").strip().strip("/"),
        "verifyTls": bool(config.get("verifyTls", True)),
        "caCertPath": str(config.get("caCertPath", "") or "").strip(),
        "timeoutSeconds": int(config.get("timeoutSeconds", 5) or 5),
        "authMethod": auth_method,
        "authMount": str(config.get("authMount", "approle") or "approle").strip().strip("/") or "approle",
        "roleId": str(os.environ.get(role_id_env_var, "") or "").strip(),
        "secretId": str(os.environ.get(secret_id_env_var, "") or "").strip(),
        "addressEnvVar": address_env_var,
        "tokenEnvVar": token_env_var,
        "roleIdEnvVar": role_id_env_var,
        "secretIdEnvVar": secret_id_env_var,
    }


def _vault_secret_path_and_field(profile: SecretBackendProfile, secret_name: str) -> tuple[str, str]:
    settings = _vault_settings(profile)
    if not settings["address"]:
        raise SecretBackendOperationError(
            f"Vault address is not configured; set {settings['addressEnvVar']} or backend config.address"
        )
    if not settings["token"] and settings["authMethod"] != "approle":
        raise SecretBackendOperationError(
            f"Vault token is not configured; set {settings['tokenEnvVar']} or use a managed identity flow"
        )
    if settings["authMethod"] == "approle" and (not settings["roleId"] or not settings["secretId"]):
        raise SecretBackendOperationError(
            f"Vault AppRole auth is incomplete; set {settings['roleIdEnvVar']} and {settings['secretIdEnvVar']}"
        )
    path = "/".join(part for part in [settings["kvMount"], "data", settings["kvPrefix"], secret_name] if part)
    field = str(profile.config.get("field", "value") or "value").strip() or "value"
    return path, field


def _vault_request(
    profile: SecretBackendProfile,
    *,
    method: str,
    path: str,
    payload: Mapping[str, Any] | None = None,
    allow_missing: bool = False,
) -> dict[str, Any]:
    settings = _vault_settings(profile)
    token = _vault_resolve_token(settings)
    return _vault_request_with_settings(
        settings,
        token=token,
        method=method,
        path=path,
        payload=payload,
        allow_missing=allow_missing,
    )


def _vault_resolve_token(settings: Mapping[str, Any]) -> str:
    token = str(settings.get("token", "") or "").strip()
    if token:
        return token
    if str(settings.get("authMethod", "token") or "token").strip().lower() != "approle":
        return ""
    payload = _vault_request_with_settings(
        settings,
        token="",
        method="POST",
        path=f"auth/{settings['authMount']}/login",
        payload={
            "role_id": settings["roleId"],
            "secret_id": settings["secretId"],
        },
        allow_missing=False,
    )
    auth = dict(payload.get("auth", {}) or {})
    token = str(auth.get("client_token", "") or "").strip()
    if not token:
        raise SecretBackendOperationError("Vault AppRole login did not return a client token")
    return token


def _vault_request_with_settings(
    settings: Mapping[str, Any],
    *,
    token: str,
    method: str,
    path: str,
    payload: Mapping[str, Any] | None = None,
    allow_missing: bool = False,
) -> dict[str, Any]:
    body = None
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
    }
    if token:
        headers["X-Vault-Token"] = token
    if settings["namespace"]:
        headers["X-Vault-Namespace"] = settings["namespace"]
    request = urllib.request.Request(f"{settings['address']}/v1/{path.lstrip('/')}", data=body, method=method, headers=headers)
    context = None
    if not settings["verifyTls"]:
        context = ssl._create_unverified_context()
    elif settings["caCertPath"]:
        context = ssl.create_default_context(cafile=settings["caCertPath"])
    try:
        with urllib.request.urlopen(request, context=context, timeout=settings["timeoutSeconds"]) as response:
            raw = response.read().decode("utf-8") if response.length != 0 else ""
    except urllib.error.HTTPError as exc:
        if allow_missing and exc.code == 404:
            return {}
        message = exc.read().decode("utf-8", errors="replace").strip()
        raise SecretBackendOperationError(f"Vault request failed: HTTP {exc.code}. {message}".strip()) from exc
    except urllib.error.URLError as exc:
        raise SecretBackendOperationError(f"unable to reach Vault at {settings['address']}: {exc.reason}") from exc
    if not raw:
        return {}
    try:
        payload_obj = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SecretBackendOperationError(f"Vault returned invalid JSON: {exc}") from exc
    if not isinstance(payload_obj, dict):
        raise SecretBackendOperationError("Vault returned an unexpected payload.")
    return payload_obj


def _encrypted_file_settings(profile: SecretBackendProfile) -> dict[str, Any]:
    config = dict(profile.config)
    raw_path = str(config.get("storagePath", "") or "").strip()
    using_default_path = False
    if not raw_path:
        raw_path = str(Path.home() / ".config" / "ccp-core" / "secrets.enc")
        using_default_path = True
    path = Path(raw_path).expanduser().resolve()
    passphrase_env_var = str(config.get("passphraseEnvVar", "CCP_ENCRYPTED_FILE_KEY") or "CCP_ENCRYPTED_FILE_KEY").strip()
    using_default_passphrase_env = "passphraseEnvVar" not in config
    cipher = str(config.get("cipher", "aes-256-cbc") or "aes-256-cbc").strip() or "aes-256-cbc"
    return {
        "storagePath": path,
        "passphraseEnvVar": passphrase_env_var,
        "passphrase": str(os.environ.get(passphrase_env_var, "") or "").strip(),
        "cipher": cipher,
        "opensslAvailable": bool(shutil.which("openssl")),
        "usingDefaultPath": using_default_path,
        "usingDefaultPassphraseEnv": using_default_passphrase_env,
    }


def _encrypted_file_load(profile: SecretBackendProfile) -> dict[str, str]:
    settings = _encrypted_file_settings(profile)
    path = settings["storagePath"]
    if not settings["opensslAvailable"]:
        raise SecretBackendOperationError("OpenSSL is required for encrypted-file secret operations")
    if not settings["passphrase"]:
        raise SecretBackendOperationError(
            f"encrypted-file backend passphrase is missing; set {settings['passphraseEnvVar']}"
        )
    if not path.exists():
        return {}
    result = subprocess.run(
        [
            "openssl",
            "enc",
            f"-{settings['cipher']}",
            "-d",
            "-pbkdf2",
            "-a",
            "-pass",
            f"env:{settings['passphraseEnvVar']}",
        ],
        check=False,
        input=path.read_bytes(),
        capture_output=True,
        env=_subprocess_secret_env(settings["passphraseEnvVar"], settings["passphrase"]),
    )
    if result.returncode != 0:
        raise SecretBackendOperationError((result.stderr or result.stdout).decode("utf-8", errors="replace").strip() or "encrypted-file decrypt failed")
    try:
        payload = json.loads(result.stdout.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise SecretBackendOperationError(f"encrypted-file backend contained invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise SecretBackendOperationError("encrypted-file backend payload must be a JSON object")
    return {str(key): str(value) for key, value in payload.items()}


def _encrypted_file_store(profile: SecretBackendProfile, payload: Mapping[str, str]) -> None:
    settings = _encrypted_file_settings(profile)
    path = settings["storagePath"]
    if not settings["opensslAvailable"]:
        raise SecretBackendOperationError("OpenSSL is required for encrypted-file secret operations")
    if not settings["passphrase"]:
        raise SecretBackendOperationError(
            f"encrypted-file backend passphrase is missing; set {settings['passphraseEnvVar']}"
        )
    if not payload:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    plaintext = json.dumps(dict(payload), sort_keys=True).encode("utf-8")
    result = subprocess.run(
        [
            "openssl",
            "enc",
            f"-{settings['cipher']}",
            "-pbkdf2",
            "-a",
            "-pass",
            f"env:{settings['passphraseEnvVar']}",
        ],
        check=False,
        input=plaintext,
        capture_output=True,
        env=_subprocess_secret_env(settings["passphraseEnvVar"], settings["passphrase"]),
    )
    if result.returncode != 0:
        raise SecretBackendOperationError((result.stderr or result.stdout).decode("utf-8", errors="replace").strip() or "encrypted-file encrypt failed")
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".ccp-secret-", delete=False) as handle:
        temp_path = Path(handle.name)
        handle.write(result.stdout)
    os.chmod(temp_path, 0o600)
    temp_path.replace(path)
    os.chmod(path, 0o600)


def _subprocess_secret_env(name: str, value: str) -> dict[str, str]:
    env = dict(os.environ)
    env[name] = value
    return env
