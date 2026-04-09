from __future__ import annotations

import json
import ssl
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping

from ..kernel.command_api import CommandEnvelope, CommandStatus
from ..kernel.materialization import read_materialized_secret_from_context


def _string_mapping(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): str(item) for key, item in value.items()}


def _resolve_url(endpoint: str, path: str) -> str:
    base = str(endpoint or "").strip()
    parsed_base = urllib.parse.urlparse(base)
    if not parsed_base.scheme or not parsed_base.netloc:
        raise ValueError("http-json adapter requires a fully qualified connection endpoint")

    suffix = str(path or "").strip()
    if not suffix:
        return base.rstrip("/")
    if suffix.startswith("//"):
        raise ValueError("http-json request paths must stay relative to the configured endpoint")
    if suffix.startswith("http://") or suffix.startswith("https://"):
        parsed_target = urllib.parse.urlparse(suffix)
        if (parsed_target.scheme, parsed_target.netloc) != (parsed_base.scheme, parsed_base.netloc):
            raise ValueError("http-json request targets must stay on the configured endpoint origin")
        return suffix

    resolved = urllib.parse.urljoin(f"{base.rstrip('/')}/", suffix.lstrip("/"))
    parsed_resolved = urllib.parse.urlparse(resolved)
    if (parsed_resolved.scheme, parsed_resolved.netloc) != (parsed_base.scheme, parsed_base.netloc):
        raise ValueError("http-json request paths must stay on the configured endpoint origin")
    return resolved


def _secret_from_source(
    auth_config: Mapping[str, Any],
    *,
    secret_bindings: Mapping[str, str],
    materialization: Mapping[str, Any] | None,
) -> str:
    secret_ref = str(auth_config.get("secretRef", "") or "").strip()
    if not secret_ref:
        return ""
    source = str(auth_config.get("source", "binding") or "binding").strip().lower()
    if source == "materialized-file":
        if materialization is None:
            raise ValueError("materialized-file auth source requires a materialization context")
        return read_materialized_secret_from_context(materialization, secret_ref)
    return str(secret_bindings.get(secret_ref, "") or "")


def _apply_auth(
    headers: dict[str, str],
    auth_config: Mapping[str, Any],
    *,
    secret_bindings: Mapping[str, str],
    materialization: Mapping[str, Any] | None,
) -> None:
    auth_type = str(auth_config.get("type", "") or "").strip().lower()
    if not auth_type:
        return
    secret_value = _secret_from_source(auth_config, secret_bindings=secret_bindings, materialization=materialization)
    if not secret_value:
        raise ValueError("auth secretRef did not resolve to a usable secret value")
    if auth_type == "bearer":
        header = str(auth_config.get("header", "Authorization") or "Authorization").strip()
        prefix = str(auth_config.get("prefix", "Bearer") or "Bearer").strip()
        headers[header] = f"{prefix} {secret_value}".strip()
        return
    if auth_type == "header":
        header = str(auth_config.get("header", "X-API-Key") or "X-API-Key").strip()
        prefix = str(auth_config.get("prefix", "") or "").strip()
        headers[header] = f"{prefix}{secret_value}" if prefix else secret_value
        return
    if auth_type == "basic":
        import base64

        username = str(auth_config.get("username", "") or "").strip()
        token = base64.b64encode(f"{username}:{secret_value}".encode("utf-8")).decode("ascii")
        headers["Authorization"] = f"Basic {token}"
        return
    raise ValueError(f"unsupported http-json auth type {auth_type!r}")


def _ssl_context(connection: Mapping[str, Any]) -> ssl.SSLContext | None:
    tls = connection.get("tls", {})
    if not isinstance(tls, Mapping):
        tls = {}
    verify_tls = bool(tls.get("verifyTls", True))
    if not verify_tls:
        return ssl._create_unverified_context()
    ca_cert_path = str(tls.get("caCertPath", "") or "").strip()
    if ca_cert_path:
        return ssl.create_default_context(cafile=ca_cert_path)
    return None


@dataclass(frozen=True)
class HttpJsonConnectionAdapter:
    adapter_id: str = "http-json"
    response_allowlist: tuple[str, ...] = ("statusCode", "summary", "json", "headers", "url", "method")

    def test_connection(self, profile_name: str) -> CommandEnvelope:
        return CommandEnvelope(
            status=CommandStatus.OK,
            result={
                "adapter": self.adapter_id,
                "profile": profile_name,
                "message": "http-json adapter is available",
            },
        )

    def execute(
        self,
        profile_name: str,
        action: str,
        params: Mapping[str, Any] | None = None,
        secret_bindings: Mapping[str, str] | None = None,
        connection: Mapping[str, Any] | None = None,
        materialization: Mapping[str, Any] | None = None,
    ) -> CommandEnvelope:
        request_params = dict(params or {})
        connection_config = dict(connection or {})
        endpoint = str(connection_config.get("endpoint", "") or "").strip()
        if not endpoint:
            return CommandEnvelope(status=CommandStatus.ERROR, reason="http-json adapter requires a connection endpoint")

        request_defaults = dict(connection_config.get("request", {})) if isinstance(connection_config.get("request"), Mapping) else {}
        method = str(request_params.get("method", request_defaults.get("method", "GET")) or "GET").strip().upper()
        path = str(request_params.get("path", request_defaults.get("path", "")) or "").strip()
        try:
            url = _resolve_url(endpoint, path)
            query = request_params.get("query", request_defaults.get("query", {}))
            if isinstance(query, Mapping) and query:
                url = f"{url}?{urllib.parse.urlencode({str(key): str(value) for key, value in query.items()})}"

            headers = _string_mapping(connection_config.get("headers"))
            headers.update(_string_mapping(request_params.get("headers")))
            auth_config = dict(connection_config.get("auth", {})) if isinstance(connection_config.get("auth"), Mapping) else {}
            if auth_config:
                _apply_auth(
                    headers,
                    auth_config,
                    secret_bindings=dict(secret_bindings or {}),
                    materialization=materialization,
                )

            body = request_params.get("json", request_defaults.get("json"))
            raw_body = request_params.get("body", request_defaults.get("body"))
            data: bytes | None = None
            if body is not None:
                data = json.dumps(body).encode("utf-8")
                headers.setdefault("Content-Type", "application/json")
            elif raw_body not in (None, ""):
                data = str(raw_body).encode("utf-8")
        except ValueError as exc:
            return CommandEnvelope(
                status=CommandStatus.ERROR,
                reason=str(exc),
                result={"method": method, "url": endpoint},
            )

        request = urllib.request.Request(url=url, method=method, data=data, headers=headers)
        timeout_settings = dict(connection_config.get("timeouts", {})) if isinstance(connection_config.get("timeouts"), Mapping) else {}
        timeout = float(timeout_settings.get("requestSeconds", 5) or 5)
        ssl_context = _ssl_context(connection_config)
        handlers: list[Any] = [urllib.request.ProxyHandler({})]
        if ssl_context is not None:
            handlers.append(urllib.request.HTTPSHandler(context=ssl_context))
        opener = urllib.request.build_opener(*handlers)
        try:
            with opener.open(request, timeout=timeout) as response:
                raw = response.read()
                content_type = str(response.headers.get("Content-Type", "") or "")
                filtered_headers = {
                    key: value
                    for key, value in response.headers.items()
                    if key.lower() in {"content-type", "x-request-id"}
                }
                payload: dict[str, Any] = {
                    "method": method,
                    "url": url,
                    "statusCode": response.status,
                    "headers": filtered_headers,
                    "summary": f"http-json adapter executed {action} with {method} {url} -> {response.status}",
                }
                if "json" in content_type.lower():
                    payload["json"] = json.loads(raw.decode("utf-8") or "null")
                elif raw:
                    payload["json"] = {"text": raw.decode("utf-8", errors="replace")}
        except urllib.error.HTTPError as exc:
            exc.read()
            return CommandEnvelope(
                status=CommandStatus.ERROR,
                reason=f"http-json request failed with HTTP {exc.code}",
                result={
                    "method": method,
                    "url": url,
                    "statusCode": exc.code,
                },
            )
        except urllib.error.URLError as exc:
            return CommandEnvelope(
                status=CommandStatus.ERROR,
                reason="http-json request failed",
                result={"method": method, "url": url},
            )
        except ValueError as exc:
            return CommandEnvelope(
                status=CommandStatus.ERROR,
                reason=str(exc),
                result={"method": method, "url": url},
            )
        return CommandEnvelope(status=CommandStatus.OK, result=payload)
