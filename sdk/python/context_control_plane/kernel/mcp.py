from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

from .resource_registry import ResourceDocument, ResourceRegistry
from .loaders import load_resource_file
from .mcp_runtime import observe_mcp_runtime

_TRUST_TIERS = frozenset({"builtin-trusted", "verified", "user-added", "quarantined"})
_SECRET_USAGE_MODES = frozenset({"brokered", "ephemeral-materialization", "raw-secret"})
_EGRESS_MODES = frozenset({"deny", "allowlist", "open", "inherit", "unspecified"})


class McpConfigurationError(ValueError):
    """Raised when an MCP resource document is malformed."""


def _string_list(value: Any) -> tuple[str, ...]:
    if value in (None, ""):
        return ()
    if not isinstance(value, (list, tuple, set)):
        raise McpConfigurationError("expected a JSON array of strings")
    return tuple(str(item).strip() for item in value if str(item).strip())


def _normalize_sanitization_fields(value: Any) -> dict[str, list[str]]:
    items = list(_string_list(value))
    return {"redact": items}


def _mapping(value: Any, *, field_name: str) -> Mapping[str, Any]:
    if value in (None, ""):
        return {}
    if not isinstance(value, Mapping):
        raise McpConfigurationError(f"{field_name} must be a JSON object when provided")
    return value


def _pick(spec: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in spec:
            return spec[key]
    return None


@dataclass(frozen=True)
class McpServerProfile:
    name: str
    namespace: str
    transport: str
    enabled: bool
    command: str
    args: tuple[str, ...] = field(default_factory=tuple)
    url: str = ""
    mode: str = "read"
    capabilities: tuple[str, ...] = field(default_factory=tuple)
    declared_tools: tuple[str, ...] = field(default_factory=tuple)
    source: str = ""

    @classmethod
    def from_document(cls, document: ResourceDocument) -> "McpServerProfile":
        if document.identifier.kind != "McpServer":
            raise McpConfigurationError("expected an McpServer resource")
        spec = document.spec
        transport = str(_pick(spec, "transport") or "").strip().lower()
        if transport not in {"stdio", "http", "https"}:
            raise McpConfigurationError("McpServer transport must be one of stdio, http, or https")
        command = str(_pick(spec, "command") or "").strip()
        url = str(_pick(spec, "url") or "").strip()
        if transport == "stdio" and not command:
            raise McpConfigurationError("stdio McpServer resources require spec.command")
        if transport in {"http", "https"} and not url:
            raise McpConfigurationError("http/https McpServer resources require spec.url")
        return cls(
            name=document.identifier.name,
            namespace=document.identifier.namespace,
            transport=transport,
            enabled=bool(_pick(spec, "enabled") if _pick(spec, "enabled") is not None else True),
            command=command,
            args=_string_list(_pick(spec, "args")),
            url=url,
            mode=str(_pick(spec, "mode") or "read").strip() or "read",
            capabilities=_string_list(_pick(spec, "capabilities")),
            declared_tools=_string_list(_pick(spec, "declared_tools", "declaredTools")),
            source=document.provenance[0].source if document.provenance else "",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "namespace": self.namespace,
            "transport": self.transport,
            "enabled": self.enabled,
            "command": self.command,
            "args": list(self.args),
            "url": self.url,
            "mode": self.mode,
            "capabilities": list(self.capabilities),
            "declaredTools": list(self.declared_tools),
            "source": self.source,
        }


@dataclass(frozen=True)
class McpPolicyProfile:
    name: str
    namespace: str
    targets: tuple[str, ...]
    trust_tier: str
    sandbox_profile: Mapping[str, Any]
    egress_policy: Mapping[str, Any]
    secret_usage_mode: str
    input_sanitization: Mapping[str, Any]
    output_sanitization: Mapping[str, Any]
    trace_redaction: Mapping[str, Any]
    tool_rules: tuple[Mapping[str, Any], ...]
    source: str = ""

    @classmethod
    def from_document(cls, document: ResourceDocument) -> "McpPolicyProfile":
        if document.identifier.kind != "McpPolicy":
            raise McpConfigurationError("expected an McpPolicy resource")
        spec = document.spec
        trust_tier = str(_pick(spec, "trust_tier", "trustTier") or "quarantined").strip().lower() or "quarantined"
        if trust_tier not in _TRUST_TIERS:
            raise McpConfigurationError(f"unsupported MCP trust tier {trust_tier!r}")
        secret_usage_mode = (
            str(_pick(spec, "secret_usage_mode", "secretUsageMode") or "brokered").strip().lower() or "brokered"
        )
        if secret_usage_mode not in _SECRET_USAGE_MODES:
            raise McpConfigurationError(f"unsupported MCP secret usage mode {secret_usage_mode!r}")

        egress_policy = dict(_mapping(_pick(spec, "egress_policy", "egressPolicy"), field_name="egress_policy"))
        egress_mode = str(egress_policy.get("mode", "unspecified") or "unspecified").strip().lower() or "unspecified"
        if egress_mode not in _EGRESS_MODES:
            raise McpConfigurationError(f"unsupported MCP egress mode {egress_mode!r}")
        egress_policy["mode"] = egress_mode

        tool_rules_raw = _pick(spec, "tool_rules", "toolRules")
        tool_rules = _stringify_mapping_list(tool_rules_raw, field_name="tool_rules")

        return cls(
            name=document.identifier.name,
            namespace=document.identifier.namespace,
            targets=_string_list(_pick(spec, "targets")),
            trust_tier=trust_tier,
            sandbox_profile=dict(_mapping(_pick(spec, "sandbox_profile", "sandboxProfile"), field_name="sandbox_profile")),
            egress_policy=egress_policy,
            secret_usage_mode=secret_usage_mode,
            input_sanitization=dict(
                _mapping(_pick(spec, "input_sanitization", "inputSanitization"), field_name="input_sanitization")
            ),
            output_sanitization=dict(
                _mapping(_pick(spec, "output_sanitization", "outputSanitization"), field_name="output_sanitization")
            ),
            trace_redaction=dict(
                _mapping(_pick(spec, "trace_redaction", "traceRedaction"), field_name="trace_redaction")
            ),
            tool_rules=tool_rules,
            source=document.provenance[0].source if document.provenance else "",
        )

    def targets_server(self, server_name: str) -> bool:
        return self.name == server_name or server_name in self.targets

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "namespace": self.namespace,
            "targets": list(self.targets),
            "trustTier": self.trust_tier,
            "sandboxProfile": dict(self.sandbox_profile),
            "egressPolicy": dict(self.egress_policy),
            "secretUsageMode": self.secret_usage_mode,
            "inputSanitization": dict(self.input_sanitization),
            "outputSanitization": dict(self.output_sanitization),
            "traceRedaction": dict(self.trace_redaction),
            "toolRules": [dict(item) for item in self.tool_rules],
            "source": self.source,
        }


def _stringify_mapping_list(value: Any, *, field_name: str) -> tuple[Mapping[str, Any], ...]:
    if value in (None, ""):
        return ()
    if not isinstance(value, list):
        raise McpConfigurationError(f"{field_name} must be a JSON array when provided")
    normalized: list[Mapping[str, Any]] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise McpConfigurationError(f"{field_name} entries must be JSON objects")
        normalized.append({str(key): item[key] for key in item})
    return tuple(normalized)


def resolve_mcp_policy(
    server: McpServerProfile,
    registry: ResourceRegistry,
) -> tuple[McpPolicyProfile | None, list[str]]:
    warnings: list[str] = []
    candidates: list[McpPolicyProfile] = []
    for document in registry.list_resources(kind="McpPolicy", namespace=server.namespace):
        profile = McpPolicyProfile.from_document(document)
        if profile.targets_server(server.name):
            candidates.append(profile)
    exact = [item for item in candidates if item.name == server.name]
    if len(exact) == 1:
        return exact[0], warnings
    if len(exact) > 1:
        warnings.append("multiple McpPolicy resources exactly matched this MCP; using the first merged policy")
        return exact[0], warnings
    if len(candidates) == 1:
        return candidates[0], warnings
    if len(candidates) > 1:
        warnings.append("multiple McpPolicy resources target this MCP; attach one explicit policy per server")
        return candidates[0], warnings
    warnings.append("no McpPolicy is attached; defaulting this MCP to quarantined trust")
    return None, warnings


def build_mcp_list_records(registry: ResourceRegistry, *, namespace: str = "default") -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for document in registry.list_resources(kind="McpServer", namespace=namespace):
        server = McpServerProfile.from_document(document)
        policy, warnings = resolve_mcp_policy(server, registry)
        report = build_mcp_test_report(server, policy, inherited_warnings=warnings)
        records.append(
            {
                "name": server.name,
                "namespace": server.namespace,
                "enabled": server.enabled,
                "transport": server.transport,
                "trustTier": report["trustTier"],
                "health": report["health"],
                "declaredTools": report["declaredTools"],
                "policyAttached": report["policy"]["attached"],
                "source": server.source,
            }
        )
    return records


def build_mcp_test_report(
    server: McpServerProfile,
    policy: McpPolicyProfile | None,
    *,
    inherited_warnings: list[str] | None = None,
    observed: bool = False,
    probe_seconds: float = 0.35,
) -> dict[str, Any]:
    warnings = list(inherited_warnings or [])
    startup = _build_startup_report(server)
    trust_tier = policy.trust_tier if policy is not None else "quarantined"
    secret_usage_mode = policy.secret_usage_mode if policy is not None else "brokered"
    declared_tools = list(server.declared_tools)
    if not declared_tools and server.capabilities:
        declared_tools = [f"capability:{item}" for item in server.capabilities]

    filesystem_access = _filesystem_access_requested(policy)
    network_destinations = _network_destinations_requested(server, policy)
    sanitization = {
        "input": bool(policy and policy.input_sanitization),
        "output": bool(policy and policy.output_sanitization),
        "trace": bool(policy and policy.trace_redaction),
    }
    egress_policy = dict(policy.egress_policy) if policy is not None else {"mode": "unspecified", "allow": []}
    sandbox_profile = dict(policy.sandbox_profile) if policy is not None else {}

    if not server.enabled:
        warnings.append("MCP is disabled and will not be started until explicitly enabled.")
    if trust_tier == "quarantined":
        warnings.append("quarantined MCPs should stay isolated until their behavior is reviewed.")
    elif trust_tier == "user-added":
        warnings.append("user-added MCPs should be reviewed before broader access is enabled.")
    if policy is None:
        warnings.append("attach an McpPolicy to declare trust tier, sandbox profile, egress policy, and sanitization.")
    if not declared_tools:
        warnings.append("declare tools or capabilities so AI clients can reason about the MCP surface safely.")
    if secret_usage_mode == "raw-secret":
        warnings.append("raw-secret mode is risky; prefer brokered or ephemeral-materialization handling.")
    if not sanitization["input"] or not sanitization["output"] or not sanitization["trace"]:
        warnings.append("configure input, output, and trace sanitization before relying on this MCP in governed flows.")
    if not sandbox_profile:
        warnings.append("sandbox profile is not defined; filesystem and process limits are unclear.")
    if egress_policy.get("mode") in {"open", "unspecified", "inherit"}:
        warnings.append("egress policy is not explicitly constrained; restrict destinations with an allowlist.")
    if server.transport in {"http", "https"} and network_destinations:
        allowed = {str(item).strip() for item in _string_list(egress_policy.get("allow"))}
        if egress_policy.get("mode") == "allowlist" and not set(network_destinations).issubset(allowed):
            warnings.append("configured MCP endpoint is not fully covered by the egress allowlist.")

    blocked_reasons: list[str] = []
    if not startup["success"]:
        blocked_reasons.append(startup["reason"])
    health = "blocked" if blocked_reasons else ("attention_needed" if warnings else "safe")

    recommendations = []
    if policy is None:
        recommendations.append(
            "Attach an McpPolicy with trust_tier, sandbox_profile, egress_policy, and sanitization before wider use."
        )
    if egress_policy.get("mode") in {"open", "unspecified", "inherit"}:
        recommendations.append("Restrict egress_policy to an explicit allowlist of expected destinations.")
    if secret_usage_mode != "brokered":
        recommendations.append("Prefer brokered secret handling unless a short-lived exception is required.")
    if not sanitization["input"] or not sanitization["output"] or not sanitization["trace"]:
        recommendations.append("Enable input_sanitization, output_sanitization, and trace_redaction for this MCP.")
    if startup["status"] == "missing_executable":
        recommendations.append("Install or correct the stdio command before enabling this MCP.")

    observed_report = {
        "mode": "not-run",
        "attempted": False,
        "startupSuccess": False,
        "status": "not-run",
        "reason": "observed runtime probing was not requested",
        "sandboxApplied": {},
        "observedNetworkDestinations": [],
        "observedFilesystemPaths": [],
        "egressViolations": [],
        "warnings": [],
    }
    if observed:
        runtime_report = observe_mcp_runtime(server, policy, probe_seconds=probe_seconds)
        observed_report = runtime_report.to_dict()
        warnings.extend(runtime_report.warnings)
        egress_enforcement = str(runtime_report.sandbox_applied.get("egressEnforcement", "observed-only") or "observed-only")
        if policy is None and egress_enforcement == "observed-only":
            warnings.append("no policy is attached and the runtime could not enforce stricter egress controls during observation.")
        if policy is not None and egress_policy.get("mode") in {"deny", "allowlist"} and egress_enforcement == "observed-only":
            warnings.append("runtime egress enforcement is partial here, so keep this MCP in a lower trust tier until the runner can fence it.")
        if runtime_report.egress_violations:
            warnings.extend(runtime_report.egress_violations)
            blocked_reasons.extend(runtime_report.egress_violations)
        if runtime_report.attempted and not runtime_report.startup_success:
            blocked_reasons.append(runtime_report.reason)
        health = "blocked" if blocked_reasons else ("attention_needed" if warnings else "safe")
        if runtime_report.mode == "process-probe":
            recommendations.append("Use observed MCP testing before widening trust for custom stdio servers.")

    return {
        "health": health,
        "server": server.to_dict(),
        "policy": {
            "attached": policy is not None,
            "name": "" if policy is None else policy.name,
            "source": "" if policy is None else policy.source,
        },
        "startup": startup,
        "declaredTools": declared_tools,
        "capabilities": list(server.capabilities),
        "networkDestinationsRequested": network_destinations,
        "filesystemAccessRequested": filesystem_access,
        "secretUsageMode": secret_usage_mode,
        "sanitizationPolicyApplied": sanitization,
        "trustTier": trust_tier,
        "sandboxProfile": sandbox_profile,
        "egressPolicy": egress_policy,
        "observed": observed_report,
        "warnings": warnings,
        "recommendations": recommendations,
    }


def _build_startup_report(server: McpServerProfile) -> dict[str, Any]:
    if not server.enabled:
        return {
            "success": False,
            "status": "disabled",
            "mode": "config-only",
            "reason": "MCP server is disabled",
            "executable": "",
        }
    if server.transport == "stdio":
        executable = shutil.which(server.command) or (
            str(Path(server.command)) if Path(server.command).exists() else ""
        )
        if not executable:
            return {
                "success": False,
                "status": "missing_executable",
                "mode": "config-only",
                "reason": f"stdio MCP command {server.command!r} is not available on PATH",
                "executable": "",
            }
        return {
            "success": True,
            "status": "ready",
            "mode": "config-only",
            "reason": "stdio MCP command resolved successfully",
            "executable": executable,
        }
    parsed = urlparse(server.url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return {
            "success": False,
            "status": "invalid_url",
            "mode": "config-only",
            "reason": f"MCP endpoint URL {server.url!r} is invalid",
            "executable": "",
        }
    return {
        "success": True,
        "status": "ready",
        "mode": "config-only",
        "reason": "HTTP MCP endpoint is syntactically valid",
        "executable": "",
    }


def add_mcp_resources(
    *,
    resource_dir: str | Path,
    name: str,
    namespace: str = "default",
    transport: str,
    command: str = "",
    args: tuple[str, ...] = (),
    url: str = "",
    declared_tools: tuple[str, ...] = (),
    capabilities: tuple[str, ...] = (),
    trust_tier: str = "quarantined",
    egress_mode: str = "deny",
    egress_allow: tuple[str, ...] = (),
    sandbox_read: tuple[str, ...] = (),
    sandbox_write: tuple[str, ...] = (),
    allow_tmp: bool = False,
    secret_usage_mode: str = "brokered",
    enabled: bool = True,
) -> dict[str, str]:
    if trust_tier not in _TRUST_TIERS:
        raise McpConfigurationError(f"unsupported MCP trust tier {trust_tier!r}")
    if secret_usage_mode not in _SECRET_USAGE_MODES:
        raise McpConfigurationError(f"unsupported MCP secret usage mode {secret_usage_mode!r}")
    if egress_mode not in _EGRESS_MODES - {"unspecified", "inherit"}:
        raise McpConfigurationError(f"unsupported MCP egress mode {egress_mode!r}")

    server_payload = {
        "apiVersion": "ccp.io/v1beta1",
        "kind": "McpServer",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "transport": transport,
            "enabled": enabled,
            "mode": "read",
            "capabilities": list(capabilities),
            "declared_tools": list(declared_tools),
        },
    }
    if transport == "stdio":
        if not command:
            raise McpConfigurationError("stdio MCPs require a command")
        server_payload["spec"]["command"] = command
        if args:
            server_payload["spec"]["args"] = list(args)
    elif transport in {"http", "https"}:
        if not url:
            raise McpConfigurationError("http/https MCPs require a url")
        server_payload["spec"]["url"] = url
    else:
        raise McpConfigurationError("MCP transport must be one of stdio, http, or https")

    default_allow = list(egress_allow)
    if not default_allow and url:
        parsed = urlparse(url)
        if parsed.netloc:
            default_allow = [parsed.netloc]
    policy_payload = {
        "apiVersion": "ccp.io/v1beta1",
        "kind": "McpPolicy",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "targets": [name],
            "trust_tier": trust_tier,
            "sandbox_profile": {
                "filesystem": {
                    "read": list(sandbox_read),
                    "write": list(sandbox_write),
                    "allowTmp": allow_tmp,
                }
            },
            "egress_policy": {
                "mode": egress_mode,
                "allow": default_allow,
            },
            "secret_usage_mode": secret_usage_mode,
            "input_sanitization": _normalize_sanitization_fields(("token", "authorization", "cookie", "secret")),
            "output_sanitization": _normalize_sanitization_fields(("token", "authorization", "cookie", "secret")),
            "trace_redaction": _normalize_sanitization_fields(("token", "authorization", "cookie", "secret")),
            "tool_rules": [{"tool": tool, "access": "read"} for tool in declared_tools],
        },
    }

    root = Path(resource_dir)
    root.mkdir(parents=True, exist_ok=True)
    server_path = root / f"{name}.server.json"
    policy_path = root / f"{name}.policy.json"
    if server_path.exists() or policy_path.exists():
        raise McpConfigurationError(f"MCP resources for {name!r} already exist in {root}")
    server_path.write_text(_dump_json(server_payload), encoding="utf-8")
    policy_path.write_text(_dump_json(policy_payload), encoding="utf-8")
    return {
        "serverPath": str(server_path),
        "policyPath": str(policy_path),
    }


def disable_mcp_server(document: ResourceDocument) -> str:
    server = McpServerProfile.from_document(document)
    source = Path(server.source)
    if not source.exists():
        raise McpConfigurationError(f"MCP server source file does not exist: {source}")
    payload = load_resource_file(source, layer="local").to_dict()
    payload.setdefault("spec", {})
    payload["spec"]["enabled"] = False
    source.write_text(_dump_json(payload), encoding="utf-8")
    return str(source)


def _dump_json(payload: Mapping[str, Any]) -> str:
    import json

    return json.dumps(payload, indent=2, sort_keys=True)


def _filesystem_access_requested(policy: McpPolicyProfile | None) -> dict[str, Any]:
    if policy is None:
        return {"read": [], "write": [], "allowTmp": False}
    filesystem = _mapping(policy.sandbox_profile.get("filesystem"), field_name="sandbox_profile.filesystem")
    return {
        "read": list(_string_list(filesystem.get("read"))),
        "write": list(_string_list(filesystem.get("write"))),
        "allowTmp": bool(filesystem.get("allowTmp", False)),
    }


def _network_destinations_requested(server: McpServerProfile, policy: McpPolicyProfile | None) -> list[str]:
    destinations: list[str] = []
    if server.transport in {"http", "https"} and server.url:
        parsed = urlparse(server.url)
        if parsed.netloc:
            destinations.append(parsed.netloc)
    if policy is not None:
        for item in _string_list(policy.egress_policy.get("allow")):
            if item not in destinations:
                destinations.append(item)
    return destinations
