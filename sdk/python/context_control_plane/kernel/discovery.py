from __future__ import annotations

from dataclasses import dataclass, field
from importlib import metadata as importlib_metadata
from typing import Any, Mapping

from .approvals import APPROVAL_API_VERSION
from .packs import PACK_API_VERSION
from .tracing import TRACE_API_VERSION
from .versioning import Capability, CompatibilityLevel, ContractVersion

CORE_PACKAGE_NAME = "ccp-core"
CORE_DEFAULT_API_VERSION = "ccp.io/v1beta1"
CORE_FALLBACK_VERSION = "0.1.0"


@dataclass(frozen=True)
class ResourceKindSchema:
    kind: str
    description: str
    required_fields: tuple[str, ...]
    spec_fields: tuple[str, ...]
    stability: CompatibilityLevel = CompatibilityLevel.BETA
    api_version: str = CORE_DEFAULT_API_VERSION
    notes: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "apiVersion": self.api_version,
            "stability": self.stability.value,
            "description": self.description,
        }

    def schema_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "apiVersion": self.api_version,
            "stability": self.stability.value,
            "description": self.description,
            "required_fields": list(self.required_fields),
            "spec_fields": list(self.spec_fields),
            "notes": list(self.notes),
        }


_CONTRACT_VERSIONS: tuple[ContractVersion, ...] = (
    ContractVersion(name="command-api", version="v1beta1", stability=CompatibilityLevel.BETA),
    ContractVersion(name="job-api", version="v1beta1", stability=CompatibilityLevel.BETA),
    ContractVersion(name="resource-registry-api", version="v1beta1", stability=CompatibilityLevel.BETA),
    ContractVersion(name="resource-schema-catalog", version="v1beta1", stability=CompatibilityLevel.BETA),
    ContractVersion(name="adapter-api", version="v1beta1", stability=CompatibilityLevel.BETA),
)

_CORE_CAPABILITIES: tuple[Capability, ...] = (
    Capability(
        name="command-api",
        version="v1beta1",
        stability=CompatibilityLevel.BETA,
        description="Stable command envelope for northbound callers.",
    ),
    Capability(
        name="job-api",
        version="v1beta1",
        stability=CompatibilityLevel.BETA,
        description="Async job handle and event contract for long-running work.",
    ),
    Capability(
        name="resource-schema-catalog",
        version="v1beta1",
        stability=CompatibilityLevel.BETA,
        description="Lists supported resource kinds and compact schema summaries.",
    ),
    Capability(
        name="pack-manifest",
        version="v1beta1",
        stability=CompatibilityLevel.BETA,
        description="Defines pack compatibility and activation metadata for installable bundles.",
    ),
    Capability(
        name="upgrade-plan",
        version="v1beta1",
        stability=CompatibilityLevel.BETA,
        description="Produces a reviewable upgrade plan before applying core or pack changes.",
    ),
    Capability(
        name="pack-health",
        version="v1beta1",
        stability=CompatibilityLevel.BETA,
        description="Reports pack activation status, validation findings, and doctor recommendations.",
    ),
    Capability(
        name="connection-safety",
        version="v1beta1",
        stability=CompatibilityLevel.BETA,
        description="Explains connection usage, secret handling, and single-step approval needs.",
    ),
    Capability(
        name="secret-backend",
        version="v1beta1",
        stability=CompatibilityLevel.BETA,
        description="Models durable secret backend selection without exposing raw secrets to AI callers.",
    ),
    Capability(
        name="secret-sanitization",
        version="v1beta1",
        stability=CompatibilityLevel.BETA,
        description="Applies response allowlists and secret detectors before results reach AI or traces.",
    ),
    Capability(
        name="secret-backend-health",
        version="v1beta1",
        stability=CompatibilityLevel.BETA,
        description="Reports secret backend readiness and durability without exposing raw credentials.",
    ),
    Capability(
        name="materialization-lifecycle",
        version="v1beta1",
        stability=CompatibilityLevel.BETA,
        description="Issues short-lived materialization leases for exceptional connection flows.",
    ),
    Capability(
        name="secret-binding-resolution",
        version="v1beta1",
        stability=CompatibilityLevel.BETA,
        description="Resolves secret_refs inside ccp-core so adapters receive capabilities instead of chat-visible secrets.",
    ),
    Capability(
        name="approval-receipt",
        version="v1beta1",
        stability=CompatibilityLevel.BETA,
        description="Issues and validates exact approval receipts for governed execution.",
    ),
    Capability(
        name="execution-plan",
        version="v1beta1",
        stability=CompatibilityLevel.BETA,
        description="Builds a governed execution plan without exposing raw secrets by default.",
    ),
    Capability(
        name="execution-run",
        version="v1beta1",
        stability=CompatibilityLevel.BETA,
        description="Runs one governed operation through a brokered adapter and returns sanitized output.",
    ),
    Capability(
        name="trace-record",
        version="v1beta1",
        stability=CompatibilityLevel.BETA,
        description="Captures sanitized execution traces for governed actions.",
    ),
    Capability(
        name="mcp-security-report",
        version="v1beta1",
        stability=CompatibilityLevel.BETA,
        description="Explains MCP trust tier, sandboxing, egress, secret usage, and safe test posture.",
    ),
    Capability(
        name="mcp-runtime-observation",
        version="v1beta1",
        stability=CompatibilityLevel.BETA,
        description="Runs observed MCP process probes with scrubbed environments and egress reporting.",
    ),
    Capability(
        name="mcp-runtime-enforcement",
        version="v1beta1",
        stability=CompatibilityLevel.BETA,
        description="Uses the strongest available local runner controls to fence MCP egress and filesystem writes during probes.",
    ),
    Capability(
        name="mcp-management",
        version="v1beta1",
        stability=CompatibilityLevel.BETA,
        description="Creates, disables, and inventories MCP resources through the CLI.",
    ),
    Capability(
        name="gateway-policy-evaluation",
        version="v1beta1",
        stability=CompatibilityLevel.BETA,
        description="Summarizes gateway policies and explains allow, deny, or approval-required decisions.",
    ),
    Capability(
        name="trace-inspection",
        version="v1beta1",
        stability=CompatibilityLevel.BETA,
        description="Lists, loads, and explains sanitized trace records for governed execution.",
    ),
    Capability(
        name="version-discovery",
        version="v1beta1",
        stability=CompatibilityLevel.BETA,
        description="Reports package and contract versions through a stable surface.",
    ),
)

_RESOURCE_KIND_SCHEMAS: dict[str, ResourceKindSchema] = {
    "ConnectionProfile": ResourceKindSchema(
        kind="ConnectionProfile",
        description="Reusable outbound connection profile backed by secret references.",
        required_fields=("apiVersion", "kind", "metadata.name", "spec"),
        spec_fields=(
            "adapter",
            "endpoint",
            "classification",
            "allowedAccess",
            "allowedModes",
            "defaultMode",
            "approval",
            "secretHandling",
            "secretBackendRef",
            "secretBackend",
            "materialization",
            "outputPolicy",
            "auth",
            "gatewayPolicyRef",
            "secret_refs",
            "timeouts",
        ),
        notes=("Prefer brokered execution over secret reveal.", "One approval layer should be enough."),
    ),
    "SecretBackend": ResourceKindSchema(
        kind="SecretBackend",
        description="Named secret backend with durability and provider metadata for connection usage.",
        required_fields=("apiVersion", "kind", "metadata.name", "spec"),
        spec_fields=("type", "durability", "provider", "managed", "config"),
        notes=(
            "Use durable local defaults before asking users to run Vault.",
            "Backend lifecycle can stay separate from the lightweight kernel.",
        ),
    ),
    "GatewayPolicy": ResourceKindSchema(
        kind="GatewayPolicy",
        description="Governed action policy for allow, deny, and approval-required decisions.",
        required_fields=("apiVersion", "kind", "metadata.name", "spec"),
        spec_fields=("defaults", "rules", "classifications"),
        notes=("Keep user-local overlays separate from shared policy packs.",),
    ),
    "McpPolicy": ResourceKindSchema(
        kind="McpPolicy",
        description="Input, output, approval, and trace rules for an MCP integration.",
        required_fields=("apiVersion", "kind", "metadata.name", "spec"),
        spec_fields=(
            "targets",
            "tool_rules",
            "trust_tier",
            "sandbox_profile",
            "egress_policy",
            "secret_usage_mode",
            "input_sanitization",
            "output_sanitization",
            "trace_redaction",
        ),
        notes=(
            "Policy config defines behavior; core must enforce it.",
            "Custom MCPs should be treated as untrusted until reviewed.",
        ),
    ),
    "McpServer": ResourceKindSchema(
        kind="McpServer",
        description="Managed MCP server definition for stdio, HTTP, or future transports.",
        required_fields=("apiVersion", "kind", "metadata.name", "spec"),
        spec_fields=("transport", "command", "args", "url", "mode", "enabled", "capabilities", "declared_tools"),
        notes=(
            "Custom MCPs should be first-class resources, not repo edits.",
            "Capability declaration should happen before broader AI access is allowed.",
        ),
    ),
    "ProviderProfile": ResourceKindSchema(
        kind="ProviderProfile",
        description="Named AI or runtime provider configuration with stable execution knobs.",
        required_fields=("apiVersion", "kind", "metadata.name", "spec"),
        spec_fields=("provider", "target", "model", "timeouts", "routing"),
        notes=("Provider profiles stay generic; vendor quirks belong in adapters.",),
    ),
    "PackActivation": ResourceKindSchema(
        kind="PackActivation",
        description="Enables or disables a named pack in a specific layer or namespace.",
        required_fields=("apiVersion", "kind", "metadata.name", "spec"),
        spec_fields=("pack", "state", "reason"),
        notes=("Activation should be layered and reversible.",),
    ),
    "TracePolicy": ResourceKindSchema(
        kind="TracePolicy",
        description="Trace capture and redaction policy for governed execution.",
        required_fields=("apiVersion", "kind", "metadata.name", "spec"),
        spec_fields=("sinks", "redaction", "retention", "sampling"),
        notes=("Trace should explain the decision without leaking secrets.",),
    ),
}

_MANIFEST_SCHEMAS: dict[str, ResourceKindSchema] = {
    "ApprovalReceipt": ResourceKindSchema(
        kind="ApprovalReceipt",
        api_version=APPROVAL_API_VERSION,
        description="Exact approval receipt for one governed action against one resource and operation.",
        required_fields=(
            "apiVersion",
            "kind",
            "metadata.name",
            "spec.subject.kind",
            "spec.subject.name",
            "spec.access",
            "spec.mode",
            "spec.operation",
            "spec.approvedBy",
            "spec.issuedAt",
            "spec.expiresAt",
            "spec.bindingDigest",
            "spec.issuer",
            "spec.signature",
        ),
        spec_fields=(
            "subject",
            "access",
            "mode",
            "operation",
            "approvedBy",
            "issuedAt",
            "expiresAt",
            "bindingDigest",
            "issuer",
            "signature",
            "reason",
        ),
        notes=("One receipt should map to one exact governed action and a signed connection binding.",),
    ),
    "TraceRecord": ResourceKindSchema(
        kind="TraceRecord",
        api_version=TRACE_API_VERSION,
        description="Sanitized execution trace for one governed action.",
        required_fields=("apiVersion", "kind", "metadata.name", "spec.executionId", "spec.status", "spec.events"),
        spec_fields=("executionId", "status", "operation", "connection", "events", "storedAt"),
        notes=("Trace should explain decisions without leaking secrets.",),
    ),
    "Pack": ResourceKindSchema(
        kind="Pack",
        api_version=PACK_API_VERSION,
        description="Installable pack manifest that declares compatibility, resources, and activation defaults.",
        required_fields=("apiVersion", "kind", "metadata.name", "metadata.version", "spec"),
        spec_fields=(
            "displayName",
            "description",
            "requiresCore",
            "requiresCapabilities",
            "dependsOn",
            "installsResources",
            "optionalResources",
            "migrations",
            "defaultActivation",
            "stability",
        ),
        notes=("Pack manifests should stay generic and avoid private repo assumptions.",),
    ),
}


def list_contract_versions() -> list[ContractVersion]:
    return list(_CONTRACT_VERSIONS)


def list_core_capabilities() -> list[Capability]:
    return list(_CORE_CAPABILITIES)


def list_resource_kind_schemas() -> list[ResourceKindSchema]:
    return [_RESOURCE_KIND_SCHEMAS[key] for key in sorted(_RESOURCE_KIND_SCHEMAS)]


def get_resource_kind_schema(kind: str) -> ResourceKindSchema | None:
    return _RESOURCE_KIND_SCHEMAS.get(str(kind or "").strip())


def list_schema_definitions() -> list[ResourceKindSchema]:
    catalog = dict(_RESOURCE_KIND_SCHEMAS)
    catalog.update(_MANIFEST_SCHEMAS)
    return [catalog[key] for key in sorted(catalog)]


def get_schema_definition(kind: str) -> ResourceKindSchema | None:
    name = str(kind or "").strip()
    return _RESOURCE_KIND_SCHEMAS.get(name) or _MANIFEST_SCHEMAS.get(name)


def resolve_package_version() -> str:
    try:
        return importlib_metadata.version(CORE_PACKAGE_NAME)
    except importlib_metadata.PackageNotFoundError:
        return CORE_FALLBACK_VERSION


def build_version_payload() -> Mapping[str, Any]:
    return {
        "package": {
            "name": CORE_PACKAGE_NAME,
            "version": resolve_package_version(),
        },
        "default_api_version": CORE_DEFAULT_API_VERSION,
        "contracts": [item.to_dict() for item in list_contract_versions()],
    }
