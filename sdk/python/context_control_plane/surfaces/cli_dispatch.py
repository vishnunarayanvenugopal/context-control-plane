from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable

from ..kernel import (
    ApprovalRef,
    CommandEnvelope,
    CommandStatus,
    GatewayConfigurationError,
    GatewayPolicyProfile,
    InMemoryResourceRegistry,
    McpConfigurationError,
    McpServerProfile,
    PackLoadError,
    ResourceLoadError,
    ResourceRef,
    SecretConfigurationError,
    TraceLoadError,
    add_mcp_resources,
    build_connection_execution_plan,
    build_doctor_report,
    build_gateway_status_records,
    build_mcp_list_records,
    build_mcp_test_report,
    build_pack_status,
    build_secret_backend_status_records,
    build_validation_report,
    build_version_payload,
    build_upgrade_plan,
    delete_secret_binding,
    disable_mcp_server,
    evaluate_gateway_policy,
    evaluate_connection_profile,
    explain_secret_backend,
    explain_trace_record,
    get_schema_definition,
    issue_approval_receipt,
    load_activation_documents,
    load_approval_receipt_file,
    load_pack_manifest_file,
    load_pack_manifests_from_dir,
    load_resource_file,
    load_resources_from_dir,
    load_trace_record_file,
    load_trace_records_from_dir,
    resolve_mcp_policy,
    inspect_secret_binding,
    run_governed_execution,
    save_approval_receipt_file,
    set_secret_value,
    summarize_trace_record,
)
from ..kernel.command_api import NextAction
from ..kernel.execution import build_connection_approval_binding
from ..kernel.versioning import Capability, CompatibilityLevel


def cli_capability() -> Capability:
    return Capability(
        name="cli-discovery",
        version="v1beta1",
        stability=CompatibilityLevel.BETA,
        description="Lists capabilities, resource kinds, schemas, and version data through the CLI.",
    )


def dedupe_capabilities(capabilities: Iterable[Capability]) -> list[Capability]:
    deduped: dict[str, Capability] = {}
    for capability in capabilities:
        deduped[capability.capability_id] = capability
    return [deduped[key] for key in sorted(deduped)]


def build_capabilities_payload(registry: InMemoryResourceRegistry, list_core_capabilities_fn) -> dict[str, object]:
    capabilities = dedupe_capabilities([*list_core_capabilities_fn(), *registry.list_capabilities(), cli_capability()])
    return {
        "capabilities": [item.to_dict() for item in capabilities],
    }


def build_resource_kinds_payload(list_resource_kind_schemas_fn) -> dict[str, object]:
    resource_kinds = [item.to_dict() for item in list_resource_kind_schemas_fn()]
    return {"resource_kinds": resource_kinds}


def load_generic_resource_registry(args: argparse.Namespace, active_registry: InMemoryResourceRegistry) -> InMemoryResourceRegistry:
    documents = []
    for path in getattr(args, "resource", []):
        documents.append(load_resource_file(path, layer="local"))
    for directory in getattr(args, "resource_dir", []):
        documents.extend(load_resources_from_dir(directory, layer="local"))
    if not documents:
        return active_registry
    return InMemoryResourceRegistry(documents)


def build_resource_list_payload(args: argparse.Namespace, active_registry: InMemoryResourceRegistry) -> CommandEnvelope:
    try:
        registry = load_generic_resource_registry(args, active_registry)
        documents = registry.list_resources(
            kind=str(getattr(args, "kind", "") or "").strip() or None,
            namespace=str(getattr(args, "namespace", "default") or "default").strip() or "default",
        )
    except (ResourceLoadError, ValueError) as exc:
        return CommandEnvelope(
            status=CommandStatus.ERROR,
            reason=str(exc),
            next_action=NextAction(
                command="ccp resource list --json",
                description="Re-run resource listing with valid resource files or directories.",
            ),
        )
    return CommandEnvelope(
        status=CommandStatus.OK,
        result={
            "resources": [document.to_dict() for document in documents],
            "summary": {"count": len(documents)},
        },
    )


def build_resource_get_payload(args: argparse.Namespace, active_registry: InMemoryResourceRegistry) -> CommandEnvelope:
    try:
        registry = load_generic_resource_registry(args, active_registry)
        document = registry.get_resource(kind=args.kind, name=args.name, namespace=args.namespace)
    except (ResourceLoadError, ValueError) as exc:
        return CommandEnvelope(
            status=CommandStatus.ERROR,
            reason=str(exc),
            next_action=NextAction(
                command="ccp resource get --kind <kind> --name <name> --json",
                description="Re-run resource lookup with valid registry inputs.",
            ),
        )
    if document is None:
        return CommandEnvelope(
            status=CommandStatus.ERROR,
            reason=f"resource {args.kind}/{args.namespace}/{args.name} was not found",
            next_action=NextAction(
                command="ccp resource list --json",
                description="List available resources and choose one of those names.",
            ),
        )
    return CommandEnvelope(
        status=CommandStatus.OK,
        resource_refs=(ResourceRef(kind=document.identifier.kind, name=document.identifier.name, namespace=document.identifier.namespace),),
        result={"resource": document.to_dict()},
    )


def build_resource_explain_payload(args: argparse.Namespace, active_registry: InMemoryResourceRegistry) -> CommandEnvelope:
    try:
        registry = load_generic_resource_registry(args, active_registry)
        explanation = registry.explain_resource(kind=args.kind, name=args.name, namespace=args.namespace)
    except (ResourceLoadError, ValueError) as exc:
        return CommandEnvelope(
            status=CommandStatus.ERROR,
            reason=str(exc),
            next_action=NextAction(
                command="ccp resource explain --kind <kind> --name <name> --json",
                description="Re-run resource explanation with valid registry inputs.",
            ),
        )
    if not explanation.get("found"):
        return CommandEnvelope(
            status=CommandStatus.ERROR,
            reason=f"resource {args.kind}/{args.namespace}/{args.name} was not found",
            next_action=NextAction(
                command="ccp resource list --json",
                description="List available resources and choose one of those names.",
            ),
        )
    return CommandEnvelope(
        status=CommandStatus.OK,
        resource_refs=(ResourceRef(kind=args.kind, name=args.name, namespace=args.namespace),),
        result=explanation,
    )


def build_schema_payload(kind: str) -> CommandEnvelope:
    schema = get_schema_definition(kind)
    if schema is None:
        return CommandEnvelope(
            status=CommandStatus.ERROR,
            reason=f"unknown resource kind {kind!r}",
            next_action=NextAction(
                command="ccp resource kinds --json",
                description="List supported resource kinds and choose one of those names.",
            ),
            result={"requested_kind": kind},
        )
    return CommandEnvelope(
        status=CommandStatus.OK,
        result={"schema": schema.schema_dict()},
    )


def build_upgrade_plan_payload(args: argparse.Namespace) -> CommandEnvelope:
    try:
        pack_manifests = tuple(load_pack_manifests(args))
    except (PackLoadError, ResourceLoadError, ValueError) as exc:
        return CommandEnvelope(
            status=CommandStatus.ERROR,
            reason=str(exc),
            next_action=NextAction(
                command="ccp upgrade plan --json",
                description="Re-run the upgrade plan with valid pack manifest paths.",
            ),
        )
    plan = build_upgrade_plan(target_version=args.target_version, pack_manifests=pack_manifests)
    return CommandEnvelope(status=CommandStatus.OK, result=plan.to_dict())


def load_pack_manifests(args: argparse.Namespace) -> list[object]:
    manifests = [load_pack_manifest_file(path) for path in getattr(args, "pack_manifest", [])]
    for directory in getattr(args, "pack_dir", []):
        manifests.extend(load_pack_manifests_from_dir(directory))
    return manifests


def load_activation_inputs(args: argparse.Namespace) -> list[object]:
    return load_activation_documents(
        resource_paths=getattr(args, "activation_resource", []),
        resource_dirs=getattr(args, "activation_dir", []),
    )


def issue_summary(issues: list[dict[str, object]] | tuple[object, ...]) -> dict[str, int]:
    issue_dicts = [
        item.to_dict() if hasattr(item, "to_dict") else dict(item)  # type: ignore[arg-type]
        for item in issues
    ]
    return {
        "errors": sum(1 for item in issue_dicts if item["level"] == "error"),
        "warnings": sum(1 for item in issue_dicts if item["level"] == "warning"),
    }


def status_from_summary(summary: dict[str, int]) -> CommandStatus:
    return CommandStatus.ERROR if summary.get("errors", 0) > 0 else CommandStatus.OK


def build_pack_status_payload(args: argparse.Namespace) -> CommandEnvelope:
    try:
        manifests = tuple(load_pack_manifests(args))
        activations = tuple(load_activation_inputs(args))
    except (PackLoadError, ResourceLoadError, ValueError) as exc:
        return CommandEnvelope(
            status=CommandStatus.ERROR,
            reason=str(exc),
            next_action=NextAction(
                command="ccp pack status --json",
                description="Re-run pack status with valid pack manifest and activation paths.",
            ),
        )

    pack_status, issues = build_pack_status(pack_manifests=manifests, activation_documents=activations)
    summary = {
        "packs": len(pack_status),
        "enabledPacks": sum(1 for item in pack_status if item.enabled),
        **issue_summary(list(issues)),
    }
    return CommandEnvelope(
        status=status_from_summary(summary),
        reason="" if summary["errors"] == 0 else f"pack status reported {summary['errors']} error(s)",
        result={
            "summary": summary,
            "pack_status": [item.to_dict() for item in pack_status],
            "issues": [item.to_dict() for item in issues],
        },
    )


def build_validate_payload(args: argparse.Namespace) -> CommandEnvelope:
    try:
        manifests = tuple(load_pack_manifests(args))
        activations = tuple(load_activation_inputs(args))
    except (PackLoadError, ResourceLoadError, ValueError) as exc:
        return CommandEnvelope(
            status=CommandStatus.ERROR,
            reason=str(exc),
            next_action=NextAction(
                command="ccp validate --json",
                description="Re-run validation with valid pack manifest and activation paths.",
            ),
        )

    report = build_validation_report(pack_manifests=manifests, activation_documents=activations)
    status = status_from_summary(dict(report.summary))
    return CommandEnvelope(
        status=status,
        reason="" if status is CommandStatus.OK else f"validation reported {report.summary['errors']} error(s)",
        result=report.to_dict(),
    )


def build_doctor_payload(args: argparse.Namespace) -> CommandEnvelope:
    try:
        manifests = tuple(load_pack_manifests(args))
        activations = tuple(load_activation_inputs(args))
    except (PackLoadError, ResourceLoadError, ValueError) as exc:
        return CommandEnvelope(
            status=CommandStatus.ERROR,
            reason=str(exc),
            next_action=NextAction(
                command="ccp doctor --json",
                description="Re-run doctor with valid pack manifest and activation paths.",
            ),
        )

    report = build_doctor_report(pack_manifests=manifests, activation_documents=activations)
    status = CommandStatus.ERROR if report.summary["errors"] > 0 else CommandStatus.OK
    return CommandEnvelope(
        status=status,
        reason="" if status is CommandStatus.OK else f"doctor found {report.summary['errors']} error(s)",
        result=report.to_dict(),
    )


def load_secret_registry(args: argparse.Namespace, active_registry: InMemoryResourceRegistry) -> InMemoryResourceRegistry:
    documents = []
    for path in getattr(args, "resource", []):
        document = load_resource_file(path, layer="local")
        if document.identifier.kind == "SecretBackend":
            documents.append(document)
    for directory in getattr(args, "resource_dir", []):
        for document in load_resources_from_dir(directory, layer="local"):
            if document.identifier.kind == "SecretBackend":
                documents.append(document)
    if not documents:
        return active_registry
    return InMemoryResourceRegistry(documents)


def build_secret_status_payload(args: argparse.Namespace, active_registry: InMemoryResourceRegistry) -> CommandEnvelope:
    try:
        registry = load_secret_registry(args, active_registry)
        records = build_secret_backend_status_records(registry, namespace=args.namespace)
    except (ResourceLoadError, SecretConfigurationError, ValueError) as exc:
        return CommandEnvelope(
            status=CommandStatus.ERROR,
            reason=str(exc),
            next_action=NextAction(
                command="ccp secret status --json",
                description="Re-run secret backend status with valid SecretBackend resources.",
            ),
        )
    if not records:
        return CommandEnvelope(
            status=CommandStatus.ERROR,
            reason="no SecretBackend resources were loaded",
            next_action=NextAction(
                command="ccp schema get SecretBackend --json",
                description="Create or load at least one SecretBackend resource before checking backend status.",
            ),
        )
    return CommandEnvelope(
        status=CommandStatus.OK,
        result={
            "summary": {
                "backends": len(records),
                "ok": sum(1 for item in records if item["health"] == "ok"),
                "attentionNeeded": sum(1 for item in records if item["health"] == "attention_needed"),
            },
            "backends": records,
        },
    )


def build_secret_explain_payload(args: argparse.Namespace, active_registry: InMemoryResourceRegistry) -> CommandEnvelope:
    try:
        registry = load_secret_registry(args, active_registry)
        requested_name = str(getattr(args, "name", "") or "").strip()
        if requested_name:
            result = explain_secret_backend(registry, name=requested_name, namespace=args.namespace)
            refs = (ResourceRef(kind="SecretBackend", name=requested_name, namespace=args.namespace),)
        else:
            records = registry.list_resources(kind="SecretBackend", namespace=args.namespace)
            if len(records) != 1:
                if not records:
                    raise SecretConfigurationError("no SecretBackend resources were loaded")
                available = ", ".join(item.identifier.name for item in records)
                return CommandEnvelope(
                    status=CommandStatus.ERROR,
                    reason="multiple SecretBackend resources were loaded; use --name to choose one",
                    next_action=NextAction(
                        command=f"ccp secret explain --name {records[0].identifier.name} --json",
                        description=f"Available secret backends: {available}",
                    ),
                )
            document = records[0]
            result = explain_secret_backend(registry, name=document.identifier.name, namespace=document.identifier.namespace)
            refs = (ResourceRef(kind="SecretBackend", name=document.identifier.name, namespace=document.identifier.namespace),)
    except (ResourceLoadError, SecretConfigurationError, ValueError) as exc:
        return CommandEnvelope(
            status=CommandStatus.ERROR,
            reason=str(exc),
            next_action=NextAction(
                command="ccp secret explain --resource <path> --json",
                description="Re-run secret backend explanation with valid SecretBackend resources.",
            ),
        )
    status = CommandStatus.OK if result["health"] == "ok" else CommandStatus.ERROR
    return CommandEnvelope(
        status=status,
        reason="" if status is CommandStatus.OK else result["reason"],
        resource_refs=refs,
        result=result,
    )


def _load_secret_value_input(args: argparse.Namespace) -> str:
    if str(getattr(args, "value", "") or "").strip():
        raise ValueError("direct --value is disabled; use --value-file or --value-stdin instead")
    value_file = str(getattr(args, "value_file", "") or "").strip()
    if value_file:
        return Path(value_file).read_text(encoding="utf-8").rstrip("\n")
    if bool(getattr(args, "value_stdin", False)):
        import sys

        return sys.stdin.read().rstrip("\n")
    raise ValueError("provide --value-file or --value-stdin for secret set")


def _secret_resource_ref(args: argparse.Namespace) -> tuple[ResourceRef, ...]:
    return (ResourceRef(kind="SecretBackend", name=args.backend, namespace=args.namespace),)


def build_secret_set_payload(args: argparse.Namespace, active_registry: InMemoryResourceRegistry) -> CommandEnvelope:
    try:
        registry = load_secret_registry(args, active_registry)
        value = _load_secret_value_input(args)
        result = set_secret_value(
            registry,
            backend_name=args.backend,
            secret_name=args.secret,
            value=value,
            namespace=args.namespace,
        )
    except (ResourceLoadError, SecretConfigurationError, ValueError, RuntimeError, OSError) as exc:
        return CommandEnvelope(
            status=CommandStatus.ERROR,
            reason=str(exc),
            next_action=NextAction(
                command="ccp secret set --backend <name> --secret <alias> --value-file <path> --json",
                description="Re-run secret set with a valid backend resource and input value source.",
            ),
            resource_refs=_secret_resource_ref(args),
        )
    return CommandEnvelope(
        status=CommandStatus.OK,
        resource_refs=_secret_resource_ref(args),
        result=result,
    )


def build_secret_inspect_payload(args: argparse.Namespace, active_registry: InMemoryResourceRegistry) -> CommandEnvelope:
    try:
        registry = load_secret_registry(args, active_registry)
        result = inspect_secret_binding(
            registry,
            backend_name=args.backend,
            secret_name=args.secret,
            namespace=args.namespace,
        )
    except (ResourceLoadError, SecretConfigurationError, ValueError, RuntimeError, OSError) as exc:
        return CommandEnvelope(
            status=CommandStatus.ERROR,
            reason=str(exc),
            next_action=NextAction(
                command="ccp secret inspect --backend <name> --secret <alias> --json",
                description="Re-run secret inspect with a valid backend resource and secret alias.",
            ),
            resource_refs=_secret_resource_ref(args),
        )
    return CommandEnvelope(
        status=CommandStatus.OK if result["exists"] else CommandStatus.ERROR,
        reason="" if result["exists"] else result["reason"],
        resource_refs=_secret_resource_ref(args),
        result=result,
    )


def build_secret_delete_payload(args: argparse.Namespace, active_registry: InMemoryResourceRegistry) -> CommandEnvelope:
    try:
        registry = load_secret_registry(args, active_registry)
        result = delete_secret_binding(
            registry,
            backend_name=args.backend,
            secret_name=args.secret,
            namespace=args.namespace,
        )
    except (ResourceLoadError, SecretConfigurationError, ValueError, RuntimeError, OSError) as exc:
        return CommandEnvelope(
            status=CommandStatus.ERROR,
            reason=str(exc),
            next_action=NextAction(
                command="ccp secret delete --backend <name> --secret <alias> --json",
                description="Re-run secret delete with a valid backend resource and secret alias.",
            ),
            resource_refs=_secret_resource_ref(args),
        )
    return CommandEnvelope(
        status=CommandStatus.OK,
        resource_refs=_secret_resource_ref(args),
        result=result,
    )


def _resolve_trace_path(args: argparse.Namespace) -> Path:
    trace_path = str(getattr(args, "trace", "") or "").strip()
    if trace_path:
        return Path(trace_path)
    trace_id = str(getattr(args, "id", "") or "").strip()
    trace_dir = str(getattr(args, "trace_dir", "") or "").strip()
    if trace_id and trace_dir:
        return Path(trace_dir) / f"{trace_id}.json"
    raise TraceLoadError("provide --trace <path> or both --trace-dir <dir> and --id <trace-id>")


def build_trace_list_payload(args: argparse.Namespace) -> CommandEnvelope:
    trace_dir = str(getattr(args, "trace_dir", "") or "").strip()
    if not trace_dir:
        return CommandEnvelope(
            status=CommandStatus.ERROR,
            reason="trace list requires --trace-dir",
            next_action=NextAction(
                command="ccp trace list --trace-dir <dir> --json",
                description="Point the command at a directory containing TraceRecord JSON files.",
            ),
        )
    try:
        records = load_trace_records_from_dir(trace_dir)
    except TraceLoadError as exc:
        return CommandEnvelope(
            status=CommandStatus.ERROR,
            reason=str(exc),
            next_action=NextAction(
                command="ccp trace list --trace-dir <dir> --json",
                description="Re-run trace listing with a valid trace directory.",
            ),
        )

    summaries = [summarize_trace_record(item) for item in records]
    return CommandEnvelope(
        status=CommandStatus.OK,
        result={
            "summary": {
                "traces": len(summaries),
                "ok": sum(1 for item in summaries if item["status"] == "ok"),
                "nonOk": sum(1 for item in summaries if item["status"] != "ok"),
            },
            "traces": summaries,
        },
    )


def build_trace_get_payload(args: argparse.Namespace) -> CommandEnvelope:
    try:
        trace = load_trace_record_file(_resolve_trace_path(args))
    except TraceLoadError as exc:
        return CommandEnvelope(
            status=CommandStatus.ERROR,
            reason=str(exc),
            next_action=NextAction(
                command="ccp trace get --trace <path> --json",
                description="Provide a valid TraceRecord file or a trace id plus trace directory.",
            ),
        )
    return CommandEnvelope(
        status=CommandStatus.OK,
        trace_id=trace.trace_id,
        resource_refs=(ResourceRef(kind="TraceRecord", name=trace.trace_id, namespace=trace.namespace),),
        result={"trace": trace.to_dict()},
    )


def build_trace_explain_payload(args: argparse.Namespace) -> CommandEnvelope:
    try:
        trace = load_trace_record_file(_resolve_trace_path(args))
    except TraceLoadError as exc:
        return CommandEnvelope(
            status=CommandStatus.ERROR,
            reason=str(exc),
            next_action=NextAction(
                command="ccp trace explain --trace <path> --json",
                description="Provide a valid TraceRecord file or a trace id plus trace directory.",
            ),
        )
    return CommandEnvelope(
        status=CommandStatus.OK,
        trace_id=trace.trace_id,
        resource_refs=(ResourceRef(kind="TraceRecord", name=trace.trace_id, namespace=trace.namespace),),
        result=explain_trace_record(trace),
    )


def load_gateway_registry(args: argparse.Namespace, active_registry: InMemoryResourceRegistry) -> InMemoryResourceRegistry:
    documents = []
    for path in getattr(args, "resource", []):
        document = load_resource_file(path, layer="local")
        if document.identifier.kind == "GatewayPolicy":
            documents.append(document)
    for directory in getattr(args, "resource_dir", []):
        for document in load_resources_from_dir(directory, layer="local"):
            if document.identifier.kind == "GatewayPolicy":
                documents.append(document)
    if not documents:
        return active_registry
    return InMemoryResourceRegistry(documents)


def resolve_gateway_policy_document(
    args: argparse.Namespace,
    registry: InMemoryResourceRegistry,
) -> tuple[object | None, CommandEnvelope | None]:
    namespace = str(getattr(args, "namespace", "default") or "default").strip() or "default"
    requested_name = str(getattr(args, "name", "") or "").strip()
    if requested_name:
        document = registry.get_resource(kind="GatewayPolicy", name=requested_name, namespace=namespace)
        if document is None:
            return None, CommandEnvelope(
                status=CommandStatus.ERROR,
                reason=f"GatewayPolicy {requested_name!r} was not found in namespace {namespace!r}",
                next_action=NextAction(
                    command="ccp schema get GatewayPolicy --json",
                    description="Load a valid GatewayPolicy resource and re-run the command with --name when needed.",
                ),
            )
        return document, None

    policies = registry.list_resources(kind="GatewayPolicy", namespace=namespace)
    if len(policies) == 1:
        return policies[0], None
    if not policies:
        return None, CommandEnvelope(
            status=CommandStatus.ERROR,
            reason="no GatewayPolicy resources were loaded",
            next_action=NextAction(
                command="ccp gateway status --resource <path> --json",
                description="Provide one or more GatewayPolicy resources to inspect.",
            ),
        )
    available = ", ".join(item.identifier.name for item in policies)
    return None, CommandEnvelope(
        status=CommandStatus.ERROR,
        reason="multiple GatewayPolicy resources were loaded; use --name to choose one",
        next_action=NextAction(
            command=f"ccp gateway explain --name {policies[0].identifier.name} --json",
            description=f"Available gateway policies: {available}",
        ),
    )


def build_gateway_status_payload(args: argparse.Namespace, active_registry: InMemoryResourceRegistry) -> CommandEnvelope:
    try:
        registry = load_gateway_registry(args, active_registry)
        records = build_gateway_status_records(registry, namespace=args.namespace)
    except (ResourceLoadError, GatewayConfigurationError, ValueError) as exc:
        return CommandEnvelope(
            status=CommandStatus.ERROR,
            reason=str(exc),
            next_action=NextAction(
                command="ccp gateway status --json",
                description="Re-run gateway status with valid GatewayPolicy resources.",
            ),
        )
    if not records:
        return CommandEnvelope(
            status=CommandStatus.ERROR,
            reason="no GatewayPolicy resources were loaded",
            next_action=NextAction(
                command="ccp schema get GatewayPolicy --json",
                description="Create or load at least one GatewayPolicy before checking gateway status.",
            ),
        )
    return CommandEnvelope(
        status=CommandStatus.OK,
        result={
            "summary": {
                "policies": len(records),
                "approvalDefaults": sum(1 for item in records if item["defaultDecision"] == "approval_required"),
                "denyDefaults": sum(1 for item in records if item["defaultDecision"] == "deny"),
            },
            "policies": records,
        },
    )


def build_gateway_explain_payload(args: argparse.Namespace, active_registry: InMemoryResourceRegistry) -> CommandEnvelope:
    try:
        registry = load_gateway_registry(args, active_registry)
        document, error = resolve_gateway_policy_document(args, registry)
        if error is not None:
            return error
        assert document is not None
        profile = GatewayPolicyProfile.from_document(document)
        decision = evaluate_gateway_policy(
            profile,
            access=args.access,
            classification=args.classification,
            mode=args.mode,
            operation=args.operation,
        )
    except (ResourceLoadError, GatewayConfigurationError, ValueError) as exc:
        return CommandEnvelope(
            status=CommandStatus.ERROR,
            reason=str(exc),
            next_action=NextAction(
                command="ccp gateway explain --json",
                description="Re-run gateway explanation with valid GatewayPolicy resources and request parameters.",
            ),
        )
    status_map = {
        "allow": CommandStatus.OK,
        "deny": CommandStatus.DENIED,
        "approval_required": CommandStatus.APPROVAL_REQUIRED,
    }
    status = status_map[decision.decision]
    next_action = None
    approval = None
    if status is CommandStatus.APPROVAL_REQUIRED:
        approval = ApprovalRef(mode="explicit")
        next_action = NextAction(
            command="issue one explicit approval receipt for this governed action before execution",
            description="One explicit approval should be enough for the exact governed action.",
        )
    return CommandEnvelope(
        status=status,
        reason="" if status is CommandStatus.OK else decision.reason,
        next_action=next_action,
        approval=approval,
        resource_refs=(ResourceRef(kind="GatewayPolicy", name=profile.name, namespace=profile.namespace),),
        result=decision.to_dict(),
    )


def load_mcp_registry(args: argparse.Namespace, active_registry: InMemoryResourceRegistry) -> InMemoryResourceRegistry:
    documents = []
    for path in getattr(args, "resource", []):
        document = load_resource_file(path, layer="local")
        if document.identifier.kind in {"McpServer", "McpPolicy"}:
            documents.append(document)
    for directory in getattr(args, "resource_dir", []):
        for document in load_resources_from_dir(directory, layer="local"):
            if document.identifier.kind in {"McpServer", "McpPolicy"}:
                documents.append(document)
    if not documents:
        return active_registry
    return InMemoryResourceRegistry(documents)


def resolve_mcp_server_document(
    args: argparse.Namespace,
    registry: InMemoryResourceRegistry,
) -> tuple[object | None, CommandEnvelope | None]:
    namespace = str(getattr(args, "namespace", "default") or "default").strip() or "default"
    requested_name = str(getattr(args, "name", "") or "").strip()
    if requested_name:
        document = registry.get_resource(kind="McpServer", name=requested_name, namespace=namespace)
        if document is None:
            return None, CommandEnvelope(
                status=CommandStatus.ERROR,
                reason=f"McpServer {requested_name!r} was not found in namespace {namespace!r}",
                next_action=NextAction(
                    command="ccp schema get McpServer --json",
                    description="Load a valid McpServer resource and re-run the command with --name when needed.",
                ),
            )
        return document, None

    servers = registry.list_resources(kind="McpServer", namespace=namespace)
    if len(servers) == 1:
        return servers[0], None
    if not servers:
        return None, CommandEnvelope(
            status=CommandStatus.ERROR,
            reason="no McpServer resources were loaded",
            next_action=NextAction(
                command="ccp mcp list --resource <path> --json",
                description="Provide McpServer and McpPolicy resources to inspect.",
            ),
        )
    available = ", ".join(item.identifier.name for item in servers)
    return None, CommandEnvelope(
        status=CommandStatus.ERROR,
        reason="multiple McpServer resources were loaded; use --name to choose one",
        next_action=NextAction(
            command=f"ccp mcp test --name {servers[0].identifier.name} --json",
            description=f"Available MCP servers: {available}",
        ),
    )


def mcp_resource_refs(server_document: object, policy_document: object | None = None) -> tuple[ResourceRef, ...]:
    refs = [
        ResourceRef(
            kind=server_document.identifier.kind,
            name=server_document.identifier.name,
            namespace=server_document.identifier.namespace,
        )
    ]
    if policy_document is not None:
        refs.append(
            ResourceRef(
                kind=policy_document.identifier.kind,
                name=policy_document.identifier.name,
                namespace=policy_document.identifier.namespace,
            )
        )
    return tuple(refs)


def build_mcp_list_payload(args: argparse.Namespace, active_registry: InMemoryResourceRegistry) -> CommandEnvelope:
    try:
        registry = load_mcp_registry(args, active_registry)
        records = build_mcp_list_records(registry, namespace=args.namespace)
    except (ResourceLoadError, McpConfigurationError, ValueError) as exc:
        return CommandEnvelope(
            status=CommandStatus.ERROR,
            reason=str(exc),
            next_action=NextAction(
                command="ccp mcp list --json",
                description="Re-run MCP listing with valid McpServer and McpPolicy resources.",
            ),
        )

    if not records:
        return CommandEnvelope(
            status=CommandStatus.ERROR,
            reason="no McpServer resources were loaded",
            next_action=NextAction(
                command="ccp schema get McpServer --json",
                description="Create or load at least one McpServer resource before listing MCP state.",
            ),
        )

    summary = {
        "servers": len(records),
        "enabled": sum(1 for item in records if item["enabled"]),
        "safe": sum(1 for item in records if item["health"] == "safe"),
        "attentionNeeded": sum(1 for item in records if item["health"] == "attention_needed"),
        "blocked": sum(1 for item in records if item["health"] == "blocked"),
    }
    return CommandEnvelope(
        status=CommandStatus.OK,
        result={
            "summary": summary,
            "servers": records,
        },
    )


def build_mcp_test_payload(args: argparse.Namespace, active_registry: InMemoryResourceRegistry) -> CommandEnvelope:
    try:
        registry = load_mcp_registry(args, active_registry)
        server_document, error = resolve_mcp_server_document(args, registry)
        if error is not None:
            return error
        assert server_document is not None
        server_profile = McpServerProfile.from_document(server_document)
        policy, inherited_warnings = resolve_mcp_policy(server_profile, registry)
        report = build_mcp_test_report(
            server_profile,
            policy,
            inherited_warnings=inherited_warnings,
            observed=bool(getattr(args, "observed", False)),
            probe_seconds=float(getattr(args, "probe_seconds", 0.35) or 0.35),
        )
    except (ResourceLoadError, McpConfigurationError, ValueError) as exc:
        return CommandEnvelope(
            status=CommandStatus.ERROR,
            reason=str(exc),
            next_action=NextAction(
                command="ccp mcp test --json",
                description="Re-run MCP testing with valid McpServer and McpPolicy resources.",
            ),
        )

    policy_document = None
    if policy is not None:
        policy_document = registry.get_resource(kind="McpPolicy", name=policy.name, namespace=policy.namespace)

    next_action = None
    if report["health"] != "safe":
        next_action = NextAction(
            command="ccp schema get McpPolicy --json",
            description="Review the MCP policy contract and tighten trust tier, sandboxing, egress, and sanitization.",
        )
    status = CommandStatus.OK if report["health"] == "safe" else CommandStatus.ERROR
    reason = ""
    if report["health"] == "attention_needed":
        reason = "MCP configuration needs review before it should be treated as safe"
    elif report["health"] == "blocked":
        reason = "MCP configuration is blocked until the startup or policy issues are fixed"
    return CommandEnvelope(
        status=status,
        reason=reason,
        next_action=next_action,
        resource_refs=mcp_resource_refs(server_document, policy_document),
        result=report,
    )


def build_mcp_add_payload(args: argparse.Namespace) -> CommandEnvelope:
    try:
        created = add_mcp_resources(
            resource_dir=args.resource_dir,
            name=args.name,
            namespace=args.namespace,
            transport=args.transport,
            command=args.startup_command,
            args=tuple(args.arg),
            url=args.url,
            declared_tools=tuple(args.declared_tool),
            capabilities=tuple(args.capability),
            trust_tier=args.trust_tier,
            egress_mode=args.egress_mode,
            egress_allow=tuple(args.egress_allow),
            sandbox_read=tuple(args.sandbox_read),
            sandbox_write=tuple(args.sandbox_write),
            allow_tmp=bool(args.allow_tmp),
            secret_usage_mode=args.secret_usage_mode,
            enabled=not bool(args.disabled),
        )
    except (McpConfigurationError, ValueError) as exc:
        return CommandEnvelope(
            status=CommandStatus.ERROR,
            reason=str(exc),
            next_action=NextAction(
                command="ccp mcp add --resource-dir <dir> --name <name> --transport stdio --command <cmd> --json",
                description="Re-run MCP creation with a valid transport, target path, and safe MCP settings.",
            ),
        )
    return CommandEnvelope(
        status=CommandStatus.OK,
        resource_refs=(
            ResourceRef(kind="McpServer", name=args.name, namespace=args.namespace),
            ResourceRef(kind="McpPolicy", name=args.name, namespace=args.namespace),
        ),
        result=created,
    )


def build_mcp_disable_payload(args: argparse.Namespace, active_registry: InMemoryResourceRegistry) -> CommandEnvelope:
    try:
        registry = load_mcp_registry(args, active_registry)
        server_document, error = resolve_mcp_server_document(args, registry)
        if error is not None:
            return error
        assert server_document is not None
        updated_path = disable_mcp_server(server_document)
    except (ResourceLoadError, McpConfigurationError, ValueError) as exc:
        return CommandEnvelope(
            status=CommandStatus.ERROR,
            reason=str(exc),
            next_action=NextAction(
                command="ccp mcp disable --name <name> --resource-dir <dir> --json",
                description="Re-run MCP disable with a valid McpServer resource source.",
            ),
        )
    return CommandEnvelope(
        status=CommandStatus.OK,
        resource_refs=mcp_resource_refs(server_document),
        result={"updated": updated_path, "enabled": False},
    )


def load_connection_registry(args: argparse.Namespace, active_registry: InMemoryResourceRegistry) -> InMemoryResourceRegistry:
    documents = []
    for path in getattr(args, "resource", []):
        document = load_resource_file(path, layer="local")
        if document.identifier.kind in {"ConnectionProfile", "SecretBackend", "GatewayPolicy"}:
            documents.append(document)
    for directory in getattr(args, "resource_dir", []):
        for document in load_resources_from_dir(directory, layer="local"):
            if document.identifier.kind in {"ConnectionProfile", "SecretBackend", "GatewayPolicy"}:
                documents.append(document)
    if not documents:
        return active_registry
    return InMemoryResourceRegistry(documents)


def resolve_connection_document(
    args: argparse.Namespace,
    registry: InMemoryResourceRegistry,
) -> tuple[object | None, CommandEnvelope | None]:
    namespace = str(getattr(args, "namespace", "default") or "default").strip() or "default"
    requested_name = str(getattr(args, "name", "") or "").strip()
    if requested_name:
        document = registry.get_resource(kind="ConnectionProfile", name=requested_name, namespace=namespace)
        if document is None:
            return None, CommandEnvelope(
                status=CommandStatus.ERROR,
                reason=f"ConnectionProfile {requested_name!r} was not found in namespace {namespace!r}",
                next_action=NextAction(
                    command="ccp resource kinds --json",
                    description="Load a valid ConnectionProfile resource and re-run the command with --name when needed.",
                ),
            )
        return document, None

    connections = registry.list_resources(kind="ConnectionProfile", namespace=namespace)
    if len(connections) == 1:
        return connections[0], None
    if not connections:
        return None, CommandEnvelope(
            status=CommandStatus.ERROR,
            reason="no ConnectionProfile resources were loaded",
            next_action=NextAction(
                command="ccp connection explain --resource <path> --json",
                description="Provide a ConnectionProfile resource file or directory to inspect.",
            ),
        )
    available = ", ".join(item.identifier.name for item in connections)
    return None, CommandEnvelope(
        status=CommandStatus.ERROR,
        reason="multiple ConnectionProfile resources were loaded; use --name to choose one",
        next_action=NextAction(
            command=f"ccp connection explain --name {connections[0].identifier.name} --json",
            description=f"Available connection profiles: {available}",
        ),
    )


def resolve_connection_decision(
    args: argparse.Namespace,
    active_registry: InMemoryResourceRegistry,
) -> tuple[object | None, object | None, CommandEnvelope | None]:
    try:
        registry = load_connection_registry(args, active_registry)
        document, error = resolve_connection_document(args, registry)
        if error is not None:
            return None, None, error
        assert document is not None
        decision = evaluate_connection_profile(
            document,
            requested_access=args.access,
            requested_mode=args.mode,
            requested_operation=str(getattr(args, "operation", "") or "").strip(),
            registry=registry,
        )
    except (ValueError, ResourceLoadError) as exc:
        return None, None, CommandEnvelope(
            status=CommandStatus.ERROR,
            reason=str(exc),
            next_action=NextAction(
                command="ccp connection explain --json",
                description="Re-run the connection explanation with valid resources and request parameters.",
            ),
        )
    return document, decision, None


def connection_resource_ref(document: object) -> tuple[ResourceRef, ...]:
    return (
        ResourceRef(
            kind=document.identifier.kind,
            name=document.identifier.name,
            namespace=document.identifier.namespace,
        ),
    )


def connection_denied_envelope(document: object, decision: object) -> CommandEnvelope:
    next_action = None
    if decision.requested_mode.value == "reveal":
        name_flag = f" --name {document.identifier.name}" if document.identifier.name else ""
        next_action = NextAction(
            command=f"ccp connection explain{name_flag} --access {decision.requested_access.value} --mode connect --json",
            description="Use brokered connect mode instead of raw secret reveal when possible.",
        )
    return CommandEnvelope(
        status=CommandStatus.DENIED,
        reason=decision.reason,
        next_action=next_action,
        resource_refs=connection_resource_ref(document),
        result=decision.to_dict(),
    )


def build_connection_payload(args: argparse.Namespace, active_registry: InMemoryResourceRegistry) -> CommandEnvelope:
    document, decision, error = resolve_connection_decision(args, active_registry)
    if error is not None:
        return error
    assert document is not None
    assert decision is not None

    if not decision.allowed:
        return connection_denied_envelope(document, decision)

    status = CommandStatus.APPROVAL_REQUIRED if decision.approval_required else CommandStatus.OK
    next_action = None
    approval = None
    if status is CommandStatus.APPROVAL_REQUIRED:
        approval = ApprovalRef(mode="explicit")
        next_action = NextAction(
            command="issue one exact approval receipt for this connection action before governed execution",
            description="One explicit approval receipt should cover this exact connection usage.",
        )
    return CommandEnvelope(
        status=status,
        reason="" if status is CommandStatus.OK else decision.reason,
        next_action=next_action,
        approval=approval,
        resource_refs=connection_resource_ref(document),
        result=decision.to_dict(),
    )


def build_approval_issue_payload(args: argparse.Namespace, active_registry: InMemoryResourceRegistry) -> CommandEnvelope:
    document, decision, error = resolve_connection_decision(args, active_registry)
    if error is not None:
        return error
    assert document is not None
    assert decision is not None

    if not decision.allowed:
        return connection_denied_envelope(document, decision)
    if not decision.approval_required:
        return CommandEnvelope(
            status=CommandStatus.ERROR,
            reason="approval is not required for this exact connection usage",
            next_action=NextAction(
                command="ccp connection explain --json",
                description="Inspect the connection policy first and only issue receipts for approval-required actions.",
            ),
            resource_refs=connection_resource_ref(document),
        )

    try:
        receipt = issue_approval_receipt(
            subject_kind=document.identifier.kind,
            subject_name=document.identifier.name,
            namespace=document.identifier.namespace,
            access=decision.requested_access.value,
            mode=decision.requested_mode.value,
            operation=args.operation,
            approved_by=args.approved_by,
            reason=args.reason,
            ttl_minutes=args.ttl_minutes,
            binding=build_connection_approval_binding(
                decision=decision,
                operation=args.operation,
                connection_document=document,
            ),
        )
        saved_path = ""
        if args.output:
            saved_path = save_approval_receipt_file(receipt, args.output)
    except ValueError as exc:
        description = "Re-run approval issuance with valid parameters."
        if "approval signing key" in str(exc):
            description = (
                "Configure CCP_APPROVAL_SIGNING_KEY, CCP_APPROVAL_SIGNING_KEY_FILE, or "
                "CCP_APPROVAL_SIGNING_KEY_PATH, then re-run approval issuance."
            )
        return CommandEnvelope(
            status=CommandStatus.ERROR,
            reason=str(exc),
            next_action=NextAction(
                command="ccp approval issue --json",
                description=description,
            ),
            resource_refs=connection_resource_ref(document),
        )

    return CommandEnvelope(
        status=CommandStatus.OK,
        resource_refs=(
            *connection_resource_ref(document),
            ResourceRef(kind="ApprovalReceipt", name=receipt.approval_id, namespace=receipt.namespace),
        ),
        result={
            "receipt": receipt.to_dict(),
            "savedTo": saved_path,
        },
    )


def build_approval_inspect_payload(args: argparse.Namespace) -> CommandEnvelope:
    try:
        receipt = load_approval_receipt_file(args.receipt)
    except ValueError as exc:
        return CommandEnvelope(
            status=CommandStatus.ERROR,
            reason=str(exc),
            next_action=NextAction(
                command="ccp approval inspect --receipt <path> --json",
                description="Provide a valid approval receipt JSON file.",
            ),
        )
    return CommandEnvelope(
        status=CommandStatus.OK,
        resource_refs=(ResourceRef(kind="ApprovalReceipt", name=receipt.approval_id, namespace=receipt.namespace),),
        result={"receipt": receipt.to_dict()},
    )


def resolve_execution_planning(
    args: argparse.Namespace,
    active_registry: InMemoryResourceRegistry,
    *,
    command_name: str,
) -> tuple[object | None, object | None, CommandEnvelope | None]:
    document, decision, error = resolve_connection_decision(args, active_registry)
    if error is not None:
        return None, None, error
    assert document is not None
    assert decision is not None

    receipt = None
    if getattr(args, "approval_receipt", ""):
        try:
            receipt = load_approval_receipt_file(args.approval_receipt)
        except ValueError as exc:
            return document, None, CommandEnvelope(
                status=CommandStatus.ERROR,
                reason=str(exc),
                next_action=NextAction(
                    command=f"{command_name} --approval-receipt <path> --json",
                    description="Provide a valid approval receipt file or omit it.",
                ),
                resource_refs=connection_resource_ref(document),
            )

    try:
        planning = build_connection_execution_plan(
            decision,
            operation=args.operation,
            approval_receipt=receipt,
            connection_document=document,
        )
    except ValueError as exc:
        return document, None, CommandEnvelope(
            status=CommandStatus.ERROR,
            reason=str(exc),
            next_action=NextAction(
                command=f"{command_name} --operation <text> --json",
                description="Provide the exact governed operation.",
            ),
            resource_refs=connection_resource_ref(document),
        )

    return document, planning, None


def build_exec_plan_payload(args: argparse.Namespace, active_registry: InMemoryResourceRegistry) -> CommandEnvelope:
    document, planning, error = resolve_execution_planning(args, active_registry, command_name="ccp exec plan")
    if error is not None:
        return error
    assert document is not None
    assert planning is not None

    next_action = None
    approval = None
    if planning.status is CommandStatus.APPROVAL_REQUIRED:
        approval = ApprovalRef(mode="explicit")
        operation_arg = json.dumps(args.operation)
        access = planning.connection.requested_access.value
        mode = planning.connection.requested_mode.value
        next_action = NextAction(
            command=(
                "ccp approval issue"
                f" --operation {operation_arg}"
                f" --approved-by <approver>"
                f" --access {access}"
                f" --mode {mode}"
                " --json"
            ),
            description="Issue one exact approval receipt, then re-run exec plan with --approval-receipt.",
        )

    return CommandEnvelope(
        status=planning.status,
        reason="" if planning.status is CommandStatus.OK else planning.reason,
        next_action=next_action,
        approval=approval,
        resource_refs=connection_resource_ref(document),
        result=planning.to_dict(),
    )


def load_exec_params(args: argparse.Namespace) -> dict[str, object]:
    raw = str(getattr(args, "params", "{}") or "{}").strip() or "{}"
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"exec params must be valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("exec params must decode to a JSON object")
    return payload


def build_exec_run_payload(args: argparse.Namespace, active_registry: InMemoryResourceRegistry) -> CommandEnvelope:
    document, planning, error = resolve_execution_planning(args, active_registry, command_name="ccp exec run")
    if error is not None:
        return error
    assert document is not None
    assert planning is not None
    if planning.status is not CommandStatus.OK:
        return build_exec_plan_payload(args, active_registry)

    try:
        params = load_exec_params(args)
    except ValueError as exc:
        return CommandEnvelope(
            status=CommandStatus.ERROR,
            reason=str(exc),
            next_action=NextAction(
                command="ccp exec run --params '{\"key\":\"value\"}' --json",
                description="Provide adapter params as a JSON object.",
            ),
            resource_refs=connection_resource_ref(document),
        )

    result = run_governed_execution(
        planning,
        params=params,
        trace_dir=args.trace_dir,
    )
    return CommandEnvelope(
        status=result.status,
        reason="" if result.status is CommandStatus.OK else result.reason,
        trace_id="" if result.trace is None else result.trace.trace_id,
        resource_refs=(
            *connection_resource_ref(document),
            *(
                ()
                if result.trace is None
                else (ResourceRef(kind="TraceRecord", name=result.trace.trace_id, namespace=planning.plan.namespace),)
            ),
        ),
        result={
            **result.to_dict(),
            "planning": planning.to_dict(),
        },
    )


def exit_code_for_status(status: CommandStatus) -> int:
    return 0 if status in {CommandStatus.OK, CommandStatus.ACCEPTED} else 1


def build_envelope(
    args: argparse.Namespace,
    *,
    active_registry: InMemoryResourceRegistry,
    list_core_capabilities_fn,
    list_resource_kind_schemas_fn,
) -> CommandEnvelope:
    if args.command == "capabilities":
        return CommandEnvelope(
            status=CommandStatus.OK,
            result=build_capabilities_payload(active_registry, list_core_capabilities_fn),
        )
    if args.command == "resource" and args.resource_command == "kinds":
        return CommandEnvelope(
            status=CommandStatus.OK,
            result=build_resource_kinds_payload(list_resource_kind_schemas_fn),
        )
    if args.command == "resource" and args.resource_command == "list":
        return build_resource_list_payload(args, active_registry)
    if args.command == "resource" and args.resource_command == "get":
        return build_resource_get_payload(args, active_registry)
    if args.command == "resource" and args.resource_command == "explain":
        return build_resource_explain_payload(args, active_registry)
    if args.command == "schema" and args.schema_command == "get":
        return build_schema_payload(args.kind)
    if args.command == "upgrade" and args.upgrade_command == "plan":
        return build_upgrade_plan_payload(args)
    if args.command == "pack" and args.pack_command == "status":
        return build_pack_status_payload(args)
    if args.command == "validate":
        return build_validate_payload(args)
    if args.command == "doctor":
        return build_doctor_payload(args)
    if args.command == "secret" and args.secret_command == "status":
        return build_secret_status_payload(args, active_registry)
    if args.command == "secret" and args.secret_command == "explain":
        return build_secret_explain_payload(args, active_registry)
    if args.command == "secret" and args.secret_command == "set":
        return build_secret_set_payload(args, active_registry)
    if args.command == "secret" and args.secret_command == "inspect":
        return build_secret_inspect_payload(args, active_registry)
    if args.command == "secret" and args.secret_command == "delete":
        return build_secret_delete_payload(args, active_registry)
    if args.command == "trace" and args.trace_command == "list":
        return build_trace_list_payload(args)
    if args.command == "trace" and args.trace_command == "get":
        return build_trace_get_payload(args)
    if args.command == "trace" and args.trace_command == "explain":
        return build_trace_explain_payload(args)
    if args.command == "gateway" and args.gateway_command == "status":
        return build_gateway_status_payload(args, active_registry)
    if args.command == "gateway" and args.gateway_command == "explain":
        return build_gateway_explain_payload(args, active_registry)
    if args.command == "mcp" and args.mcp_command == "list":
        return build_mcp_list_payload(args, active_registry)
    if args.command == "mcp" and args.mcp_command == "test":
        return build_mcp_test_payload(args, active_registry)
    if args.command == "mcp" and args.mcp_command == "add":
        return build_mcp_add_payload(args)
    if args.command == "mcp" and args.mcp_command == "disable":
        return build_mcp_disable_payload(args, active_registry)
    if args.command == "connection" and args.connection_command == "explain":
        return build_connection_payload(args, active_registry)
    if args.command == "approval" and args.approval_command == "issue":
        return build_approval_issue_payload(args, active_registry)
    if args.command == "approval" and args.approval_command == "inspect":
        return build_approval_inspect_payload(args)
    if args.command == "exec" and args.exec_command == "plan":
        return build_exec_plan_payload(args, active_registry)
    if args.command == "exec" and args.exec_command == "run":
        return build_exec_run_payload(args, active_registry)
    if args.command == "version":
        return CommandEnvelope(status=CommandStatus.OK, result=build_version_payload())
    return CommandEnvelope(status=CommandStatus.ERROR, reason="unsupported discovery command")
