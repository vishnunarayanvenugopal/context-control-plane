from __future__ import annotations

import argparse

DISCOVERY_COMMANDS = frozenset(
    {
        "approval",
        "capabilities",
        "connection",
        "doctor",
        "exec",
        "gateway",
        "mcp",
        "pack",
        "resource",
        "schema",
        "secret",
        "trace",
        "upgrade",
        "validate",
        "version",
    }
)

_JSON_ARG = argparse.ArgumentParser(add_help=False)
_JSON_ARG.add_argument("--json", dest="json_output", action="store_true", help="Emit a stable JSON envelope.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ccp",
        description="Discovery commands for the lightweight ccp-core surface.",
        parents=[_JSON_ARG],
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser(
        "capabilities",
        help="List the capabilities exposed by the core discovery surface.",
        parents=[_JSON_ARG],
    )

    resource_parser = subparsers.add_parser(
        "resource",
        help="Inspect supported resource kinds.",
        parents=[_JSON_ARG],
    )
    resource_subparsers = resource_parser.add_subparsers(dest="resource_command", required=True)
    resource_subparsers.add_parser(
        "kinds",
        help="List supported resource kinds.",
        parents=[_JSON_ARG],
    )
    resource_list_parser = resource_subparsers.add_parser(
        "list",
        help="List effective resources from the active registry.",
        parents=[_JSON_ARG],
    )
    _add_generic_resource_input_args(resource_list_parser)
    resource_list_parser.add_argument("--kind", default="", help="Optional resource kind filter.")
    resource_list_parser.add_argument("--namespace", default="default", help="Optional resource namespace filter.")
    resource_get_parser = resource_subparsers.add_parser(
        "get",
        help="Get one effective resource from the active registry.",
        parents=[_JSON_ARG],
    )
    _add_generic_resource_input_args(resource_get_parser)
    resource_get_parser.add_argument("--kind", required=True, help="Resource kind to load.")
    resource_get_parser.add_argument("--name", required=True, help="Resource name to load.")
    resource_get_parser.add_argument("--namespace", default="default", help="Optional resource namespace filter.")
    resource_explain_parser = resource_subparsers.add_parser(
        "explain",
        help="Explain the effective provenance for one resource.",
        parents=[_JSON_ARG],
    )
    _add_generic_resource_input_args(resource_explain_parser)
    resource_explain_parser.add_argument("--kind", required=True, help="Resource kind to inspect.")
    resource_explain_parser.add_argument("--name", required=True, help="Resource name to inspect.")
    resource_explain_parser.add_argument("--namespace", default="default", help="Optional resource namespace filter.")

    schema_parser = subparsers.add_parser(
        "schema",
        help="Inspect the compact schema summary for a resource kind.",
        parents=[_JSON_ARG],
    )
    schema_subparsers = schema_parser.add_subparsers(dest="schema_command", required=True)
    schema_get_parser = schema_subparsers.add_parser(
        "get",
        help="Get the compact schema summary for a resource kind.",
        parents=[_JSON_ARG],
    )
    schema_get_parser.add_argument("kind", help="Resource kind to inspect, for example McpServer.")

    subparsers.add_parser(
        "version",
        help="Show core package and contract versions.",
        parents=[_JSON_ARG],
    )

    upgrade_parser = subparsers.add_parser(
        "upgrade",
        help="Inspect upgrade compatibility and migration impact.",
        parents=[_JSON_ARG],
    )
    upgrade_subparsers = upgrade_parser.add_subparsers(dest="upgrade_command", required=True)
    upgrade_plan_parser = upgrade_subparsers.add_parser(
        "plan",
        help="Build a reviewable upgrade plan for the target core version.",
        parents=[_JSON_ARG],
    )
    upgrade_plan_parser.add_argument(
        "--target-version",
        default="",
        help="Optional target core version to evaluate against. Defaults to the installed version.",
    )
    upgrade_plan_parser.add_argument(
        "--pack-manifest",
        action="append",
        default=[],
        help="Optional path to a pack.json manifest to include in compatibility checks. Repeat as needed.",
    )
    upgrade_plan_parser.add_argument(
        "--pack-dir",
        action="append",
        default=[],
        help="Optional directory containing pack.json manifests to include in compatibility checks. Repeat as needed.",
    )
    pack_parser = subparsers.add_parser(
        "pack",
        help="Inspect pack activation state and manifest status.",
        parents=[_JSON_ARG],
    )
    pack_subparsers = pack_parser.add_subparsers(dest="pack_command", required=True)
    pack_status_parser = pack_subparsers.add_parser(
        "status",
        help="Show effective activation state for installed packs.",
        parents=[_JSON_ARG],
    )
    _add_pack_input_args(pack_status_parser)

    validate_parser = subparsers.add_parser(
        "validate",
        help="Validate pack manifests and activation resources.",
        parents=[_JSON_ARG],
    )
    _add_pack_input_args(validate_parser)

    doctor_parser = subparsers.add_parser(
        "doctor",
        help="Explain pack health and recommend next steps.",
        parents=[_JSON_ARG],
    )
    _add_pack_input_args(doctor_parser)

    secret_parser = subparsers.add_parser(
        "secret",
        help="Inspect secret backend health without revealing secret values.",
        parents=[_JSON_ARG],
    )
    secret_subparsers = secret_parser.add_subparsers(dest="secret_command", required=True)
    secret_status_parser = secret_subparsers.add_parser(
        "status",
        help="List secret backends with health and durability summaries.",
        parents=[_JSON_ARG],
    )
    _add_secret_input_args(secret_status_parser)
    secret_explain_parser = secret_subparsers.add_parser(
        "explain",
        help="Explain one secret backend and its safe usage posture.",
        parents=[_JSON_ARG],
    )
    _add_secret_input_args(secret_explain_parser)
    secret_set_parser = secret_subparsers.add_parser(
        "set",
        help="Store one secret value in a backend without printing it back to the caller.",
        parents=[_JSON_ARG],
    )
    _add_secret_operation_args(secret_set_parser)
    secret_set_parser.add_argument("--value-file", default="", help="Path to a file containing the secret value.")
    secret_set_parser.add_argument("--value", default="", help=argparse.SUPPRESS)
    secret_set_parser.add_argument(
        "--value-stdin",
        action="store_true",
        help="Read the secret value from stdin instead of putting it in argv or shell history.",
    )
    secret_inspect_parser = secret_subparsers.add_parser(
        "inspect",
        help="Check whether one secret alias exists in a backend without revealing it.",
        parents=[_JSON_ARG],
    )
    _add_secret_operation_args(secret_inspect_parser)
    secret_delete_parser = secret_subparsers.add_parser(
        "delete",
        help="Delete one secret alias from a backend.",
        parents=[_JSON_ARG],
    )
    _add_secret_operation_args(secret_delete_parser)

    trace_parser = subparsers.add_parser(
        "trace",
        help="Inspect sanitized trace records for governed execution.",
        parents=[_JSON_ARG],
    )
    trace_subparsers = trace_parser.add_subparsers(dest="trace_command", required=True)
    trace_list_parser = trace_subparsers.add_parser(
        "list",
        help="List trace records from a trace directory.",
        parents=[_JSON_ARG],
    )
    _add_trace_input_args(trace_list_parser, require_trace_path=False)
    trace_get_parser = trace_subparsers.add_parser(
        "get",
        help="Load one trace record by path or by trace id from a trace directory.",
        parents=[_JSON_ARG],
    )
    _add_trace_input_args(trace_get_parser, require_trace_path=False)
    trace_explain_parser = trace_subparsers.add_parser(
        "explain",
        help="Explain one trace record with a compact event timeline.",
        parents=[_JSON_ARG],
    )
    _add_trace_input_args(trace_explain_parser, require_trace_path=False)

    gateway_parser = subparsers.add_parser(
        "gateway",
        help="Inspect gateway policies and explain governed decisions.",
        parents=[_JSON_ARG],
    )
    gateway_subparsers = gateway_parser.add_subparsers(dest="gateway_command", required=True)
    gateway_status_parser = gateway_subparsers.add_parser(
        "status",
        help="List gateway policies and summarize their defaults.",
        parents=[_JSON_ARG],
    )
    _add_gateway_input_args(gateway_status_parser)
    gateway_explain_parser = gateway_subparsers.add_parser(
        "explain",
        help="Explain what one GatewayPolicy would decide for a requested action.",
        parents=[_JSON_ARG],
    )
    _add_gateway_input_args(gateway_explain_parser)
    gateway_explain_parser.add_argument("--access", default="read", help="Requested access level: read, write, or admin.")
    gateway_explain_parser.add_argument(
        "--classification",
        default="internal",
        help="Requested data classification: public, internal, confidential, or restricted.",
    )
    gateway_explain_parser.add_argument(
        "--mode",
        default="connect",
        help="Requested execution mode: connect, materialize, reveal, or another gateway-scoped mode string.",
    )
    gateway_explain_parser.add_argument(
        "--operation",
        default="",
        help="Optional governed operation text used for rule matching and explanation.",
    )

    mcp_parser = subparsers.add_parser(
        "mcp",
        help="Inspect MCP trust, sandboxing, and safe test posture.",
        parents=[_JSON_ARG],
    )
    mcp_subparsers = mcp_parser.add_subparsers(dest="mcp_command", required=True)
    mcp_list_parser = mcp_subparsers.add_parser(
        "list",
        help="List MCP servers with trust and health summaries.",
        parents=[_JSON_ARG],
    )
    _add_mcp_input_args(mcp_list_parser)
    mcp_test_parser = mcp_subparsers.add_parser(
        "test",
        help="Build a safe install/test report for one MCP without trusting it by default.",
        parents=[_JSON_ARG],
    )
    _add_mcp_input_args(mcp_test_parser)
    mcp_test_parser.add_argument(
        "--observed",
        action="store_true",
        help="Run a short-lived local process probe for stdio MCPs with scrubbed environment settings.",
    )
    mcp_test_parser.add_argument(
        "--probe-seconds",
        type=float,
        default=0.35,
        help="Observation window for --observed stdio MCP probes.",
    )
    mcp_add_parser = mcp_subparsers.add_parser(
        "add",
        help="Create a safe-by-default McpServer and McpPolicy resource pair.",
        parents=[_JSON_ARG],
    )
    mcp_add_parser.add_argument("--resource-dir", required=True, help="Directory where the MCP resource files should be created.")
    mcp_add_parser.add_argument("--name", required=True, help="Name of the MCP server resource to create.")
    mcp_add_parser.add_argument("--namespace", default="default", help="Optional resource namespace. Defaults to default.")
    mcp_add_parser.add_argument("--transport", required=True, help="Transport type: stdio, http, or https.")
    mcp_add_parser.add_argument("--command", dest="startup_command", default="", help="Stdio command used to start the MCP.")
    mcp_add_parser.add_argument("--arg", action="append", default=[], help="Repeatable stdio command argument.")
    mcp_add_parser.add_argument("--url", default="", help="HTTP/HTTPS endpoint for a remote MCP.")
    mcp_add_parser.add_argument("--declared-tool", action="append", default=[], help="Repeatable declared MCP tool name.")
    mcp_add_parser.add_argument("--capability", action="append", default=[], help="Repeatable declared MCP capability.")
    mcp_add_parser.add_argument("--trust-tier", default="quarantined", help="Trust tier: builtin-trusted, verified, user-added, or quarantined.")
    mcp_add_parser.add_argument("--egress-mode", default="deny", help="Egress policy mode: deny, allowlist, or open.")
    mcp_add_parser.add_argument("--egress-allow", action="append", default=[], help="Repeatable allowed network destination.")
    mcp_add_parser.add_argument("--sandbox-read", action="append", default=[], help="Repeatable readable filesystem path.")
    mcp_add_parser.add_argument("--sandbox-write", action="append", default=[], help="Repeatable writable filesystem path.")
    mcp_add_parser.add_argument("--allow-tmp", action="store_true", help="Allow temporary filesystem writes in the sandbox profile.")
    mcp_add_parser.add_argument("--secret-usage-mode", default="brokered", help="Secret usage mode: brokered, ephemeral-materialization, or raw-secret.")
    mcp_add_parser.add_argument("--disabled", action="store_true", help="Create the MCP resource in a disabled state.")
    mcp_disable_parser = mcp_subparsers.add_parser(
        "disable",
        help="Disable one managed MCP by updating its McpServer resource.",
        parents=[_JSON_ARG],
    )
    _add_mcp_input_args(mcp_disable_parser)

    connection_parser = subparsers.add_parser(
        "connection",
        help="Explain connection safety, approval, and secret handling.",
        parents=[_JSON_ARG],
    )
    connection_subparsers = connection_parser.add_subparsers(dest="connection_command", required=True)
    connection_explain_parser = connection_subparsers.add_parser(
        "explain",
        help="Explain how a ConnectionProfile will be handled for a requested access pattern.",
        parents=[_JSON_ARG],
    )
    _add_connection_input_args(connection_explain_parser)
    connection_explain_parser.add_argument(
        "--access",
        default="read",
        help="Requested access level: read, write, or admin.",
    )
    connection_explain_parser.add_argument(
        "--mode",
        default="",
        help="Requested connection mode: connect, materialize, or reveal.",
    )
    connection_explain_parser.add_argument(
        "--operation",
        default="",
        help="Optional governed operation string used for gateway-policy evaluation.",
    )

    approval_parser = subparsers.add_parser(
        "approval",
        help="Issue or inspect exact approval receipts for governed execution.",
        parents=[_JSON_ARG],
    )
    approval_subparsers = approval_parser.add_subparsers(dest="approval_command", required=True)
    approval_issue_parser = approval_subparsers.add_parser(
        "issue",
        help="Issue an approval receipt for one exact governed action using an explicitly configured signer.",
        parents=[_JSON_ARG],
    )
    _add_connection_input_args(approval_issue_parser)
    approval_issue_parser.add_argument("--access", default="read", help="Requested access level: read, write, or admin.")
    approval_issue_parser.add_argument("--mode", default="", help="Requested connection mode: connect, materialize, or reveal.")
    approval_issue_parser.add_argument("--operation", required=True, help="Exact governed operation being approved.")
    approval_issue_parser.add_argument("--approved-by", required=True, help="Identifier for the approving human or system.")
    approval_issue_parser.add_argument("--reason", default="", help="Optional reason for the approval receipt.")
    approval_issue_parser.add_argument("--ttl-minutes", type=int, default=60, help="Receipt lifetime in minutes.")
    approval_issue_parser.add_argument("--output", default="", help="Optional path to save the issued receipt.")

    approval_inspect_parser = approval_subparsers.add_parser(
        "inspect",
        help="Inspect a saved approval receipt.",
        parents=[_JSON_ARG],
    )
    approval_inspect_parser.add_argument("--receipt", required=True, help="Path to an approval receipt JSON file.")

    exec_parser = subparsers.add_parser(
        "exec",
        help="Build or run governed execution through a brokered adapter.",
        parents=[_JSON_ARG],
    )
    exec_subparsers = exec_parser.add_subparsers(dest="exec_command", required=True)
    exec_plan_parser = exec_subparsers.add_parser(
        "plan",
        help="Plan governed execution for a connection-backed operation.",
        parents=[_JSON_ARG],
    )
    _add_connection_input_args(exec_plan_parser)
    exec_plan_parser.add_argument("--access", default="read", help="Requested access level: read, write, or admin.")
    exec_plan_parser.add_argument("--mode", default="", help="Requested connection mode: connect, materialize, or reveal.")
    exec_plan_parser.add_argument("--operation", required=True, help="Exact governed operation to plan.")
    exec_plan_parser.add_argument(
        "--approval-receipt",
        default="",
        help="Optional approval receipt file to satisfy an approval-required execution plan.",
    )

    exec_run_parser = exec_subparsers.add_parser(
        "run",
        help="Run one governed operation through a brokered adapter with trace recording.",
        parents=[_JSON_ARG],
    )
    _add_connection_input_args(exec_run_parser)
    exec_run_parser.add_argument("--access", default="read", help="Requested access level: read, write, or admin.")
    exec_run_parser.add_argument("--mode", default="", help="Requested connection mode: connect, materialize, or reveal.")
    exec_run_parser.add_argument("--operation", required=True, help="Exact governed operation to run.")
    exec_run_parser.add_argument(
        "--approval-receipt",
        default="",
        help="Optional approval receipt file for approval-required execution.",
    )
    exec_run_parser.add_argument(
        "--params",
        default="{}",
        help="Optional JSON object of adapter parameters for the governed run.",
    )
    exec_run_parser.add_argument(
        "--trace-dir",
        default="",
        help="Optional directory where the sanitized trace record should be saved.",
    )

    return parser


def _add_pack_input_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--pack-manifest",
        action="append",
        default=[],
        help="Optional path to a pack.json manifest. Repeat as needed.",
    )
    parser.add_argument(
        "--pack-dir",
        action="append",
        default=[],
        help="Optional directory containing pack.json manifests. Repeat as needed.",
    )
    parser.add_argument(
        "--activation-resource",
        action="append",
        default=[],
        help="Optional path to a PackActivation resource document. Repeat as needed.",
    )
    parser.add_argument(
        "--activation-dir",
        action="append",
        default=[],
        help="Optional directory containing PackActivation resource documents. Repeat as needed.",
    )


def _add_connection_input_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--resource",
        action="append",
        default=[],
        help="Optional path to a ConnectionProfile resource document. Repeat as needed.",
    )
    parser.add_argument(
        "--resource-dir",
        action="append",
        default=[],
        help="Optional directory containing ConnectionProfile resource documents. Repeat as needed.",
    )
    parser.add_argument(
        "--name",
        default="",
        help="Optional ConnectionProfile name. Required when multiple profiles are loaded.",
    )
    parser.add_argument(
        "--namespace",
        default="default",
        help="Optional resource namespace. Defaults to default.",
    )


def _add_generic_resource_input_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--resource",
        action="append",
        default=[],
        help="Optional path to a resource document. Repeat as needed.",
    )
    parser.add_argument(
        "--resource-dir",
        action="append",
        default=[],
        help="Optional directory containing resource documents. Repeat as needed.",
    )


def _add_secret_input_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--resource",
        action="append",
        default=[],
        help="Optional path to a SecretBackend resource document. Repeat as needed.",
    )
    parser.add_argument(
        "--resource-dir",
        action="append",
        default=[],
        help="Optional directory containing SecretBackend resource documents. Repeat as needed.",
    )
    parser.add_argument(
        "--name",
        default="",
        help="Optional SecretBackend name. Required when multiple backends are loaded.",
    )
    parser.add_argument(
        "--namespace",
        default="default",
        help="Optional resource namespace. Defaults to default.",
    )


def _add_secret_operation_args(parser: argparse.ArgumentParser) -> None:
    _add_secret_input_args(parser)
    parser.add_argument(
        "--backend",
        required=True,
        help="Name of the SecretBackend resource that should handle the secret operation.",
    )
    parser.add_argument(
        "--secret",
        required=True,
        help="Logical secret alias name. This is the name connections will reference via secret_refs.",
    )


def _add_mcp_input_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--resource",
        action="append",
        default=[],
        help="Optional path to an McpServer or McpPolicy resource document. Repeat as needed.",
    )
    parser.add_argument(
        "--resource-dir",
        action="append",
        default=[],
        help="Optional directory containing McpServer and McpPolicy resource documents. Repeat as needed.",
    )
    parser.add_argument(
        "--name",
        default="",
        help="Optional McpServer name. Required when multiple MCP servers are loaded.",
    )
    parser.add_argument(
        "--namespace",
        default="default",
        help="Optional resource namespace. Defaults to default.",
    )


def _add_trace_input_args(parser: argparse.ArgumentParser, *, require_trace_path: bool) -> None:
    parser.add_argument(
        "--trace-dir",
        default="",
        help="Directory containing persisted TraceRecord JSON files.",
    )
    parser.add_argument(
        "--trace",
        default="",
        required=require_trace_path,
        help="Path to a specific TraceRecord JSON file.",
    )
    parser.add_argument(
        "--id",
        default="",
        help="Trace id to resolve from --trace-dir when an explicit --trace path is not provided.",
    )


def _add_gateway_input_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--resource",
        action="append",
        default=[],
        help="Optional path to a GatewayPolicy resource document. Repeat as needed.",
    )
    parser.add_argument(
        "--resource-dir",
        action="append",
        default=[],
        help="Optional directory containing GatewayPolicy resource documents. Repeat as needed.",
    )
    parser.add_argument(
        "--name",
        default="",
        help="Optional GatewayPolicy name. Required when multiple gateway policies are loaded.",
    )
    parser.add_argument(
        "--namespace",
        default="default",
        help="Optional resource namespace. Defaults to default.",
    )
