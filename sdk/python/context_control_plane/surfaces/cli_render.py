from __future__ import annotations

import argparse
import json
from typing import TextIO

from ..kernel import CommandEnvelope, CommandStatus
from .cli_dispatch import exit_code_for_status


def render_text(args: argparse.Namespace, envelope: CommandEnvelope, stdout: TextIO, stderr: TextIO) -> int:
    payload = envelope.to_dict()
    result = payload["result"]
    if envelope.status is CommandStatus.ERROR and not result:
        print(f"error: {payload['reason']}", file=stderr)
        next_action = payload.get("next_action")
        if next_action:
            print(f"next: {next_action['command']}", file=stderr)
        return 1

    if args.command == "secret" and args.secret_command == "status":
        summary = result["summary"]
        print(
            f"Secret backends: {summary['backends']} ok={summary['ok']} attention={summary['attentionNeeded']}",
            file=stdout,
        )
        for item in result["backends"]:
            print(
                f"{item['name']} [{item['health']}] type={item['type']} durability={item['durability']}",
                file=stdout,
            )
        return exit_code_for_status(envelope.status)

    if args.command == "secret" and args.secret_command == "explain":
        backend = result["backend"]
        print(f"Secret backend: {backend['name']} [{result['health']}]", file=stdout)
        print(f"Type: {backend['type']}", file=stdout)
        print(f"Durability: {backend['durability']}", file=stdout)
        print(f"Managed: {backend['managed']}", file=stdout)
        print(f"Reason: {result['reason']}", file=stdout)
        if result["capabilities"]:
            print(f"Capabilities: {', '.join(result['capabilities'])}", file=stdout)
        if result["warnings"]:
            print("Warnings:", file=stdout)
            for warning in result["warnings"]:
                print(f"- {warning}", file=stdout)
        return exit_code_for_status(envelope.status)

    if args.command == "secret" and args.secret_command == "set":
        print(f"Secret: {result['secretName']} [stored]", file=stdout)
        print(f"Backend: {result['backend']['name']} ({result['backend']['type']})", file=stdout)
        print(f"Reason: {result['reason']}", file=stdout)
        return exit_code_for_status(envelope.status)

    if args.command == "secret" and args.secret_command == "inspect":
        print(f"Secret: {result['secretName']} [{'present' if result['exists'] else 'missing'}]", file=stdout)
        print(f"Backend: {result['backend']['name']} ({result['backend']['type']})", file=stdout)
        print(f"Reason: {result['reason']}", file=stdout)
        return exit_code_for_status(envelope.status)

    if args.command == "secret" and args.secret_command == "delete":
        print(f"Secret: {result['secretName']} [deleted]", file=stdout)
        print(f"Backend: {result['backend']['name']} ({result['backend']['type']})", file=stdout)
        print(f"Reason: {result['reason']}", file=stdout)
        return exit_code_for_status(envelope.status)

    if args.command == "connection" and args.connection_command == "explain":
        decision = result
        connection = decision["connection"]
        print(f"Connection: {connection['name']} [{payload['status']}]", file=stdout)
        print(f"Adapter: {connection['adapter'] or 'unspecified'}", file=stdout)
        print(f"Endpoint: {connection['endpoint'] or 'unspecified'}", file=stdout)
        print(f"Classification: {decision['classification']}", file=stdout)
        print(f"Access: {decision['requestedAccess']}", file=stdout)
        print(f"Mode: {decision['requestedMode']}", file=stdout)
        print(f"Brokered: {decision['secretHandling']['brokered']}", file=stdout)
        print(f"Sanitize input/output: {decision['secretHandling']['sanitizeInput']}/{decision['secretHandling']['sanitizeOutput']}", file=stdout)
        if payload["reason"]:
            print(f"Reason: {payload['reason']}", file=stdout)
        elif decision["reason"]:
            print(f"Reason: {decision['reason']}", file=stdout)
        if decision["warnings"]:
            print("Warnings:", file=stdout)
            for warning in decision["warnings"]:
                print(f"- {warning}", file=stdout)
        if payload.get("next_action"):
            print(f"Next: {payload['next_action']['command']}", file=stdout)
        return exit_code_for_status(envelope.status)

    if args.command == "approval" and args.approval_command == "issue":
        receipt = result["receipt"]
        subject = receipt["spec"]["subject"]
        print(f"Approval: {receipt['metadata']['name']} [ok]", file=stdout)
        print(f"Subject: {subject['kind']} {subject['name']}", file=stdout)
        print(f"Access/Mode: {receipt['spec']['access']} / {receipt['spec']['mode']}", file=stdout)
        print(f"Operation: {receipt['spec']['operation']}", file=stdout)
        print(f"Approved by: {receipt['spec']['approvedBy']}", file=stdout)
        print(f"Expires: {receipt['spec']['expiresAt']}", file=stdout)
        if result.get("savedTo"):
            print(f"Saved to: {result['savedTo']}", file=stdout)
        return exit_code_for_status(envelope.status)

    if args.command == "approval" and args.approval_command == "inspect":
        receipt = result["receipt"]
        subject = receipt["spec"]["subject"]
        print(f"Approval: {receipt['metadata']['name']}", file=stdout)
        print(f"Subject: {subject['kind']} {subject['name']}", file=stdout)
        print(f"Access/Mode: {receipt['spec']['access']} / {receipt['spec']['mode']}", file=stdout)
        print(f"Operation: {receipt['spec']['operation']}", file=stdout)
        print(f"Approved by: {receipt['spec']['approvedBy']}", file=stdout)
        print(f"Expires: {receipt['spec']['expiresAt']}", file=stdout)
        return exit_code_for_status(envelope.status)

    if args.command == "exec" and args.exec_command == "plan":
        print(f"Execution Plan [{payload['status']}]", file=stdout)
        print(f"Operation: {result['operation']}", file=stdout)
        connection = result["connection"]["connection"]
        print(f"Connection: {connection['name']} ({connection['adapter'] or 'unspecified'})", file=stdout)
        if result["plan"] is not None:
            plan = result["plan"]
            print(f"Mode: {plan['mode']}", file=stdout)
            print(f"Credential delivery: {plan['credentialDelivery']}", file=stdout)
            print(f"Secret exposure: {plan['secretExposure']}", file=stdout)
            print(f"Trace: {plan['traceId']}", file=stdout)
            if plan["notes"]:
                print("Notes:", file=stdout)
                for note in plan["notes"]:
                    print(f"- {note}", file=stdout)
        if payload["reason"]:
            print(f"Reason: {payload['reason']}", file=stdout)
        if payload.get("next_action"):
            print(f"Next: {payload['next_action']['command']}", file=stdout)
        return exit_code_for_status(envelope.status)

    if args.command == "exec" and args.exec_command == "run":
        print(f"Execution Run [{payload['status']}]", file=stdout)
        print(f"Operation: {result['operation']}", file=stdout)
        print(f"Adapter: {result['adapterId'] or 'unspecified'}", file=stdout)
        if result["trace"] is not None:
            trace = result["trace"]
            print(f"Trace: {trace['metadata']['name']}", file=stdout)
            print(f"Trace events: {len(trace['spec']['events'])}", file=stdout)
        if result.get("tracePath"):
            print(f"Trace file: {result['tracePath']}", file=stdout)
        if result["output"]:
            print(f"Output keys: {', '.join(sorted(result['output']))}", file=stdout)
        if payload["reason"]:
            print(f"Reason: {payload['reason']}", file=stdout)
        if payload.get("next_action"):
            print(f"Next: {payload['next_action']['command']}", file=stdout)
        return exit_code_for_status(envelope.status)

    if args.command == "trace" and args.trace_command == "list":
        summary = result["summary"]
        print(f"Traces: {summary['traces']} ok={summary['ok']} non-ok={summary['nonOk']}", file=stdout)
        for item in result["traces"]:
            print(
                f"{item['traceId']} [{item['status']}] {item['operation']} events={item['eventCount']} stored={item['storedAt'] or 'n/a'}",
                file=stdout,
            )
        return exit_code_for_status(envelope.status)

    if args.command == "trace" and args.trace_command == "get":
        trace = result["trace"]
        print(f"Trace: {trace['metadata']['name']}", file=stdout)
        print(f"Status: {trace['spec']['status']}", file=stdout)
        print(f"Operation: {trace['spec']['operation']}", file=stdout)
        print(f"Events: {len(trace['spec']['events'])}", file=stdout)
        return exit_code_for_status(envelope.status)

    if args.command == "trace" and args.trace_command == "explain":
        print(f"Trace: {result['traceId']} [{result['status']}]", file=stdout)
        print(f"Operation: {result['operation']}", file=stdout)
        print(f"Connection: {result['connection']['name']} ({result['connection']['adapter'] or 'unspecified'})", file=stdout)
        print(f"Events: {result['eventCount']}", file=stdout)
        print(f"Redacted fields: {result['redactedFieldCount']}", file=stdout)
        if result["timeline"]:
            print("Timeline:", file=stdout)
            for item in result["timeline"]:
                print(f"- {item['eventType']} @ {item['recordedAt']}", file=stdout)
        return exit_code_for_status(envelope.status)

    if args.command == "gateway" and args.gateway_command == "status":
        summary = result["summary"]
        print(
            f"Gateway policies: {summary['policies']} approval-defaults={summary['approvalDefaults']} deny-defaults={summary['denyDefaults']}",
            file=stdout,
        )
        for item in result["policies"]:
            print(
                f"{item['name']} default={item['defaultDecision']} rules={item['ruleCount']} classifications={item['classificationCount']}",
                file=stdout,
            )
        return exit_code_for_status(envelope.status)

    if args.command == "gateway" and args.gateway_command == "explain":
        print(f"Gateway: {result['policy']['name']} [{payload['status']}]", file=stdout)
        print(f"Decision: {result['decision']}", file=stdout)
        print(f"Access/Classification/Mode: {result['requestedAccess']} / {result['requestedClassification']} / {result['requestedMode']}", file=stdout)
        if result["requestedOperation"]:
            print(f"Operation: {result['requestedOperation']}", file=stdout)
        print(f"Reason: {payload['reason'] or result['reason']}", file=stdout)
        if result["matchedRuleIndex"] >= 0:
            print(f"Matched rule: {result['matchedRuleIndex']}", file=stdout)
        if result["warnings"]:
            print("Warnings:", file=stdout)
            for warning in result["warnings"]:
                print(f"- {warning}", file=stdout)
        if payload.get("next_action"):
            print(f"Next: {payload['next_action']['command']}", file=stdout)
        return exit_code_for_status(envelope.status)

    if args.command == "mcp" and args.mcp_command == "list":
        summary = result["summary"]
        print(
            (
                f"MCPs: {summary['servers']} enabled={summary['enabled']} "
                f"safe={summary['safe']} attention={summary['attentionNeeded']} blocked={summary['blocked']}"
            ),
            file=stdout,
        )
        for item in result["servers"]:
            policy_state = "policy" if item["policyAttached"] else "no-policy"
            print(
                f"{item['name']} [{item['health']}] transport={item['transport']} trust={item['trustTier']} {policy_state}",
                file=stdout,
            )
        return exit_code_for_status(envelope.status)

    if args.command == "mcp" and args.mcp_command == "test":
        server = result["server"]
        startup = result["startup"]
        observed = result.get("observed", {})
        print(f"MCP: {server['name']} [{result['health']}]", file=stdout)
        print(f"Transport: {server['transport']}", file=stdout)
        print(f"Trust tier: {result['trustTier']}", file=stdout)
        print(f"Policy attached: {result['policy']['attached']}", file=stdout)
        print(f"Startup: {startup['status']}", file=stdout)
        if startup["reason"]:
            print(f"Startup reason: {startup['reason']}", file=stdout)
        print(f"Secret usage: {result['secretUsageMode']}", file=stdout)
        sanitization = result["sanitizationPolicyApplied"]
        print(
            f"Sanitization: input={sanitization['input']} output={sanitization['output']} trace={sanitization['trace']}",
            file=stdout,
        )
        print(
            f"Network destinations: {', '.join(result['networkDestinationsRequested']) or 'none declared'}",
            file=stdout,
        )
        filesystem = result["filesystemAccessRequested"]
        print(
            f"Filesystem access: read={len(filesystem['read'])} write={len(filesystem['write'])} allowTmp={filesystem['allowTmp']}",
            file=stdout,
        )
        print(f"Declared tools: {', '.join(result['declaredTools']) or 'none declared'}", file=stdout)
        if observed:
            print(
                f"Observed: {observed.get('mode', 'not-run')} startup={observed.get('startupSuccess', False)} status={observed.get('status', 'unknown')}",
                file=stdout,
            )
            if observed.get("observedNetworkDestinations"):
                print(
                    f"Observed network: {', '.join(observed['observedNetworkDestinations'])}",
                    file=stdout,
                )
        if result["warnings"]:
            print("Warnings:", file=stdout)
            for warning in result["warnings"]:
                print(f"- {warning}", file=stdout)
        if result["recommendations"]:
            print("Recommendations:", file=stdout)
            for recommendation in result["recommendations"]:
                print(f"- {recommendation}", file=stdout)
        if payload["reason"]:
            print(f"Reason: {payload['reason']}", file=stdout)
        if payload.get("next_action"):
            print(f"Next: {payload['next_action']['command']}", file=stdout)
        return exit_code_for_status(envelope.status)

    if args.command == "mcp" and args.mcp_command == "add":
        print(f"MCP: {args.name} [ok]", file=stdout)
        print(f"Server resource: {result['serverPath']}", file=stdout)
        print(f"Policy resource: {result['policyPath']}", file=stdout)
        return exit_code_for_status(envelope.status)

    if args.command == "mcp" and args.mcp_command == "disable":
        print(f"MCP: {args.name or envelope.resource_refs[0].name} [disabled]", file=stdout)
        print(f"Updated: {result['updated']}", file=stdout)
        return exit_code_for_status(envelope.status)

    if args.command == "pack" and args.pack_command == "status":
        summary = result["summary"]
        print(
            f"Packs: {summary['packs']} enabled={summary['enabledPacks']} errors={summary['errors']} warnings={summary['warnings']}",
            file=stdout,
        )
        if result["pack_status"]:
            for item in result["pack_status"]:
                source_bits = [f"manifest={item['manifest_source']}"]
                if item["activation_source"]:
                    source_bits.append(f"activation={item['activation_source']}")
                print(f"{item['pack_id']} [{item['effective_state']}] {' '.join(source_bits)}", file=stdout)
        else:
            print("No packs found.", file=stdout)
        if result["issues"]:
            print("Issues:", file=stdout)
            for issue in result["issues"]:
                print(f"{issue['level']} {issue['code']} ({issue['subject']}): {issue['message']}", file=stdout)
        return exit_code_for_status(envelope.status)

    if args.command == "validate":
        summary = result["summary"]
        print(
            f"Validation: packs={summary['packs']} enabled={summary['enabledPacks']} errors={summary['errors']} warnings={summary['warnings']}",
            file=stdout,
        )
        if result["issues"]:
            for issue in result["issues"]:
                print(f"{issue['level']} {issue['code']} ({issue['subject']}): {issue['message']}", file=stdout)
        else:
            print("No validation issues found.", file=stdout)
        return exit_code_for_status(envelope.status)

    if args.command == "doctor":
        print(f"Health: {result['health']}", file=stdout)
        summary = result["summary"]
        print(
            f"Summary: packs={summary['packs']} enabled={summary['enabledPacks']} errors={summary['errors']} warnings={summary['warnings']}",
            file=stdout,
        )
        if result["recommendations"]:
            print("Recommendations:", file=stdout)
            for recommendation in result["recommendations"]:
                print(f"- {recommendation}", file=stdout)
        if result["issues"]:
            print("Issues:", file=stdout)
            for issue in result["issues"]:
                print(f"{issue['level']} {issue['code']} ({issue['subject']}): {issue['message']}", file=stdout)
        return exit_code_for_status(envelope.status)

    if args.command == "capabilities":
        for item in result["capabilities"]:
            print(f"{item['capability_id']} [{item['stability']}] - {item['description']}", file=stdout)
        return 0

    if args.command == "resource" and args.resource_command == "kinds":
        for item in result["resource_kinds"]:
            print(f"{item['kind']} [{item['stability']}] - {item['description']}", file=stdout)
        return 0

    if args.command == "schema" and args.schema_command == "get":
        schema = result["schema"]
        print(f"Kind: {schema['kind']}", file=stdout)
        print(f"API version: {schema['apiVersion']}", file=stdout)
        print(f"Stability: {schema['stability']}", file=stdout)
        print(f"Required: {', '.join(schema['required_fields'])}", file=stdout)
        print(f"Spec fields: {', '.join(schema['spec_fields'])}", file=stdout)
        if schema["notes"]:
            print(f"Notes: {' | '.join(schema['notes'])}", file=stdout)
        return 0

    if args.command == "version":
        package = result["package"]
        print(f"{package['name']} {package['version']}", file=stdout)
        print(f"Default API version: {result['default_api_version']}", file=stdout)
        for contract in result["contracts"]:
            print(
                f"{contract['name']}/{contract['version']} [{contract['stability']}]",
                file=stdout,
            )
        return 0

    if args.command == "upgrade" and args.upgrade_command == "plan":
        print(
            f"Upgrade plan: {result['currentCoreVersion']} -> {result['targetCoreVersion']}",
            file=stdout,
        )
        summary = result["summary"]
        print(
            (
                f"Summary: auto={summary['autoMigrations']} "
                f"manual={summary['manualActions']} blocked={summary['blockedItems']}"
            ),
            file=stdout,
        )
        for action in result["actions"]:
            print(f"{action['category']} {action['item_id']} [{action['disposition']}] - {action['reason']}", file=stdout)
        return 0

    print(json.dumps(payload, indent=2, sort_keys=True), file=stdout)
    return 0
