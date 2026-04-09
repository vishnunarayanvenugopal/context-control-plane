from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import TextIO

from ..kernel import InMemoryResourceRegistry, list_core_capabilities, list_schema_definitions, load_resources_from_dir
from .cli_dispatch import build_envelope, exit_code_for_status
from .cli_parser import DISCOVERY_COMMANDS, build_parser
from .cli_render import render_text

_DEFAULT_RESOURCE_DIRS = (".ccp/resources", "resources")
_DEFAULT_TRACE_DIRS = (".ccp/traces", "traces")
_DEFAULT_PACK_DIRS = (".ccp/packs", "packs")
_DEFAULT_PACK_MANIFESTS = (".ccp/pack.json", "pack.json")
_DEFAULT_ACTIVATION_DIRS = (".ccp/activations", "activations")


def _existing_paths(cwd: Path, candidates: tuple[str, ...]) -> list[str]:
    paths: list[str] = []
    for candidate in candidates:
        path = cwd / candidate
        if path.exists():
            paths.append(str(path))
    return paths


def _extend_unique(target: list[str], values: list[str]) -> None:
    seen = set(target)
    for value in values:
        if value not in seen:
            target.append(value)
            seen.add(value)


def _apply_default_cli_inputs(args, *, cwd: Path) -> None:
    if hasattr(args, "resource_dir") and not getattr(args, "resource", []) and not getattr(args, "resource_dir", []):
        _extend_unique(args.resource_dir, _existing_paths(cwd, _DEFAULT_RESOURCE_DIRS))

    if hasattr(args, "pack_dir") and not getattr(args, "pack_dir", []):
        _extend_unique(args.pack_dir, _existing_paths(cwd, _DEFAULT_PACK_DIRS))
    if hasattr(args, "pack_manifest") and not getattr(args, "pack_manifest", []):
        _extend_unique(args.pack_manifest, _existing_paths(cwd, _DEFAULT_PACK_MANIFESTS))
    if hasattr(args, "activation_dir") and not getattr(args, "activation_dir", []):
        _extend_unique(args.activation_dir, _existing_paths(cwd, _DEFAULT_ACTIVATION_DIRS))

    if hasattr(args, "trace_dir") and not str(getattr(args, "trace_dir", "") or "").strip():
        trace_dirs = _existing_paths(cwd, _DEFAULT_TRACE_DIRS)
        if trace_dirs:
            args.trace_dir = trace_dirs[0]
        elif getattr(args, "command", "") == "exec" and getattr(args, "exec_command", "") == "run":
            args.trace_dir = str(cwd / ".ccp" / "traces")


def _default_registry(*, cwd: Path) -> InMemoryResourceRegistry:
    documents = []
    for directory in _existing_paths(cwd, _DEFAULT_RESOURCE_DIRS):
        documents.extend(load_resources_from_dir(directory, layer="local"))
    return InMemoryResourceRegistry(documents)


def run(
    argv: list[str],
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    registry: InMemoryResourceRegistry | None = None,
) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    parser = build_parser()
    args = parser.parse_args(argv)
    cwd = Path.cwd()
    _apply_default_cli_inputs(args, cwd=cwd)
    active_registry = registry or _default_registry(cwd=cwd)

    envelope = build_envelope(
        args,
        active_registry=active_registry,
        list_core_capabilities_fn=list_core_capabilities,
        list_resource_kind_schemas_fn=list_schema_definitions,
    )

    if args.json_output:
        print(json.dumps(envelope.to_dict(), indent=2, sort_keys=True), file=stdout)
        return exit_code_for_status(envelope.status)
    return render_text(args, envelope, stdout, stderr)


def main(argv: list[str] | None = None) -> int:
    return run(list(sys.argv[1:] if argv is None else argv))
