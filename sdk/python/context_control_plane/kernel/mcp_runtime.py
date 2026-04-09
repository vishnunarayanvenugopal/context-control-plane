from __future__ import annotations

import os
import platform
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .mcp_proxy import McpAllowlistProxy

if TYPE_CHECKING:
    from .mcp import McpPolicyProfile, McpServerProfile


@dataclass(frozen=True)
class McpObservedRuntimeReport:
    mode: str
    attempted: bool
    startup_success: bool
    status: str
    reason: str
    sandbox_applied: dict[str, Any]
    observed_network_destinations: tuple[str, ...] = field(default_factory=tuple)
    observed_filesystem_paths: tuple[str, ...] = field(default_factory=tuple)
    egress_violations: tuple[str, ...] = field(default_factory=tuple)
    warnings: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "attempted": self.attempted,
            "startupSuccess": self.startup_success,
            "status": self.status,
            "reason": self.reason,
            "sandboxApplied": dict(self.sandbox_applied),
            "observedNetworkDestinations": list(self.observed_network_destinations),
            "observedFilesystemPaths": list(self.observed_filesystem_paths),
            "egressViolations": list(self.egress_violations),
            "warnings": list(self.warnings),
        }


def observe_mcp_runtime(
    server: "McpServerProfile",
    policy: "McpPolicyProfile | None",
    *,
    probe_seconds: float = 0.35,
) -> McpObservedRuntimeReport:
    if not server.enabled:
        return McpObservedRuntimeReport(
            mode="config-only",
            attempted=False,
            startup_success=False,
            status="disabled",
            reason="MCP server is disabled",
            sandbox_applied={},
        )
    if server.transport != "stdio":
        return McpObservedRuntimeReport(
            mode="static-endpoint",
            attempted=False,
            startup_success=True,
            status="not-applicable",
            reason="HTTP MCPs do not have a local process to probe",
            sandbox_applied={},
        )

    command = [server.command, *server.args]
    with tempfile.TemporaryDirectory(prefix="ccp-mcp-") as tmp_dir:
        temp_root = Path(tmp_dir)
        env = _minimal_env(temp_root)
        sandbox_plan = _build_runtime_sandbox_plan(temp_root, policy)
        env.update(sandbox_plan["envOverlay"])
        sandbox_applied = dict(sandbox_plan["sandboxApplied"])
        proxy = sandbox_plan["proxy"]
        try:
            process = subprocess.Popen(
                [*sandbox_plan["commandPrefix"], *command],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(temp_root),
                env=env,
                text=True,
            )
        except FileNotFoundError:
            return McpObservedRuntimeReport(
                mode="process-probe",
                attempted=True,
                startup_success=False,
                status="missing_executable",
                reason=f"stdio MCP command {server.command!r} is not available on PATH",
                sandbox_applied=sandbox_applied,
            )
        except OSError as exc:
            return McpObservedRuntimeReport(
                mode="process-probe",
                attempted=True,
                startup_success=False,
                status="failed_to_start",
                reason=f"unable to start MCP process: {exc}",
                sandbox_applied=sandbox_applied,
            )

        warnings: list[str] = []
        proxy_snapshot = {"requestedDestinations": [], "blockedDestinations": []}
        try:
            time.sleep(max(0.05, probe_seconds))
            poll_result = process.poll()
            network_destinations = _collect_network_destinations(process.pid)
            filesystem_paths = _collect_filesystem_paths(process.pid)
            if proxy is not None:
                proxy_snapshot = proxy.snapshot()
                network_destinations = _unique_preserve_order([*proxy_snapshot["requestedDestinations"], *network_destinations])
            egress_violations = _evaluate_egress(network_destinations, policy)
            egress_violations.extend(
                f"proxy blocked outbound destination {destination}"
                for destination in proxy_snapshot["blockedDestinations"]
            )
            if poll_result is None:
                status = "running"
                reason = "MCP process started and remained alive during the observation window"
                startup_success = True
            elif poll_result == 0:
                status = "exited_cleanly"
                reason = "MCP process started and exited cleanly during the observation window"
                startup_success = True
                warnings.append("MCP process exited during the short observation window.")
            else:
                status = "exited_with_error"
                reason = f"MCP process exited with status {poll_result} during the observation window"
                startup_success = False
                warnings.append("Review the MCP command because it exited before the probe completed.")
        finally:
            _terminate_process(process)
            if proxy is not None:
                proxy.close()

        warnings.extend(sandbox_plan["warnings"])
        if not _lsof_available():
            warnings.append("lsof was not available, so filesystem and network observation is limited.")

        return McpObservedRuntimeReport(
            mode=str(sandbox_plan["mode"]),
            attempted=True,
            startup_success=startup_success,
            status=status,
            reason=reason,
            sandbox_applied=sandbox_applied,
            observed_network_destinations=tuple(network_destinations),
            observed_filesystem_paths=tuple(filesystem_paths),
            egress_violations=tuple(egress_violations),
            warnings=tuple(warnings),
        )


def _minimal_env(root: Path) -> dict[str, str]:
    home = root / "home"
    tmp_dir = root / "tmp"
    home.mkdir(parents=True, exist_ok=True)
    tmp_dir.mkdir(parents=True, exist_ok=True)
    path_value = os.environ.get("PATH", "/usr/bin:/bin")
    return {
        "PATH": path_value,
        "HOME": str(home),
        "TMPDIR": str(tmp_dir),
        "LANG": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def _build_runtime_sandbox_plan(root: Path, policy: "McpPolicyProfile | None") -> dict[str, Any]:
    sandbox_applied = {
        "envScrubbed": True,
        "cwd": str(root),
        "home": str(root / "home"),
        "tmpDir": str(root / "tmp"),
        "runner": "process",
        "availableRunners": list(_available_runner_names()),
        "filesystemWriteEnforcement": "scrubbed-temp-root",
        "egressEnforcement": "observed-only",
        "proxy": {
            "active": False,
            "allowlist": [],
            "url": "",
        },
    }
    warnings: list[str] = []
    env_overlay: dict[str, str] = {}
    proxy = _start_allowlist_proxy_if_needed(policy)
    extra_local_allowlist: tuple[str, ...] = ()
    if proxy is not None:
        env_overlay.update(_build_proxy_env_overlay(proxy.proxy_url))
        extra_local_allowlist = (f"localhost:{proxy.port}",)
        sandbox_applied["proxy"] = {
            "active": True,
            "allowlist": list(proxy.allowlist),
            "url": proxy.proxy_url,
        }
        warnings.append("Observed probe is routing outbound HTTP/HTTPS traffic through a local allowlist proxy.")

    if platform.system().lower() != "darwin" or not shutil.which("sandbox-exec"):
        warnings.append("sandbox-exec is unavailable on this platform, so MCP runtime enforcement stays observational.")
        if proxy is not None:
            sandbox_applied["runner"] = "process+allowlist-proxy"
            sandbox_applied["egressEnforcement"] = "allowlist-external-proxy-best-effort"
            if _has_linux_or_container_runner():
                warnings.append(
                    "Additional Linux/container runners are available on this host, but this probe stayed in process mode for compatibility."
                )
            else:
                warnings.append(
                    "Install bubblewrap or a container runner for stronger cross-platform MCP isolation beyond proxy-assisted observation."
                )
        return {
            "commandPrefix": [],
            "sandboxApplied": sandbox_applied,
            "envOverlay": env_overlay,
            "proxy": proxy,
            "warnings": warnings,
            "mode": "proxy-process-probe" if proxy is not None else "process-probe",
        }

    profile_text, enforcement_summary, profile_warnings = _build_macos_sandbox_profile(
        root,
        policy,
        extra_local_allowlist=extra_local_allowlist,
        proxy_allowlist=() if proxy is None else proxy.allowlist,
    )
    warnings.extend(profile_warnings)
    if not profile_text:
        sandbox_applied.update(enforcement_summary)
        return {
            "commandPrefix": [],
            "sandboxApplied": sandbox_applied,
            "envOverlay": env_overlay,
            "proxy": proxy,
            "warnings": warnings,
            "mode": "proxy-process-probe" if proxy is not None else "process-probe",
        }

    profile_path = root / "mcp-runtime.sb"
    profile_path.write_text(profile_text, encoding="utf-8")
    sandbox_applied.update(enforcement_summary)
    sandbox_applied["runner"] = "sandbox-exec"
    return {
        "commandPrefix": ["sandbox-exec", "-f", str(profile_path)],
        "sandboxApplied": sandbox_applied,
        "envOverlay": env_overlay,
        "proxy": proxy,
        "warnings": warnings,
        "mode": "sandbox-exec-proxy-probe" if proxy is not None else "sandbox-exec-probe",
    }


def _build_macos_sandbox_profile(
    root: Path,
    policy: "McpPolicyProfile | None",
    *,
    extra_local_allowlist: tuple[str, ...] = (),
    proxy_allowlist: tuple[str, ...] = (),
) -> tuple[str, dict[str, Any], list[str]]:
    warnings: list[str] = []
    enforced_network_mode = "observed-only"
    filesystem = dict((policy.sandbox_profile or {}).get("filesystem", {})) if policy is not None else {}
    allow_tmp = bool(filesystem.get("allowTmp", True))
    write_paths = [_resolved_path(root)] if allow_tmp else []
    for path in filesystem.get("write", []) if isinstance(filesystem.get("write", []), list) else []:
        try:
            write_paths.append(_resolved_path(Path(str(path)).expanduser()))
        except OSError:
            warnings.append(f"ignoring invalid sandbox write path {path!r}")

    lines = [
        "(version 1)",
        "(allow default)",
        "(deny file-write*)",
    ]
    for path in _unique_preserve_order(write_paths):
        lines.append(f'(allow file-write* (subpath "{_escape_sandbox_string(path)}"))')

    egress_policy = dict(policy.egress_policy) if policy is not None else {"mode": "deny", "allow": []}
    egress_mode = str(egress_policy.get("mode", "deny") or "deny").strip().lower()
    allowed_entries = [str(item).strip() for item in egress_policy.get("allow", []) if str(item).strip()]
    if egress_mode == "deny":
        lines.append("(deny network-outbound)")
        enforced_network_mode = "deny"
    elif egress_mode == "allowlist":
        local_allowlist = [
            item
            for item in (
                *(_normalize_local_allowlist_entry(entry) for entry in allowed_entries),
                *extra_local_allowlist,
            )
            if item
        ]
        unsupported = [] if proxy_allowlist else [entry for entry in allowed_entries if not _normalize_local_allowlist_entry(entry)]
        if local_allowlist:
            lines.append("(deny network-outbound)")
            for host_port in local_allowlist:
                lines.append(f'(allow network-outbound (remote tcp "{host_port}"))')
                lines.append(f'(allow network-outbound (remote udp "{host_port}"))')
            enforced_network_mode = "allowlist-external-proxy" if proxy_allowlist else "allowlist-localhost"
        if unsupported:
            warnings.append(
                "sandbox-exec cannot precisely enforce external host allowlists; those destinations stay observation-only."
            )
        if not local_allowlist and unsupported:
            enforced_network_mode = "observed-only"
    enforcement_summary = {
        "filesystemWriteEnforcement": "sandbox-exec-write-scope",
        "egressEnforcement": enforced_network_mode,
    }
    return "\n".join(lines) + "\n", enforcement_summary, warnings


def _resolved_path(path: Path) -> str:
    return str(path.resolve())


def _escape_sandbox_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _available_runner_names() -> tuple[str, ...]:
    available = ["process"]
    if shutil.which("sandbox-exec"):
        available.append("sandbox-exec")
    if shutil.which("bwrap") or shutil.which("bubblewrap"):
        available.append("bubblewrap")
    if shutil.which("docker"):
        available.append("docker")
    if shutil.which("podman"):
        available.append("podman")
    return tuple(available)


def _has_linux_or_container_runner() -> bool:
    return any(name in _available_runner_names() for name in ("bubblewrap", "docker", "podman"))


def _start_allowlist_proxy_if_needed(policy: "McpPolicyProfile | None") -> McpAllowlistProxy | None:
    if policy is None:
        return None
    egress_policy = dict(policy.egress_policy)
    egress_mode = str(egress_policy.get("mode", "unspecified") or "unspecified").strip().lower()
    if egress_mode != "allowlist":
        return None
    allowed_entries = [str(item).strip() for item in egress_policy.get("allow", []) if str(item).strip()]
    external_allowlist = tuple(entry for entry in allowed_entries if _normalize_local_allowlist_entry(entry) is None)
    if not external_allowlist:
        return None
    return McpAllowlistProxy(allowlist=external_allowlist).start()


def _build_proxy_env_overlay(proxy_url: str) -> dict[str, str]:
    return {
        "HTTP_PROXY": proxy_url,
        "HTTPS_PROXY": proxy_url,
        "ALL_PROXY": proxy_url,
        "http_proxy": proxy_url,
        "https_proxy": proxy_url,
        "all_proxy": proxy_url,
        "NO_PROXY": "127.0.0.1,localhost",
        "no_proxy": "127.0.0.1,localhost",
    }


def _normalize_local_allowlist_entry(candidate: str) -> str | None:
    value = str(candidate or "").strip()
    if not value:
        return None
    if value in {"localhost", "127.0.0.1"}:
        return "localhost:*"
    if ":" not in value:
        return None
    host, port = value.rsplit(":", 1)
    host = host.strip().lower()
    port = port.strip() or "*"
    if host in {"localhost", "127.0.0.1"}:
        return f"localhost:{port}"
    return None


def _unique_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered


def _terminate_process(process: subprocess.Popen[str]) -> None:
    try:
        if process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1.0)
    finally:
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()


def _lsof_available() -> bool:
    try:
        subprocess.run(["lsof", "-v"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1.0, check=False)
    except (FileNotFoundError, subprocess.SubprocessError):
        return False
    return True


def _collect_network_destinations(pid: int) -> list[str]:
    if not _lsof_available():
        return []
    try:
        result = subprocess.run(
            ["lsof", "-n", "-P", "-a", "-p", str(pid), "-i"],
            capture_output=True,
            text=True,
            timeout=1.5,
            check=False,
        )
    except subprocess.SubprocessError:
        return []
    destinations: list[str] = []
    for line in result.stdout.splitlines()[1:]:
        parts = line.split()
        if not parts:
            continue
        name = parts[-1]
        if "->" in name:
            name = name.split("->", 1)[1]
        if name and name not in destinations:
            destinations.append(name)
    return destinations


def _collect_filesystem_paths(pid: int) -> list[str]:
    if not _lsof_available():
        return []
    try:
        result = subprocess.run(
            ["lsof", "-n", "-P", "-p", str(pid)],
            capture_output=True,
            text=True,
            timeout=1.5,
            check=False,
        )
    except subprocess.SubprocessError:
        return []
    files: list[str] = []
    for line in result.stdout.splitlines()[1:]:
        parts = line.split()
        if not parts:
            continue
        name = parts[-1]
        if not name.startswith("/"):
            continue
        if name.startswith(("/usr/", "/System/", "/bin/", "/dev/")):
            continue
        if name not in files:
            files.append(name)
    return files


def _evaluate_egress(destinations: list[str], policy: "McpPolicyProfile | None") -> list[str]:
    if not destinations:
        return []
    if policy is None:
        return [f"observed outbound destination {destination} without an attached McpPolicy" for destination in destinations]
    mode = str(policy.egress_policy.get("mode", "unspecified") or "unspecified").strip().lower()
    allowed = [str(item).strip() for item in policy.egress_policy.get("allow", []) if str(item).strip()]
    violations: list[str] = []
    if mode == "deny":
        violations.extend(f"observed outbound destination {destination} while egress mode is deny" for destination in destinations)
        return violations
    if mode == "allowlist":
        for destination in destinations:
            if not any(_destination_matches_allowlist(destination, candidate) for candidate in allowed):
                violations.append(
                    f"observed outbound destination {destination} is not covered by the egress allowlist"
                )
    return violations


def _destination_matches_allowlist(destination: str, candidate: str) -> bool:
    destination_value = destination.strip()
    candidate_value = candidate.strip()
    if not destination_value or not candidate_value:
        return False
    destination_host = destination_value.rsplit(":", 1)[0]
    candidate_host = candidate_value.rsplit(":", 1)[0]
    return destination_value == candidate_value or destination_host == candidate_host or destination_host.endswith(
        f".{candidate_host}"
    )
