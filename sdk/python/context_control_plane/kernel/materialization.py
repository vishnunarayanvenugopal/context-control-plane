from __future__ import annotations

import json
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from .secrets import MaterializationLease, normalize_secret_ref


def _materialization_root(base_dir: str = "") -> Path:
    if base_dir:
        return Path(base_dir).expanduser().resolve()
    env_override = str(os.environ.get("CCP_MATERIALIZATION_DIR", "") or "").strip()
    if env_override:
        return Path(env_override).expanduser().resolve()
    return (Path(tempfile.gettempdir()) / "ccp-core-materializations").resolve()


def _parse_utc(value: str) -> datetime:
    text = str(value or "").strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text).astimezone(timezone.utc)


@dataclass(frozen=True)
class MaterializationBundle:
    lease: MaterializationLease
    root_path: Path
    secret_files: Mapping[str, str] = field(default_factory=dict)

    def to_adapter_context(self) -> dict[str, object]:
        return {
            "leaseId": self.lease.lease_id,
            "delivery": self.lease.delivery,
            "cleanupOnExit": self.lease.cleanup_on_exit,
            "cleanupOnRead": self.lease.cleanup_on_read,
            "rootPath": str(self.root_path),
            "secretFiles": dict(self.secret_files),
        }

    def to_runtime_summary(self) -> dict[str, object]:
        return {
            "leaseId": self.lease.lease_id,
            "delivery": self.lease.delivery,
            "cleanupOnExit": self.lease.cleanup_on_exit,
            "cleanupOnRead": self.lease.cleanup_on_read,
            "secretRefCount": len(self.secret_files),
        }


def prepare_materialization_bundle(
    lease: MaterializationLease,
    *,
    secret_bindings: Mapping[str, str],
    base_dir: str = "",
) -> MaterializationBundle:
    root = _materialization_root(base_dir)
    bundle_root = root / lease.lease_id
    bundle_root.mkdir(parents=True, exist_ok=True)
    os.chmod(bundle_root, 0o700)

    secret_files: dict[str, str] = {}
    if lease.delivery == "temp-file":
        for secret_ref, value in secret_bindings.items():
            safe_secret_ref = normalize_secret_ref(secret_ref, field_name="secret_ref")
            file_path = bundle_root / f"{safe_secret_ref}.secret"
            file_path.write_text(str(value), encoding="utf-8")
            os.chmod(file_path, 0o600)
            secret_files[safe_secret_ref] = str(file_path)

    metadata_path = bundle_root / "lease.json"
    metadata_path.write_text(
        json.dumps(
            {
                "lease": lease.to_dict(),
                "secretFiles": secret_files,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    os.chmod(metadata_path, 0o600)
    return MaterializationBundle(lease=lease, root_path=bundle_root, secret_files=secret_files)


def read_materialized_secret_from_context(context: Mapping[str, object], secret_ref: str) -> str:
    secret_files = context.get("secretFiles", {})
    if not isinstance(secret_files, Mapping):
        raise FileNotFoundError("materialization secret files are unavailable")
    path = Path(str(secret_files.get(secret_ref, "") or ""))
    if not path:
        raise FileNotFoundError(f"materialized secret {secret_ref!r} was not found")
    value = path.read_text(encoding="utf-8")
    if bool(context.get("cleanupOnRead", False)):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    return value


def cleanup_materialization_bundle(bundle_or_context: MaterializationBundle | Mapping[str, object]) -> dict[str, object]:
    if isinstance(bundle_or_context, MaterializationBundle):
        lease_id = bundle_or_context.lease.lease_id
        root_path = bundle_or_context.root_path
    else:
        lease_id = str(bundle_or_context.get("leaseId", "") or "")
        root_path = Path(str(bundle_or_context.get("rootPath", "") or "")).expanduser()
    existed = root_path.exists()
    shutil.rmtree(root_path, ignore_errors=True)
    return {
        "leaseId": lease_id,
        "removed": existed and not root_path.exists(),
        "rootPath": str(root_path),
    }


def cleanup_expired_materializations(*, base_dir: str = "") -> dict[str, object]:
    root = _materialization_root(base_dir)
    if not root.exists():
        return {"expiredLeasesRemoved": 0, "leaseIds": []}
    now = datetime.now(timezone.utc)
    removed: list[str] = []
    for bundle_root in sorted(path for path in root.iterdir() if path.is_dir()):
        metadata_path = bundle_root / "lease.json"
        if not metadata_path.exists():
            shutil.rmtree(bundle_root, ignore_errors=True)
            removed.append(bundle_root.name)
            continue
        try:
            payload = json.loads(metadata_path.read_text(encoding="utf-8"))
            expires_at = _parse_utc(str(payload["lease"]["expiresAt"]))
        except Exception:
            shutil.rmtree(bundle_root, ignore_errors=True)
            removed.append(bundle_root.name)
            continue
        if expires_at <= now:
            shutil.rmtree(bundle_root, ignore_errors=True)
            removed.append(bundle_root.name)
    return {"expiredLeasesRemoved": len(removed), "leaseIds": removed}
