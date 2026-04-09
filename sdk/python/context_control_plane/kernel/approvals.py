from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping
from uuid import uuid4

APPROVAL_API_VERSION = "ccp.io/runtime/v1beta1"
APPROVAL_KIND = "ApprovalReceipt"
APPROVAL_SIGNING_KEY_ENV = "CCP_APPROVAL_SIGNING_KEY"
APPROVAL_SIGNING_KEY_FILE_ENV = "CCP_APPROVAL_SIGNING_KEY_FILE"
APPROVAL_SIGNING_KEY_PATH_ENV = "CCP_APPROVAL_SIGNING_KEY_PATH"
APPROVAL_SIGNING_ISSUER_ENV = "CCP_APPROVAL_SIGNING_ISSUER"


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    normalized = str(value or "").strip()
    if not normalized:
        raise ValueError("approval receipt timestamp is required")
    return datetime.fromisoformat(normalized.replace("Z", "+00:00")).astimezone(timezone.utc)


def _approval_key_path() -> Path:
    configured = str(os.environ.get(APPROVAL_SIGNING_KEY_PATH_ENV, "") or "").strip()
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".ccp-core" / "approval-signing.key"


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _binding_digest(binding: Mapping[str, Any] | None) -> str:
    payload = dict(binding or {})
    if not payload:
        return ""
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _signing_key(*, create_if_missing: bool) -> bytes:
    inline = str(os.environ.get(APPROVAL_SIGNING_KEY_ENV, "") or "").strip()
    if inline:
        return inline.encode("utf-8")

    file_override = str(os.environ.get(APPROVAL_SIGNING_KEY_FILE_ENV, "") or "").strip()
    key_path = Path(file_override).expanduser() if file_override else _approval_key_path()
    if not key_path.exists():
        if not create_if_missing:
            raise ValueError(
                "approval signing key is not configured; set CCP_APPROVAL_SIGNING_KEY, "
                "CCP_APPROVAL_SIGNING_KEY_FILE, or create the default local signer"
            )
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_text(secrets.token_hex(32), encoding="utf-8")
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass
    key_value = key_path.read_text(encoding="utf-8").strip()
    if not key_value:
        raise ValueError(f"approval signing key file is empty: {key_path}")
    return key_value.encode("utf-8")


def _approval_issuer() -> str:
    configured = str(os.environ.get(APPROVAL_SIGNING_ISSUER_ENV, "") or "").strip()
    if configured:
        return configured
    if str(os.environ.get(APPROVAL_SIGNING_KEY_ENV, "") or "").strip():
        return "env-hmac"
    if str(os.environ.get(APPROVAL_SIGNING_KEY_FILE_ENV, "") or "").strip():
        return "file-hmac"
    return "local-file-hmac"


def _receipt_signing_payload(receipt: "ApprovalReceiptRecord") -> Mapping[str, Any]:
    return {
        "approvalId": receipt.approval_id,
        "subject": {
            "kind": receipt.subject_kind,
            "name": receipt.subject_name,
            "namespace": receipt.namespace,
        },
        "access": receipt.access,
        "mode": receipt.mode,
        "operation": receipt.operation,
        "approvedBy": receipt.approved_by,
        "issuedAt": receipt.issued_at,
        "expiresAt": receipt.expires_at,
        "reason": receipt.reason,
        "metadata": dict(receipt.metadata),
        "bindingDigest": receipt.binding_digest,
        "issuer": receipt.issuer,
    }


def _sign_receipt(receipt: "ApprovalReceiptRecord", *, create_if_missing: bool) -> str:
    key = _signing_key(create_if_missing=create_if_missing)
    payload = _canonical_json(_receipt_signing_payload(receipt)).encode("utf-8")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def _verify_signature(receipt: "ApprovalReceiptRecord") -> bool:
    if not receipt.signature:
        return False
    try:
        expected = _sign_receipt(receipt, create_if_missing=False)
    except ValueError:
        return False
    return hmac.compare_digest(receipt.signature, expected)


@dataclass(frozen=True)
class ApprovalReceiptRecord:
    approval_id: str
    subject_kind: str
    subject_name: str
    namespace: str
    access: str
    mode: str
    operation: str
    approved_by: str
    issued_at: str
    expires_at: str
    binding_digest: str = ""
    issuer: str = ""
    signature: str = ""
    reason: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "apiVersion": APPROVAL_API_VERSION,
            "kind": APPROVAL_KIND,
            "metadata": {
                "name": self.approval_id,
                "namespace": self.namespace,
            },
            "spec": {
                "subject": {
                    "kind": self.subject_kind,
                    "name": self.subject_name,
                    "namespace": self.namespace,
                },
                "access": self.access,
                "mode": self.mode,
                "operation": self.operation,
                "approvedBy": self.approved_by,
                "issuedAt": self.issued_at,
                "expiresAt": self.expires_at,
                "bindingDigest": self.binding_digest,
                "issuer": self.issuer,
                "signature": self.signature,
                "reason": self.reason,
                "metadata": dict(self.metadata),
            },
            "source": self.source,
        }


def build_approval_receipt(payload: Mapping[str, Any], *, source: str = "") -> ApprovalReceiptRecord:
    if not isinstance(payload, Mapping):
        raise ValueError("approval receipt must be a JSON object")
    api_version = str(payload.get("apiVersion", "") or "").strip()
    if api_version != APPROVAL_API_VERSION:
        raise ValueError(f"approval receipt must declare apiVersion {APPROVAL_API_VERSION!r}")
    kind = str(payload.get("kind", "") or "").strip()
    if kind != APPROVAL_KIND:
        raise ValueError(f"approval receipt must declare kind {APPROVAL_KIND!r}")

    metadata = payload.get("metadata", {})
    if not isinstance(metadata, Mapping):
        raise ValueError("approval receipt metadata must be a JSON object")
    approval_id = str(metadata.get("name", "") or "").strip()
    namespace = str(metadata.get("namespace", "default") or "default").strip() or "default"
    if not approval_id:
        raise ValueError("approval receipt metadata.name is required")

    spec = payload.get("spec", {})
    if not isinstance(spec, Mapping):
        raise ValueError("approval receipt spec must be a JSON object")
    subject = spec.get("subject", {})
    if not isinstance(subject, Mapping):
        raise ValueError("approval receipt spec.subject must be a JSON object")

    subject_kind = str(subject.get("kind", "") or "").strip()
    subject_name = str(subject.get("name", "") or "").strip()
    subject_namespace = str(subject.get("namespace", namespace) or namespace).strip() or namespace
    access = str(spec.get("access", "") or "").strip().lower()
    mode = str(spec.get("mode", "") or "").strip().lower()
    operation = str(spec.get("operation", "") or "").strip()
    approved_by = str(spec.get("approvedBy", "") or "").strip()
    issued_at = str(spec.get("issuedAt", "") or "").strip()
    expires_at = str(spec.get("expiresAt", "") or "").strip()
    binding_digest = str(spec.get("bindingDigest", "") or "").strip()
    issuer = str(spec.get("issuer", "") or "").strip()
    signature = str(spec.get("signature", "") or "").strip()
    reason = str(spec.get("reason", "") or "").strip()
    receipt_metadata = spec.get("metadata", {})
    if receipt_metadata in (None, ""):
        receipt_metadata = {}
    if not isinstance(receipt_metadata, Mapping):
        raise ValueError("approval receipt spec.metadata must be a JSON object when provided")

    if not subject_kind or not subject_name:
        raise ValueError("approval receipt subject.kind and subject.name are required")
    if not access:
        raise ValueError("approval receipt spec.access is required")
    if not mode:
        raise ValueError("approval receipt spec.mode is required")
    if not operation:
        raise ValueError("approval receipt spec.operation is required")
    if not approved_by:
        raise ValueError("approval receipt spec.approvedBy is required")
    if not issued_at:
        raise ValueError("approval receipt spec.issuedAt is required")
    if not expires_at:
        raise ValueError("approval receipt spec.expiresAt is required")

    _parse_timestamp(issued_at)
    _parse_timestamp(expires_at)

    return ApprovalReceiptRecord(
        approval_id=approval_id,
        subject_kind=subject_kind,
        subject_name=subject_name,
        namespace=subject_namespace,
        access=access,
        mode=mode,
        operation=operation,
        approved_by=approved_by,
        issued_at=issued_at,
        expires_at=expires_at,
        binding_digest=binding_digest,
        issuer=issuer,
        signature=signature,
        reason=reason,
        metadata=dict(receipt_metadata),
        source=source,
    )


def issue_approval_receipt(
    *,
    subject_kind: str,
    subject_name: str,
    namespace: str = "default",
    access: str,
    mode: str,
    operation: str,
    approved_by: str,
    reason: str = "",
    ttl_minutes: int = 60,
    metadata: Mapping[str, Any] | None = None,
    binding: Mapping[str, Any] | None = None,
) -> ApprovalReceiptRecord:
    issued_at = _now_utc()
    expires_at = issued_at + timedelta(minutes=max(int(ttl_minutes), 1))
    receipt = ApprovalReceiptRecord(
        approval_id=f"apr_{uuid4().hex[:12]}",
        subject_kind=str(subject_kind or "").strip(),
        subject_name=str(subject_name or "").strip(),
        namespace=str(namespace or "default").strip() or "default",
        access=str(access or "").strip().lower(),
        mode=str(mode or "").strip().lower(),
        operation=str(operation or "").strip(),
        approved_by=str(approved_by or "").strip(),
        issued_at=_format_timestamp(issued_at),
        expires_at=_format_timestamp(expires_at),
        binding_digest=_binding_digest(binding),
        issuer=_approval_issuer(),
        reason=str(reason or "").strip(),
        metadata=dict(metadata or {}),
    )
    signature = _sign_receipt(receipt, create_if_missing=True)
    return ApprovalReceiptRecord(
        approval_id=receipt.approval_id,
        subject_kind=receipt.subject_kind,
        subject_name=receipt.subject_name,
        namespace=receipt.namespace,
        access=receipt.access,
        mode=receipt.mode,
        operation=receipt.operation,
        approved_by=receipt.approved_by,
        issued_at=receipt.issued_at,
        expires_at=receipt.expires_at,
        binding_digest=receipt.binding_digest,
        issuer=receipt.issuer,
        signature=signature,
        reason=receipt.reason,
        metadata=receipt.metadata,
    )


def load_approval_receipt_file(path: str | Path) -> ApprovalReceiptRecord:
    file_path = Path(path)
    try:
        payload = json.loads(file_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"approval receipt file does not exist: {file_path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in approval receipt {file_path}: {exc}") from exc
    return build_approval_receipt(payload, source=str(file_path))


def save_approval_receipt_file(receipt: ApprovalReceiptRecord, path: str | Path) -> str:
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(json.dumps(receipt.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    return str(file_path)


def validate_approval_receipt(
    receipt: ApprovalReceiptRecord,
    *,
    subject_kind: str,
    subject_name: str,
    namespace: str,
    access: str,
    mode: str,
    operation: str,
    binding: Mapping[str, Any] | None = None,
) -> tuple[bool, str]:
    if receipt.subject_kind != str(subject_kind or "").strip():
        return False, "approval receipt subject kind does not match the requested resource"
    if receipt.subject_name != str(subject_name or "").strip():
        return False, "approval receipt subject name does not match the requested resource"
    if receipt.namespace != str(namespace or "default").strip():
        return False, "approval receipt namespace does not match the requested resource"
    if receipt.access != str(access or "").strip().lower():
        return False, "approval receipt access does not match the requested access level"
    if receipt.mode != str(mode or "").strip().lower():
        return False, "approval receipt mode does not match the requested connection mode"
    if receipt.operation != str(operation or "").strip():
        return False, "approval receipt operation does not match the requested execution plan"
    expected_binding = _binding_digest(binding)
    if receipt.binding_digest != expected_binding:
        return False, "approval receipt binding does not match the requested connection context"
    if not receipt.issuer:
        return False, "approval receipt issuer is missing"
    if not _verify_signature(receipt):
        return False, "approval receipt signature is invalid"
    if _parse_timestamp(receipt.expires_at) <= _now_utc():
        return False, "approval receipt has expired"
    return True, "approval receipt is valid"
