from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from .resource_registry import ResourceDocument, ResourceRegistry

_ALLOWED_DECISIONS = frozenset({"allow", "deny", "approval_required"})


class GatewayConfigurationError(ValueError):
    """Raised when a GatewayPolicy resource is malformed."""


def _mapping(value: Any, *, field_name: str) -> Mapping[str, Any]:
    if value in (None, ""):
        return {}
    if not isinstance(value, Mapping):
        raise GatewayConfigurationError(f"{field_name} must be a JSON object when provided")
    return value


def _mapping_list(value: Any, *, field_name: str) -> tuple[Mapping[str, Any], ...]:
    if value in (None, ""):
        return ()
    if not isinstance(value, list):
        raise GatewayConfigurationError(f"{field_name} must be a JSON array when provided")
    normalized: list[Mapping[str, Any]] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise GatewayConfigurationError(f"{field_name} entries must be JSON objects")
        normalized.append({str(key): item[key] for key in item})
    return tuple(normalized)


def _normalize_decision(raw: Any, *, field_name: str) -> str:
    value = str(raw or "").strip().lower()
    if not value:
        raise GatewayConfigurationError(f"{field_name} must not be empty")
    if value not in _ALLOWED_DECISIONS:
        raise GatewayConfigurationError(f"unsupported gateway decision {value!r}")
    return value


@dataclass(frozen=True)
class GatewayRule:
    match: Mapping[str, Any]
    decision: str
    reason: str = ""

    def matches(
        self,
        *,
        access: str,
        classification: str,
        mode: str,
        operation: str,
        namespace: str,
    ) -> bool:
        expectations = {
            "access": access,
            "classification": classification,
            "mode": mode,
            "namespace": namespace,
        }
        for key, actual in expectations.items():
            if key in self.match:
                expected = str(self.match.get(key, "") or "").strip().lower()
                if expected and expected != str(actual or "").strip().lower():
                    return False
        if "operationContains" in self.match:
            needle = str(self.match.get("operationContains", "") or "").strip().lower()
            if needle and needle not in str(operation or "").strip().lower():
                return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "match": dict(self.match),
            "decision": self.decision,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class GatewayPolicyProfile:
    name: str
    namespace: str
    default_decision: str
    rules: tuple[GatewayRule, ...] = field(default_factory=tuple)
    classifications: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    source: str = ""

    @classmethod
    def from_document(cls, document: ResourceDocument) -> "GatewayPolicyProfile":
        if document.identifier.kind != "GatewayPolicy":
            raise GatewayConfigurationError("expected a GatewayPolicy resource")
        spec = document.spec
        defaults = _mapping(spec.get("defaults"), field_name="defaults")
        default_decision = _normalize_decision(defaults.get("decision", "allow"), field_name="defaults.decision")
        rules: list[GatewayRule] = []
        for item in _mapping_list(spec.get("rules"), field_name="rules"):
            match = _mapping(item.get("match"), field_name="rules[].match")
            decision = _normalize_decision(item.get("decision"), field_name="rules[].decision")
            rules.append(
                GatewayRule(
                    match={str(key): value for key, value in match.items()},
                    decision=decision,
                    reason=str(item.get("reason", "") or "").strip(),
                )
            )
        classifications_raw = _mapping(spec.get("classifications"), field_name="classifications")
        classifications: dict[str, Mapping[str, Any]] = {}
        for key, value in classifications_raw.items():
            entry = _mapping(value, field_name=f"classifications.{key}")
            classifications[str(key).strip().lower()] = {str(entry_key): entry[entry_key] for entry_key in entry}
        return cls(
            name=document.identifier.name,
            namespace=document.identifier.namespace,
            default_decision=default_decision,
            rules=tuple(rules),
            classifications=classifications,
            source=document.provenance[0].source if document.provenance else "",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "namespace": self.namespace,
            "defaultDecision": self.default_decision,
            "rules": [item.to_dict() for item in self.rules],
            "classifications": {key: dict(value) for key, value in self.classifications.items()},
            "source": self.source,
        }


@dataclass(frozen=True)
class GatewayDecision:
    policy_name: str
    namespace: str
    decision: str
    reason: str
    matched_rule_index: int = -1
    matched_rule: Mapping[str, Any] = field(default_factory=dict)
    requested_access: str = "read"
    requested_classification: str = "internal"
    requested_mode: str = "connect"
    requested_operation: str = ""
    warnings: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy": {
                "name": self.policy_name,
                "namespace": self.namespace,
            },
            "decision": self.decision,
            "reason": self.reason,
            "matchedRuleIndex": self.matched_rule_index,
            "matchedRule": dict(self.matched_rule),
            "requestedAccess": self.requested_access,
            "requestedClassification": self.requested_classification,
            "requestedMode": self.requested_mode,
            "requestedOperation": self.requested_operation,
            "warnings": list(self.warnings),
        }


def build_gateway_status_records(registry: ResourceRegistry, *, namespace: str = "default") -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for document in registry.list_resources(kind="GatewayPolicy", namespace=namespace):
        profile = GatewayPolicyProfile.from_document(document)
        records.append(
            {
                "name": profile.name,
                "namespace": profile.namespace,
                "defaultDecision": profile.default_decision,
                "ruleCount": len(profile.rules),
                "classificationCount": len(profile.classifications),
                "source": profile.source,
            }
        )
    return records


def evaluate_gateway_policy(
    profile: GatewayPolicyProfile,
    *,
    access: str = "read",
    classification: str = "internal",
    mode: str = "connect",
    operation: str = "",
) -> GatewayDecision:
    requested_access = str(access or "read").strip().lower() or "read"
    requested_classification = str(classification or "internal").strip().lower() or "internal"
    requested_mode = str(mode or "connect").strip().lower() or "connect"
    requested_operation = str(operation or "").strip()

    warnings: list[str] = []
    effective_decision = profile.default_decision
    reason = "gateway default decision applies"

    classification_entry = profile.classifications.get(requested_classification, {})
    if "decision" in classification_entry:
        effective_decision = _normalize_decision(
            classification_entry.get("decision"),
            field_name=f"classifications.{requested_classification}.decision",
        )
        reason = f"classification {requested_classification!r} overrides the default decision"
    if "warning" in classification_entry:
        warning = str(classification_entry.get("warning", "") or "").strip()
        if warning:
            warnings.append(warning)

    matched_rule_index = -1
    matched_rule: Mapping[str, Any] = {}
    for index, rule in enumerate(profile.rules):
        if rule.matches(
            access=requested_access,
            classification=requested_classification,
            mode=requested_mode,
            operation=requested_operation,
            namespace=profile.namespace,
        ):
            effective_decision = rule.decision
            reason = rule.reason or f"rule {index} matched the requested gateway context"
            matched_rule_index = index
            matched_rule = rule.to_dict()
            break

    if matched_rule_index == -1 and effective_decision == "approval_required":
        warnings.append("approval-required defaults are active; keep the governed path simple for callers")

    return GatewayDecision(
        policy_name=profile.name,
        namespace=profile.namespace,
        decision=effective_decision,
        reason=reason,
        matched_rule_index=matched_rule_index,
        matched_rule=matched_rule,
        requested_access=requested_access,
        requested_classification=requested_classification,
        requested_mode=requested_mode,
        requested_operation=requested_operation,
        warnings=tuple(warnings),
    )
