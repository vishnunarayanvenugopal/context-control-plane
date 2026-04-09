from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class CompatibilityLevel(str, Enum):
    EXPERIMENTAL = "experimental"
    BETA = "beta"
    STABLE = "stable"


@dataclass(frozen=True)
class ContractVersion:
    name: str
    version: str
    stability: CompatibilityLevel = CompatibilityLevel.EXPERIMENTAL

    def to_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "version": self.version,
            "stability": self.stability.value,
        }


@dataclass(frozen=True)
class Capability:
    name: str
    version: str
    stability: CompatibilityLevel = CompatibilityLevel.EXPERIMENTAL
    description: str = ""

    @property
    def capability_id(self) -> str:
        return f"{self.name}/{self.version}"

    def to_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "version": self.version,
            "stability": self.stability.value,
            "description": self.description,
            "capability_id": self.capability_id,
        }
