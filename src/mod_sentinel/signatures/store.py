from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class SignatureDefinition:
    id: str
    kind: str
    value: str
    severity: str
    description: str


@dataclass(frozen=True)
class SignatureMatch:
    id: str
    severity: str
    description: str
    evidence: str
    offset: int
    end_offset: int


class SignatureStore(ABC):
    @abstractmethod
    def search(self, text: str) -> list[SignatureMatch]:
        """Search text for known suspicious signatures."""
