from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import PurePosixPath


@dataclass(frozen=True)
class StoredObject:
    key: str
    size_bytes: int
    content_type: str | None = None
    url: str | None = None


def normalize_storage_key(raw_key: str) -> str:
    cleaned = raw_key.strip().replace("\\", "/")
    if not cleaned:
        raise ValueError("Storage key cannot be empty")

    normalized = str(PurePosixPath(cleaned))
    if normalized.startswith("/") or normalized.startswith("../"):
        raise ValueError("Storage key cannot be absolute or parent-relative")
    if "/../" in f"/{normalized}" or normalized == "..":
        raise ValueError("Storage key cannot contain parent traversal")
    return normalized


class StorageBackend(ABC):
    @abstractmethod
    def save_bytes(
        self, key: str, content_type: str | None, data: bytes
    ) -> StoredObject:
        """Persist bytes under key and return metadata."""

    @abstractmethod
    def get_bytes(self, key: str) -> bytes:
        """Load raw bytes by key."""

    @abstractmethod
    def get_url(self, key: str) -> str | None:
        """Return externally reachable URL if supported."""
