from __future__ import annotations

from pathlib import Path

from mod_sentinel.storage.base import (
    StorageBackend,
    StoredObject,
    normalize_storage_key,
)


class LocalStorage(StorageBackend):
    def __init__(self, root_dir: str | Path) -> None:
        self._root_dir = Path(root_dir)
        self._root_dir.mkdir(parents=True, exist_ok=True)

    def _path_for_key(self, key: str) -> Path:
        normalized = normalize_storage_key(key)
        destination = (self._root_dir / normalized).resolve()
        root_resolved = self._root_dir.resolve()
        if (
            not str(destination).startswith(f"{root_resolved}/")
            and destination != root_resolved
        ):
            raise ValueError("Storage key escapes local storage root")
        return destination

    def save_bytes(
        self, key: str, content_type: str | None, data: bytes
    ) -> StoredObject:
        destination = self._path_for_key(key)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        return StoredObject(
            key=normalize_storage_key(key),
            size_bytes=len(data),
            content_type=content_type,
            url=None,
        )

    def get_bytes(self, key: str) -> bytes:
        path = self._path_for_key(key)
        return path.read_bytes()

    def get_url(self, key: str) -> str | None:
        _ = normalize_storage_key(key)
        return None
