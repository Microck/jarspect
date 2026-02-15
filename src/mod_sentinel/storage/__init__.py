from __future__ import annotations

from mod_sentinel.settings import Settings, get_settings
from mod_sentinel.storage.base import StorageBackend
from mod_sentinel.storage.local import LocalStorage


def get_storage_backend(settings: Settings | None = None) -> StorageBackend:
    active_settings = settings or get_settings()

    if active_settings.storage_backend == "local":
        return LocalStorage(active_settings.local_storage_dir)

    if active_settings.storage_backend == "azure_blob":
        from mod_sentinel.storage.azure_blob import AzureBlobStorage

        return AzureBlobStorage(
            connection_string=active_settings.azure_storage_connection_string,
            container_name=active_settings.azure_storage_container,
        )

    raise ValueError(
        f"Unsupported storage backend '{active_settings.storage_backend}'. "
        "Expected one of: local, azure_blob"
    )


__all__ = ["get_storage_backend", "StorageBackend"]
