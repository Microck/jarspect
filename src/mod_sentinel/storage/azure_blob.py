from __future__ import annotations

from mod_sentinel.storage.base import (
    StorageBackend,
    StoredObject,
    normalize_storage_key,
)


class AzureBlobStorage(StorageBackend):
    def __init__(
        self,
        connection_string: str | None,
        container_name: str | None,
    ) -> None:
        if not connection_string:
            raise ValueError(
                "AZURE_STORAGE_CONNECTION_STRING is required for azure_blob backend"
            )
        if not container_name:
            raise ValueError(
                "AZURE_STORAGE_CONTAINER is required for azure_blob backend"
            )

        try:
            from azure.storage.blob import BlobServiceClient
        except ImportError as exc:
            raise RuntimeError(
                "azure-storage-blob dependency is required for azure_blob backend"
            ) from exc

        self._service = BlobServiceClient.from_connection_string(connection_string)
        self._container = self._service.get_container_client(container_name)

    def save_bytes(
        self, key: str, content_type: str | None, data: bytes
    ) -> StoredObject:
        normalized = normalize_storage_key(key)
        blob = self._container.get_blob_client(normalized)
        blob.upload_blob(data, overwrite=True, content_type=content_type)
        return StoredObject(
            key=normalized,
            size_bytes=len(data),
            content_type=content_type,
            url=blob.url,
        )

    def get_bytes(self, key: str) -> bytes:
        normalized = normalize_storage_key(key)
        blob = self._container.get_blob_client(normalized)
        return blob.download_blob().readall()

    def get_url(self, key: str) -> str | None:
        normalized = normalize_storage_key(key)
        return self._container.get_blob_client(normalized).url
