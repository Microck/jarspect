from __future__ import annotations

from uuid import uuid4

from fastapi import APIRouter, File, HTTPException, UploadFile

from mod_sentinel.settings import get_settings
from mod_sentinel.storage import get_storage_backend


router = APIRouter()


async def _read_limited(upload_file: UploadFile, max_bytes: int) -> tuple[bytes, int]:
    total = 0
    chunks: list[bytes] = []
    while True:
        chunk = await upload_file.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise HTTPException(
                status_code=413, detail="Uploaded file exceeds max size"
            )
        chunks.append(chunk)
    return b"".join(chunks), total


@router.post("/upload")
async def upload_mod(file: UploadFile = File(...)) -> dict[str, str | int | None]:
    filename = file.filename or ""
    if not filename.lower().endswith(".jar"):
        raise HTTPException(status_code=400, detail="Only .jar files are supported")

    settings = get_settings()
    content, size_bytes = await _read_limited(file, settings.upload_max_bytes)

    upload_id = uuid4().hex
    storage_key = f"uploads/{upload_id}.jar"

    storage = get_storage_backend(settings)
    stored = storage.save_bytes(storage_key, file.content_type, content)

    return {
        "upload_id": upload_id,
        "filename": filename,
        "size_bytes": size_bytes,
        "storage_url": stored.url,
    }
