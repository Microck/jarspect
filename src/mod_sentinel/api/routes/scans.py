from __future__ import annotations

from fastapi import APIRouter, HTTPException

from mod_sentinel.models.scan import ScanRunResponse
from mod_sentinel.store import get_scan_store


router = APIRouter()


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str) -> dict[str, object]:
    store = get_scan_store()
    try:
        result = store.get_scan(scan_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanRunResponse(scan_id=scan_id, result=result).model_dump(exclude_none=True)
