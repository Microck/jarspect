from __future__ import annotations

import json
import re
from pathlib import Path

from mod_sentinel.models.scan import ScanResult


_SCAN_ID_PATTERN = re.compile(r"^[a-f0-9]{32}$")


class ScanStore:
    def __init__(
        self,
        *,
        base_dir: str | Path = ".local-data/scans",
        persist_to_disk: bool = True,
    ) -> None:
        self._persist_to_disk = persist_to_disk
        self._base_dir = Path(base_dir)
        self._memory: dict[str, ScanResult] = {}

        if self._persist_to_disk:
            self._base_dir.mkdir(parents=True, exist_ok=True)

    def save_scan(self, scan_id: str, result: ScanResult) -> None:
        normalized_id = _normalize_scan_id(scan_id)
        self._memory[normalized_id] = result

        if not self._persist_to_disk:
            return

        payload = {
            "scan_id": normalized_id,
            "result": result.model_dump(mode="json"),
        }
        self._path_for_scan(normalized_id).write_text(
            json.dumps(payload, indent=2),
            encoding="utf-8",
        )

    def get_scan(self, scan_id: str) -> ScanResult | None:
        normalized_id = _normalize_scan_id(scan_id)

        cached = self._memory.get(normalized_id)
        if cached is not None:
            return cached

        if not self._persist_to_disk:
            return None

        path = self._path_for_scan(normalized_id)
        if not path.exists():
            return None

        payload = json.loads(path.read_text(encoding="utf-8"))
        result = ScanResult.model_validate(payload.get("result", {}))
        self._memory[normalized_id] = result
        return result

    def _path_for_scan(self, scan_id: str) -> Path:
        return self._base_dir / f"{scan_id}.json"


def _normalize_scan_id(scan_id: str) -> str:
    candidate = scan_id.strip().lower()
    if not _SCAN_ID_PATTERN.fullmatch(candidate):
        raise ValueError("scan_id must be a 32-character hex uuid string")
    return candidate
