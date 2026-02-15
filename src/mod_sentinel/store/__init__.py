from __future__ import annotations

import os

from mod_sentinel.store.reputation_fixtures import ReputationFixtureStore
from mod_sentinel.store.scans import ScanStore

_SCAN_STORES: dict[tuple[str, bool], ScanStore] = {}


def get_scan_store() -> ScanStore:
    base_dir = os.getenv("SCAN_STORE_DIR", ".local-data/scans")
    persist_raw = os.getenv("SCAN_STORE_PERSIST", "true").strip().lower()
    persist_to_disk = persist_raw not in {"0", "false", "no", "off"}

    cache_key = (base_dir, persist_to_disk)
    if cache_key not in _SCAN_STORES:
        _SCAN_STORES[cache_key] = ScanStore(
            base_dir=base_dir,
            persist_to_disk=persist_to_disk,
        )
    return _SCAN_STORES[cache_key]


__all__ = ["get_scan_store", "ReputationFixtureStore", "ScanStore"]
