from __future__ import annotations

from collections.abc import Iterator
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

import pytest
from fastapi.testclient import TestClient

from mod_sentinel.api.main import app
from mod_sentinel.settings import reset_settings_cache


@pytest.fixture(autouse=True)
def _reset_settings_between_tests() -> Iterator[None]:
    reset_settings_cache()
    yield
    reset_settings_cache()


def _configure_local(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("STORAGE_BACKEND", "local")
    monkeypatch.setenv("LOCAL_STORAGE_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("LLM_PROVIDER", "stub")
    monkeypatch.setenv("SCAN_STORE_DIR", str(tmp_path / "scans"))


def _build_sample_jar() -> bytes:
    class_bytes = (
        b"\xca\xfe\xba\xbejava.net.URLConnectionRuntime.getRuntime().execFiles.write"
    )
    buffer = BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr("com/example/FullFlow.class", class_bytes)
    return buffer.getvalue()


def test_upload_scan_and_fetch_by_scan_id(monkeypatch, tmp_path: Path) -> None:
    _configure_local(monkeypatch, tmp_path)
    client = TestClient(app)

    upload_response = client.post(
        "/upload",
        files={
            "file": (
                "full-flow.jar",
                _build_sample_jar(),
                "application/java-archive",
            )
        },
    )
    assert upload_response.status_code == 200
    upload_id = upload_response.json()["upload_id"]

    scan_response = client.post(
        "/scan",
        json={
            "upload_id": upload_id,
            "author": {
                "author_id": "new_creator",
                "mod_id": "demo-suspicious",
            },
        },
    )
    assert scan_response.status_code == 200
    scan_payload = scan_response.json()

    scan_id = scan_payload["scan_id"]
    assert scan_payload["result"]["verdict"]["risk_tier"] in {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }

    get_response = client.get(f"/scans/{scan_id}")
    assert get_response.status_code == 200
    fetched = get_response.json()
    assert fetched["scan_id"] == scan_id
    assert fetched["result"]["intake"]["upload_id"] == upload_id
    assert fetched["result"]["verdict"]["indicators"]
