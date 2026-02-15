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


def _configure_local_storage(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("STORAGE_BACKEND", "local")
    monkeypatch.setenv("LOCAL_STORAGE_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("SCAN_STORE_DIR", str(tmp_path / "scans"))


def _build_suspicious_jar() -> bytes:
    class_bytes = (
        b"\xca\xfe\xba\xbe"
        b"java.net.URLConnection"
        b"Runtime.getRuntime().exec"
        b"QWxhZGRpbjpvcGVuIHNlc2FtZQQWxhZGRpbjpvcGVuIHNlc2FtZQQWxhZGRpbjpvcGVuIHNlc2FtZQ"
    )
    buffer = BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr("com/example/Suspicious.class", class_bytes)
    return buffer.getvalue()


def test_scan_returns_static_matches(monkeypatch, tmp_path: Path) -> None:
    _configure_local_storage(monkeypatch, tmp_path)
    client = TestClient(app)

    upload_response = client.post(
        "/upload",
        files={
            "file": (
                "suspicious.jar",
                _build_suspicious_jar(),
                "application/java-archive",
            )
        },
    )
    assert upload_response.status_code == 200
    upload_id = upload_response.json()["upload_id"]

    scan_response = client.post("/scan", json={"upload_id": upload_id})
    assert scan_response.status_code == 200
    payload = scan_response.json()
    result = payload["result"]
    matched_ids = {match["id"] for match in result["static"]["matches"]}

    assert payload["scan_id"]
    assert result["intake"]["upload_id"] == upload_id
    assert result["static"]["matches"]
    assert "NET-URLCONNECTION" in matched_ids or "EXEC-RUNTIME" in matched_ids
