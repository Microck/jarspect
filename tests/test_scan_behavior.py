from __future__ import annotations

from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

import pytest
from fastapi.testclient import TestClient

from mod_sentinel.api.main import app
from mod_sentinel.settings import reset_settings_cache


@pytest.fixture(autouse=True)
def _reset_settings_between_tests() -> None:
    reset_settings_cache()
    yield
    reset_settings_cache()


def _configure_local(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("STORAGE_BACKEND", "local")
    monkeypatch.setenv("LOCAL_STORAGE_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("LLM_PROVIDER", "stub")


def _build_behavior_jar() -> bytes:
    class_bytes = (
        b"\xca\xfe\xba\xbejava.net.URLConnectionRuntime.getRuntime().execFiles.write"
    )
    buffer = BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr("com/example/Behavior.class", class_bytes)
    return buffer.getvalue()


def test_scan_includes_behavior_prediction(monkeypatch, tmp_path: Path) -> None:
    _configure_local(monkeypatch, tmp_path)
    client = TestClient(app)

    upload_response = client.post(
        "/upload",
        files={
            "file": ("behavior.jar", _build_behavior_jar(), "application/java-archive")
        },
    )
    assert upload_response.status_code == 200
    upload_id = upload_response.json()["upload_id"]

    scan_response = client.post("/scan", json={"upload_id": upload_id})
    assert scan_response.status_code == 200
    payload = scan_response.json()

    assert payload["intake"]["upload_id"] == upload_id
    assert payload["static"]["matches"]
    assert payload["behavior"]["risk_summary"]
    assert "network" in payload["behavior"]
