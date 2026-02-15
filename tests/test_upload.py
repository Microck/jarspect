from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from mod_sentinel.api.main import app
from mod_sentinel.settings import reset_settings_cache


@pytest.fixture(autouse=True)
def _reset_settings_between_tests() -> None:
    reset_settings_cache()
    yield
    reset_settings_cache()


def _set_local_storage(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("STORAGE_BACKEND", "local")
    monkeypatch.setenv("LOCAL_STORAGE_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("UPLOAD_MAX_BYTES", "1024")
    reset_settings_cache()


def test_upload_jar_success(monkeypatch, tmp_path: Path) -> None:
    _set_local_storage(monkeypatch, tmp_path)
    client = TestClient(app)

    response = client.post(
        "/upload",
        files={
            "file": (
                "demo.jar",
                b"PK\x03\x04fake-jar-content",
                "application/java-archive",
            )
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["upload_id"]
    assert payload["filename"] == "demo.jar"
    assert payload["size_bytes"] > 0
    stored_path = tmp_path / "uploads" / "uploads" / f"{payload['upload_id']}.jar"
    assert stored_path.exists()


def test_upload_rejects_non_jar(monkeypatch, tmp_path: Path) -> None:
    _set_local_storage(monkeypatch, tmp_path)
    client = TestClient(app)

    response = client.post(
        "/upload",
        files={"file": ("demo.txt", b"not-a-jar", "text/plain")},
    )

    assert response.status_code == 400
    assert ".jar" in response.json()["detail"]
