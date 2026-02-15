from __future__ import annotations

from collections.abc import Iterator
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

import pytest
from fastapi.testclient import TestClient

from mod_sentinel.api.main import app
from mod_sentinel.analysis.jar_extract import inspect_jar_bytes
from mod_sentinel.settings import reset_settings_cache


@pytest.fixture(autouse=True)
def _reset_settings_between_tests() -> Iterator[None]:
    reset_settings_cache()
    yield
    reset_settings_cache()


def _build_jar(entries: dict[str, bytes]) -> bytes:
    buffer = BytesIO()
    with ZipFile(buffer, "w") as archive:
        for path, content in entries.items():
            archive.writestr(path, content)
    return buffer.getvalue()


def test_inspect_jar_detects_fabric_loader() -> None:
    jar_bytes = _build_jar(
        {
            "fabric.mod.json": b"{}",
            "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\nImplementation-Title: Demo\n",
            "com/example/Demo.class": b"class-bytes",
        }
    )

    inspection = inspect_jar_bytes(jar_bytes)
    assert inspection.loader == "fabric"
    assert inspection.file_count == 3
    assert "META-INF" in inspection.top_level_entries
    assert inspection.manifest.get("Implementation-Title") == "Demo"


def test_inspect_jar_rejects_path_traversal_entry() -> None:
    jar_bytes = _build_jar({"../../evil.class": b"x"})

    with pytest.raises(ValueError):
        inspect_jar_bytes(jar_bytes)


def _configure_local_storage(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("STORAGE_BACKEND", "local")
    monkeypatch.setenv("LOCAL_STORAGE_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("SCAN_STORE_DIR", str(tmp_path / "scans"))


def _upload_jar(client: TestClient, filename: str, content: bytes) -> str:
    upload_response = client.post(
        "/upload",
        files={"file": (filename, content, "application/java-archive")},
    )
    assert upload_response.status_code == 200
    return upload_response.json()["upload_id"]


def test_scan_detects_fabric_loader(monkeypatch, tmp_path: Path) -> None:
    _configure_local_storage(monkeypatch, tmp_path)
    client = TestClient(app)

    jar_bytes = _build_jar(
        {"fabric.mod.json": b"{}", "com/example/Fabric.class": b"class"}
    )
    upload_id = _upload_jar(client, "fabric.jar", jar_bytes)

    scan_response = client.post("/scan", json={"upload_id": upload_id})
    assert scan_response.status_code == 200
    assert scan_response.json()["result"]["intake"]["loader"] == "fabric"


def test_scan_detects_forge_loader(monkeypatch, tmp_path: Path) -> None:
    _configure_local_storage(monkeypatch, tmp_path)
    client = TestClient(app)

    jar_bytes = _build_jar(
        {"META-INF/mods.toml": b'modLoader="javafml"', "Demo.class": b"class"}
    )
    upload_id = _upload_jar(client, "forge.jar", jar_bytes)

    scan_response = client.post("/scan", json={"upload_id": upload_id})
    assert scan_response.status_code == 200
    assert scan_response.json()["result"]["intake"]["loader"] == "forge"
