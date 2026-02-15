from __future__ import annotations

from collections.abc import Iterator
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

import pytest
from fastapi.testclient import TestClient

from mod_sentinel.api.main import app
from mod_sentinel.agents.reputation_agent import ReputationAgent
from mod_sentinel.models.reputation import AuthorMetadata
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


def _build_simple_jar() -> bytes:
    class_bytes = b"\xca\xfe\xba\xbejava.net.URLConnectionRuntime.getRuntime().exec"
    buffer = BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr("com/example/Reputation.class", class_bytes)
    return buffer.getvalue()


def test_reputation_prefers_fixture_data_over_request_overrides() -> None:
    agent = ReputationAgent()

    result = agent.score_author(
        AuthorMetadata(
            author_id="new_creator",
            mod_id="demo-suspicious",
            account_age_days=9999,
            prior_mod_count=999,
            report_count=0,
        )
    )

    assert result.account_age_days == 14
    assert result.prior_mod_count == 1
    assert result.report_count == 4
    assert result.report_reasons
    assert result.author_score < 0.3
    assert any("fixture" in line.lower() for line in result.rationale)


def test_reputation_falls_back_to_provided_metadata_when_fixture_missing() -> None:
    agent = ReputationAgent()

    result = agent.score_author(
        AuthorMetadata(
            author_id="unknown_author",
            account_age_days=180,
            prior_mod_count=5,
            report_count=1,
        )
    )

    assert result.account_age_days == 180
    assert result.prior_mod_count == 5
    assert result.report_count == 1
    assert 0.0 <= result.author_score <= 1.0
    assert any("No fixture" in line for line in result.rationale)


def test_reputation_scoring_is_deterministic() -> None:
    agent = ReputationAgent()
    metadata = AuthorMetadata(author_id="borderline_creator", mod_id="demo-clean")

    first = agent.score_author(metadata)
    second = agent.score_author(metadata)

    assert first.author_score == second.author_score
    assert first.rationale == second.rationale


def test_scan_includes_reputation_when_author_metadata_provided(
    monkeypatch, tmp_path: Path
) -> None:
    _configure_local(monkeypatch, tmp_path)
    client = TestClient(app)

    upload_response = client.post(
        "/upload",
        files={
            "file": (
                "reputation.jar",
                _build_simple_jar(),
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
                "account_age_days": 3000,
                "prior_mod_count": 300,
                "report_count": 0,
            },
        },
    )

    assert scan_response.status_code == 200
    payload = scan_response.json()
    result = payload["result"]
    assert payload["scan_id"]
    assert result["reputation"]["author_id"] == "new_creator"
    assert result["reputation"]["account_age_days"] == 14
    assert result["reputation"]["report_count"] == 4
