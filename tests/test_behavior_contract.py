from __future__ import annotations

from mod_sentinel.llm.behavior_contract import normalize_behavior_payload


def test_behavior_contract_normalizes_partial_payload() -> None:
    normalized = normalize_behavior_payload(
        {
            "network": {"urls": "https://demo.example.invalid", "ports": [443, "8080"]},
            "risk_summary": "Network behavior observed",
            "confidence": 0.8,
        }
    )

    assert normalized["network"]["urls"] == ["https://demo.example.invalid"]
    assert normalized["network"]["ports"] == [443, 8080]
    assert normalized["file_system"]["reads"] == []
    assert normalized["persistence"]["confidence"] == 0.0


def test_behavior_contract_degrades_invalid_sections_to_unknown() -> None:
    normalized = normalize_behavior_payload(
        {
            "file_system": "invalid",
            "network": {"urls": [None], "confidence": 9},
            "persistence": {"likely": "yes"},
            "risk_summary": 123,
            "confidence": "high",
        }
    )

    assert normalized["file_system"]["rationale"] == "unknown"
    assert normalized["network"]["confidence"] == 0.0
    assert normalized["persistence"]["likely"] is False
    assert normalized["risk_summary"] == "unknown"
    assert normalized["confidence"] == 0.0
