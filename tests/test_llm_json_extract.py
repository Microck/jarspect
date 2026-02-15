from __future__ import annotations

from mod_sentinel.llm.json_extract import extract_first_json_object


def test_extract_pure_json() -> None:
    payload = extract_first_json_object('{"risk_summary":"ok","confidence":0.5}')
    assert payload["risk_summary"] == "ok"


def test_extract_markdown_fenced_json() -> None:
    text = 'Model output:\n```json\n{"risk_summary":"wrapped","confidence":0.7}\n```'
    payload = extract_first_json_object(text)
    assert payload["risk_summary"] == "wrapped"


def test_extract_json_with_extra_text() -> None:
    text = 'preface... {"risk_summary":"extra","confidence":0.4} ...suffix'
    payload = extract_first_json_object(text)
    assert payload["confidence"] == 0.4
