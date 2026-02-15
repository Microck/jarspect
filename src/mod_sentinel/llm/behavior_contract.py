from __future__ import annotations


def normalize_behavior_payload(raw_payload: dict) -> dict:
    return {
        "file_system": _normalize_file_system(raw_payload.get("file_system")),
        "network": _normalize_network(raw_payload.get("network")),
        "persistence": _normalize_persistence(raw_payload.get("persistence")),
        "risk_summary": _coerce_summary(raw_payload.get("risk_summary")),
        "confidence": _coerce_confidence(raw_payload.get("confidence")),
    }


def _normalize_file_system(raw_section: object) -> dict:
    if not isinstance(raw_section, dict):
        return {
            "reads": [],
            "writes": [],
            "rationale": "unknown",
            "confidence": 0.0,
        }
    return {
        "reads": _coerce_string_list(raw_section.get("reads")),
        "writes": _coerce_string_list(raw_section.get("writes")),
        "rationale": _coerce_rationale(raw_section.get("rationale")),
        "confidence": _coerce_confidence(raw_section.get("confidence")),
    }


def _normalize_network(raw_section: object) -> dict:
    if not isinstance(raw_section, dict):
        return {
            "domains": [],
            "urls": [],
            "ports": [],
            "rationale": "unknown",
            "confidence": 0.0,
        }
    return {
        "domains": _coerce_string_list(raw_section.get("domains")),
        "urls": _coerce_string_list(raw_section.get("urls")),
        "ports": _coerce_ports(raw_section.get("ports")),
        "rationale": _coerce_rationale(raw_section.get("rationale")),
        "confidence": _coerce_confidence(raw_section.get("confidence")),
    }


def _normalize_persistence(raw_section: object) -> dict:
    if not isinstance(raw_section, dict):
        return {
            "likely": False,
            "mechanisms": [],
            "rationale": "unknown",
            "confidence": 0.0,
        }
    return {
        "likely": bool(raw_section.get("likely"))
        if isinstance(raw_section.get("likely"), bool)
        else False,
        "mechanisms": _coerce_string_list(raw_section.get("mechanisms")),
        "rationale": _coerce_rationale(raw_section.get("rationale")),
        "confidence": _coerce_confidence(raw_section.get("confidence")),
    }


def _coerce_string_list(raw_value: object) -> list[str]:
    if isinstance(raw_value, str):
        return [raw_value]
    if isinstance(raw_value, list):
        return [str(item) for item in raw_value if isinstance(item, (str, int, float))]
    return []


def _coerce_ports(raw_value: object) -> list[int]:
    if not isinstance(raw_value, list):
        return []
    ports: list[int] = []
    for item in raw_value:
        if isinstance(item, int) and 0 < item <= 65535:
            ports.append(item)
            continue
        if isinstance(item, str) and item.isdigit():
            as_int = int(item)
            if 0 < as_int <= 65535:
                ports.append(as_int)
    return ports


def _coerce_confidence(raw_value: object) -> float:
    if isinstance(raw_value, (int, float)):
        raw_float = float(raw_value)
        if 0 <= raw_float <= 1:
            return raw_float
    return 0.0


def _coerce_rationale(raw_value: object) -> str:
    if isinstance(raw_value, str) and raw_value.strip():
        return raw_value.strip()
    return "unknown"


def _coerce_summary(raw_value: object) -> str:
    if isinstance(raw_value, str) and raw_value.strip():
        return raw_value.strip()
    return "unknown"
