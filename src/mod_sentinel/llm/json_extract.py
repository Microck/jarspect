from __future__ import annotations

import json
import re


class JsonExtractionError(ValueError):
    """Raised when JSON extraction from LLM text fails."""


def extract_first_json_object(raw_text: str) -> dict:
    fenced_matches = re.findall(r"```json\s*(\{.*?\})\s*```", raw_text, flags=re.DOTALL)
    for candidate in fenced_matches:
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed

    balanced = _extract_balanced_object(raw_text)
    if balanced is not None:
        try:
            parsed = json.loads(balanced)
        except json.JSONDecodeError as exc:
            raise JsonExtractionError(_error_message(raw_text)) from exc
        if isinstance(parsed, dict):
            return parsed

    raise JsonExtractionError(_error_message(raw_text))


def _extract_balanced_object(raw_text: str) -> str | None:
    start = raw_text.find("{")
    while start != -1:
        depth = 0
        in_string = False
        escaped = False
        for index in range(start, len(raw_text)):
            char = raw_text[index]

            if escaped:
                escaped = False
                continue

            if char == "\\":
                escaped = True
                continue

            if char == '"':
                in_string = not in_string
                continue

            if in_string:
                continue

            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return raw_text[start : index + 1]

        start = raw_text.find("{", start + 1)
    return None


def _error_message(raw_text: str) -> str:
    preview = raw_text.strip().replace("\n", " ")
    return f"Failed to extract JSON object from LLM response: {preview[:180]}"
