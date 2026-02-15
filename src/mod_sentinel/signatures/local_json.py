from __future__ import annotations

import json
import re
from pathlib import Path

from mod_sentinel.signatures.store import (
    SignatureDefinition,
    SignatureMatch,
    SignatureStore,
)


class LocalJsonSignatureStore(SignatureStore):
    def __init__(self, corpus_path: str | Path | None = None) -> None:
        root = Path(__file__).resolve().parents[3]
        default_path = root / "data" / "signatures" / "signatures.json"
        self._corpus_path = Path(corpus_path) if corpus_path else default_path
        self._definitions = _load_definitions(self._corpus_path)

    def search(self, text: str) -> list[SignatureMatch]:
        matches: list[SignatureMatch] = []
        for signature in self._definitions:
            if signature.kind == "token":
                matches.extend(_match_token(signature, text))
            elif signature.kind == "regex":
                matches.extend(_match_regex(signature, text))
        return matches


def _load_definitions(path: Path) -> list[SignatureDefinition]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    definitions: list[SignatureDefinition] = []
    for item in payload:
        definitions.append(
            SignatureDefinition(
                id=item["id"],
                kind=item["kind"],
                value=item["value"],
                severity=item["severity"],
                description=item["description"],
            )
        )
    return definitions


def _match_token(signature: SignatureDefinition, text: str) -> list[SignatureMatch]:
    matches: list[SignatureMatch] = []
    needle = signature.value
    start = 0
    while True:
        offset = text.find(needle, start)
        if offset == -1:
            break
        end_offset = offset + len(needle)
        matches.append(
            SignatureMatch(
                id=signature.id,
                severity=signature.severity,
                description=signature.description,
                evidence=_snippet(text, offset, end_offset),
                offset=offset,
                end_offset=end_offset,
            )
        )
        start = end_offset
    return matches


def _match_regex(signature: SignatureDefinition, text: str) -> list[SignatureMatch]:
    regex = re.compile(signature.value)
    matches: list[SignatureMatch] = []
    for found in regex.finditer(text):
        matches.append(
            SignatureMatch(
                id=signature.id,
                severity=signature.severity,
                description=signature.description,
                evidence=_snippet(text, found.start(), found.end()),
                offset=found.start(),
                end_offset=found.end(),
            )
        )
    return matches


def _snippet(text: str, start: int, end: int, radius: int = 80) -> str:
    left = max(start - radius, 0)
    right = min(end + radius, len(text))
    return text[left:right].strip()
