from __future__ import annotations

from collections import Counter

from mod_sentinel.analysis.patterns import PATTERNS
from mod_sentinel.models.static import StaticFindings, StaticIndicator


def scan_sources_for_patterns(sources: list[tuple[str, str]]) -> StaticFindings:
    matches: list[StaticIndicator] = []

    for file_path, text in sources:
        for pattern in PATTERNS:
            for found in pattern.regex.finditer(text):
                snippet = _snippet(text, found.start(), found.end())
                matches.append(
                    StaticIndicator(
                        source="pattern",
                        id=pattern.id,
                        title=pattern.title,
                        category=pattern.category,
                        severity=pattern.severity,  # type: ignore[arg-type]
                        file_path=file_path,
                        evidence=snippet,
                        rationale=pattern.rationale,
                    )
                )

    category_counts = Counter(match.category for match in matches)
    severity_counts = Counter(match.severity for match in matches)
    matched_pattern_ids = sorted(
        {match.id for match in matches if match.source == "pattern"}
    )

    return StaticFindings(
        matches=matches,
        counts_by_category=dict(category_counts),
        counts_by_severity=dict(severity_counts),
        matched_pattern_ids=matched_pattern_ids,
        matched_signature_ids=[],
        analyzed_files=len(sources),
    )


def _snippet(text: str, start: int, end: int, radius: int = 80) -> str:
    left = max(start - radius, 0)
    right = min(end + radius, len(text))
    return text[left:right].strip()
