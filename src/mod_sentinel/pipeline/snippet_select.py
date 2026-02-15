from __future__ import annotations

from collections import defaultdict

from mod_sentinel.models.static import StaticFindings


SEVERITY_SCORE = {"high": 3, "med": 2, "low": 1}


def select_snippets(
    static_findings: StaticFindings,
    sources: list[tuple[str, str]],
    *,
    max_files: int = 3,
    max_chars_per_snippet: int = 2000,
) -> list[str]:
    if not sources:
        return []

    score_by_file: dict[str, int] = defaultdict(int)
    evidence_by_file: dict[str, list[str]] = defaultdict(list)

    for match in static_findings.matches:
        score_by_file[match.file_path] += SEVERITY_SCORE.get(match.severity, 1)
        if match.evidence:
            evidence_by_file[match.file_path].append(match.evidence)

    ranked_sources = sorted(
        sources,
        key=lambda item: score_by_file.get(item[0], 0),
        reverse=True,
    )

    snippets: list[str] = []
    for file_path, source_text in ranked_sources[:max_files]:
        evidence_block = "\n".join(evidence_by_file.get(file_path, [])[:3])
        body = source_text[:max_chars_per_snippet]
        snippet = (
            f"FILE: {file_path}\nEVIDENCE:\n{evidence_block}\nCONTENT:\n{body}"
        ).strip()
        snippets.append(snippet[:max_chars_per_snippet])

    return snippets
