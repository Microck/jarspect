from __future__ import annotations

from dataclasses import dataclass

from mod_sentinel.analysis.decompiler import Decompiler
from mod_sentinel.analysis.static_scan import scan_sources_for_patterns
from mod_sentinel.models.static import StaticFindings, StaticIndicator
from mod_sentinel.signatures.local_json import LocalJsonSignatureStore
from mod_sentinel.signatures.store import SignatureStore
from mod_sentinel.storage import get_storage_backend
from mod_sentinel.storage.base import StorageBackend


@dataclass(frozen=True)
class StaticAnalysisArtifact:
    findings: StaticFindings
    sources: list[tuple[str, str]]


class StaticAgent:
    def __init__(
        self,
        storage_backend: StorageBackend | None = None,
        decompiler: Decompiler | None = None,
        signature_store: SignatureStore | None = None,
    ) -> None:
        self._storage = storage_backend or get_storage_backend()
        self._decompiler = decompiler or Decompiler()
        self._signature_store = signature_store or LocalJsonSignatureStore()

    def analyze(self, upload_id: str) -> StaticAnalysisArtifact:
        storage_key = f"uploads/{upload_id}.jar"
        upload_bytes = self._storage.get_bytes(storage_key)

        sources = self._decompiler.decompile(upload_bytes)
        findings = scan_sources_for_patterns(sources)

        merged_matches = list(findings.matches)
        signature_ids: set[str] = set(findings.matched_signature_ids)

        for file_path, text in sources:
            for match in self._signature_store.search(text):
                severity = _normalize_severity(match.severity)
                merged_matches.append(
                    StaticIndicator(
                        source="signature",
                        id=match.id,
                        title="Known suspicious signature",
                        category="signature",
                        severity=severity,
                        file_path=file_path,
                        evidence=match.evidence,
                        rationale=match.description,
                    )
                )
                signature_ids.add(match.id)

        findings.matches = merged_matches
        findings.matched_signature_ids = sorted(signature_ids)
        findings.counts_by_category = _rollup(merged_matches, field="category")
        findings.counts_by_severity = _rollup(merged_matches, field="severity")

        return StaticAnalysisArtifact(findings=findings, sources=sources)


def _rollup(matches: list[StaticIndicator], field: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for match in matches:
        key = str(getattr(match, field))
        counts[key] = counts.get(key, 0) + 1
    return counts


def _normalize_severity(raw: str) -> str:
    normalized = raw.lower()
    if normalized in {"low", "med", "high"}:
        return normalized
    return "med"
