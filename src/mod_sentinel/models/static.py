from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


Severity = Literal["low", "med", "high"]
IndicatorSource = Literal["pattern", "signature"]


class StaticIndicator(BaseModel):
    source: IndicatorSource
    id: str
    title: str
    category: str
    severity: Severity
    file_path: str
    evidence: str
    rationale: str | None = None


class StaticFindings(BaseModel):
    matches: list[StaticIndicator] = Field(default_factory=list)
    counts_by_category: dict[str, int] = Field(default_factory=dict)
    counts_by_severity: dict[str, int] = Field(default_factory=dict)
    matched_pattern_ids: list[str] = Field(default_factory=list)
    matched_signature_ids: list[str] = Field(default_factory=list)
    analyzed_files: int = 0
