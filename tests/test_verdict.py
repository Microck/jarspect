from __future__ import annotations

import pytest

from mod_sentinel.agents.verdict_agent import VerdictAgent, tier_for_score
from mod_sentinel.models.behavior import (
    BehaviorPrediction,
    FileSystemPrediction,
    NetworkPrediction,
    PersistencePrediction,
)
from mod_sentinel.models.intake import IntakeResult
from mod_sentinel.models.reputation import ReputationResult
from mod_sentinel.models.static import StaticFindings, StaticIndicator


def _intake(upload_id: str = "upload-123") -> IntakeResult:
    return IntakeResult(
        upload_id=upload_id,
        filename=f"{upload_id}.jar",
        loader="fabric",
        file_count=3,
        top_level_entries=["com", "META-INF"],
        manifest={},
    )


def _behavior(
    *,
    writes: list[str] | None = None,
    write_conf: float = 0.0,
    domains: list[str] | None = None,
    urls: list[str] | None = None,
    network_conf: float = 0.0,
    persistence: bool = False,
    persistence_conf: float = 0.0,
) -> BehaviorPrediction:
    return BehaviorPrediction(
        file_system=FileSystemPrediction(
            reads=[],
            writes=writes or [],
            rationale="test",
            confidence=write_conf,
        ),
        network=NetworkPrediction(
            domains=domains or [],
            urls=urls or [],
            ports=[443] if (domains or urls) else [],
            rationale="test",
            confidence=network_conf,
        ),
        persistence=PersistencePrediction(
            likely=persistence,
            mechanisms=["startup-task"] if persistence else [],
            rationale="test",
            confidence=persistence_conf,
        ),
        risk_summary="test",
        confidence=0.5,
    )


def _static(matches: list[StaticIndicator]) -> StaticFindings:
    return StaticFindings(
        matches=matches,
        counts_by_category={},
        counts_by_severity={},
        matched_pattern_ids=[match.id for match in matches],
        matched_signature_ids=[],
        analyzed_files=3,
    )


def test_verdict_benignish_mod_is_low_or_medium() -> None:
    agent = VerdictAgent()
    verdict = agent.synthesize(
        intake=_intake("benign-upload"),
        static_findings=_static(
            [
                StaticIndicator(
                    source="pattern",
                    id="NET-URLCONNECTION",
                    title="URLConnection usage",
                    category="network",
                    severity="low",
                    file_path="Demo.java",
                    evidence="java.net.URLConnection",
                )
            ]
        ),
        behavior=_behavior(),
        reputation=ReputationResult(
            author_id="trusted_creator",
            account_age_days=1320,
            prior_mod_count=47,
            report_count=0,
            report_reasons=[],
            author_score=0.95,
            rationale=["trusted fixture"],
        ),
    )

    assert verdict.risk_tier in {"LOW", "MEDIUM"}
    assert verdict.risk_score < 35
    assert "NET-URLCONNECTION" in verdict.explanation


def test_verdict_many_high_indicators_is_high_or_critical() -> None:
    agent = VerdictAgent()
    verdict = agent.synthesize(
        intake=_intake("danger-upload"),
        static_findings=_static(
            [
                StaticIndicator(
                    source="pattern",
                    id="EXEC-RUNTIME",
                    title="Runtime exec",
                    category="execution",
                    severity="high",
                    file_path="Exec.java",
                    evidence="Runtime.getRuntime().exec",
                ),
                StaticIndicator(
                    source="pattern",
                    id="OBF-BASE64",
                    title="Encoded payload",
                    category="obfuscation",
                    severity="high",
                    file_path="Payload.java",
                    evidence="QWxhZGRpbjpvcGVuIHNlc2FtZQ",
                ),
                StaticIndicator(
                    source="pattern",
                    id="FS-WRITE",
                    title="File writes",
                    category="filesystem",
                    severity="med",
                    file_path="Writer.java",
                    evidence="Files.write",
                ),
            ]
        ),
        behavior=_behavior(
            writes=["mods/cache.bin"],
            write_conf=0.8,
            domains=["payload.example.invalid"],
            urls=["https://payload.example.invalid/bootstrap"],
            network_conf=0.9,
            persistence=True,
            persistence_conf=0.85,
        ),
    )

    assert verdict.risk_tier in {"HIGH", "CRITICAL"}
    assert verdict.risk_score >= 50
    assert "EXEC-RUNTIME" in verdict.explanation
    assert "BEH-PERSISTENCE" in verdict.explanation


def test_low_reputation_pushes_borderline_case_upward() -> None:
    agent = VerdictAgent()
    static_findings = _static(
        [
            StaticIndicator(
                source="pattern",
                id="FS-WRITE",
                title="File writes",
                category="filesystem",
                severity="med",
                file_path="Writer.java",
                evidence="Files.write",
            )
        ]
    )
    behavior = _behavior(
        writes=["mods/cache.bin"],
        write_conf=0.4,
        domains=["cdn.example.invalid"],
        urls=["https://cdn.example.invalid/update"],
        network_conf=0.6,
    )

    without_reputation = agent.synthesize(
        intake=_intake("borderline-upload"),
        static_findings=static_findings,
        behavior=behavior,
    )
    with_low_reputation = agent.synthesize(
        intake=_intake("borderline-upload"),
        static_findings=static_findings,
        behavior=behavior,
        reputation=ReputationResult(
            author_id="new_creator",
            account_age_days=14,
            prior_mod_count=1,
            report_count=6,
            report_reasons=["startup persistence complaints"],
            author_score=0.1,
            rationale=["new + reported"],
        ),
    )

    assert with_low_reputation.risk_score > without_reputation.risk_score
    assert with_low_reputation.risk_tier in {"HIGH", "CRITICAL"}
    assert "REP-AUTHOR-TRUST" in with_low_reputation.explanation


@pytest.mark.parametrize(
    ("score", "expected_tier"),
    [
        (0, "LOW"),
        (24, "LOW"),
        (25, "MEDIUM"),
        (49, "MEDIUM"),
        (50, "HIGH"),
        (74, "HIGH"),
        (75, "CRITICAL"),
        (100, "CRITICAL"),
    ],
)
def test_tier_boundaries_cover_all_levels(score: int, expected_tier: str) -> None:
    assert tier_for_score(score) == expected_tier
