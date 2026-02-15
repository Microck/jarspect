from __future__ import annotations

from mod_sentinel.models.behavior import BehaviorPrediction
from mod_sentinel.models.intake import IntakeResult
from mod_sentinel.models.reputation import ReputationResult
from mod_sentinel.models.static import StaticFindings
from mod_sentinel.models.verdict import RiskTier, Verdict, VerdictIndicator


_STATIC_WEIGHTS = {"low": 4.0, "med": 10.0, "high": 18.0}


class VerdictAgent:
    def synthesize(
        self,
        intake: IntakeResult,
        static_findings: StaticFindings,
        behavior: BehaviorPrediction,
        reputation: ReputationResult | None = None,
    ) -> Verdict:
        total_score = 0.0
        indicators: list[VerdictIndicator] = []

        static_score, static_indicators = _score_static(static_findings)
        total_score += static_score
        indicators.extend(static_indicators)

        behavior_score, behavior_indicators = _score_behavior(behavior)
        total_score += behavior_score
        indicators.extend(behavior_indicators)

        reputation_score = 0.0
        if reputation is not None:
            reputation_score, reputation_indicator = _score_reputation(reputation)
            total_score += reputation_score
            indicators.append(reputation_indicator)

        risk_score = min(100, int(round(total_score)))
        risk_tier = tier_for_score(risk_score)
        summary = _build_summary(risk_tier, risk_score, indicators)
        explanation = _build_explanation(
            intake=intake,
            risk_tier=risk_tier,
            risk_score=risk_score,
            static_score=static_score,
            behavior_score=behavior_score,
            reputation_score=reputation_score,
            indicators=indicators,
        )

        return Verdict(
            risk_tier=risk_tier,
            risk_score=risk_score,
            summary=summary,
            explanation=explanation,
            indicators=indicators,
        )


def tier_for_score(risk_score: int) -> RiskTier:
    if risk_score >= 75:
        return "CRITICAL"
    if risk_score >= 50:
        return "HIGH"
    if risk_score >= 25:
        return "MEDIUM"
    return "LOW"


def _score_static(
    static_findings: StaticFindings,
) -> tuple[float, list[VerdictIndicator]]:
    score = 0.0
    indicators: list[VerdictIndicator] = []
    for match in static_findings.matches:
        score += _STATIC_WEIGHTS.get(match.severity, 8.0)
        indicators.append(
            VerdictIndicator(
                source="static",
                id=match.id,
                title=match.title,
                severity=match.severity,
                evidence=f"{match.file_path}: {match.evidence}",
            )
        )
    return score, indicators


def _score_behavior(
    behavior: BehaviorPrediction,
) -> tuple[float, list[VerdictIndicator]]:
    score = 0.0
    indicators: list[VerdictIndicator] = []

    if behavior.network.domains or behavior.network.urls:
        confidence = max(behavior.network.confidence, 0.3)
        score += 15.0 * confidence
        evidence_parts = [
            f"domains={','.join(behavior.network.domains) or 'none'}",
            f"urls={','.join(behavior.network.urls) or 'none'}",
            f"confidence={behavior.network.confidence:.2f}",
        ]
        indicators.append(
            VerdictIndicator(
                source="behavior",
                id="BEH-NETWORK",
                title="Predicted outbound network activity",
                severity="high" if confidence >= 0.7 else "med",
                evidence="; ".join(evidence_parts),
            )
        )

    if behavior.file_system.writes:
        confidence = max(behavior.file_system.confidence, 0.3)
        score += 10.0 * confidence
        indicators.append(
            VerdictIndicator(
                source="behavior",
                id="BEH-FS-WRITES",
                title="Predicted file system writes",
                severity="high" if confidence >= 0.7 else "med",
                evidence=(
                    f"writes={','.join(behavior.file_system.writes)}; "
                    f"confidence={behavior.file_system.confidence:.2f}"
                ),
            )
        )

    if behavior.persistence.likely:
        confidence = max(behavior.persistence.confidence, 0.3)
        score += 20.0 * confidence
        indicators.append(
            VerdictIndicator(
                source="behavior",
                id="BEH-PERSISTENCE",
                title="Predicted persistence behavior",
                severity="critical" if confidence >= 0.75 else "high",
                evidence=(
                    f"mechanisms={','.join(behavior.persistence.mechanisms) or 'unknown'}; "
                    f"confidence={behavior.persistence.confidence:.2f}"
                ),
            )
        )

    return score, indicators


def _score_reputation(reputation: ReputationResult) -> tuple[float, VerdictIndicator]:
    score = (1.0 - reputation.author_score) * 35.0

    if reputation.author_score < 0.2:
        severity = "critical"
    elif reputation.author_score < 0.4:
        severity = "high"
    elif reputation.author_score < 0.6:
        severity = "med"
    else:
        severity = "low"

    indicator = VerdictIndicator(
        source="reputation",
        id="REP-AUTHOR-TRUST",
        title="Author trust score",
        severity=severity,
        evidence=(
            f"author_score={reputation.author_score:.3f}; "
            f"account_age_days={reputation.account_age_days}; "
            f"prior_mod_count={reputation.prior_mod_count}; "
            f"report_count={reputation.report_count}"
        ),
    )
    return score, indicator


def _build_summary(
    risk_tier: RiskTier,
    risk_score: int,
    indicators: list[VerdictIndicator],
) -> str:
    if not indicators:
        return (
            f"{risk_tier} risk ({risk_score}/100): no suspicious indicators detected."
        )
    top_ids = ", ".join(indicator.id for indicator in indicators[:3])
    return (
        f"{risk_tier} risk ({risk_score}/100): "
        f"{len(indicators)} indicators triggered ({top_ids})."
    )


def _build_explanation(
    intake: IntakeResult,
    risk_tier: RiskTier,
    risk_score: int,
    static_score: float,
    behavior_score: float,
    reputation_score: float,
    indicators: list[VerdictIndicator],
) -> str:
    lines = [
        f"Upload {intake.upload_id} is assessed as {risk_tier} risk ({risk_score}/100).",
        (
            "Score contributions: "
            f"static={static_score:.1f}, behavior={behavior_score:.1f}, reputation={reputation_score:.1f}."
        ),
    ]

    if indicators:
        lines.append("Triggering indicators:")
        for indicator in indicators[:8]:
            lines.append(
                f"- [{indicator.id}] {indicator.title} ({indicator.source}, {indicator.severity}) :: {indicator.evidence}"
            )
    else:
        lines.append(
            "No indicators were triggered by static, behavior, or reputation stages."
        )

    return "\n".join(lines)
