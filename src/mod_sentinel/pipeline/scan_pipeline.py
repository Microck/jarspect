from __future__ import annotations

from uuid import uuid4

from mod_sentinel.agents.behavior_agent import BehaviorAgent
from mod_sentinel.agents.intake_agent import IntakeAgent
from mod_sentinel.agents.reputation_agent import ReputationAgent
from mod_sentinel.agents.static_agent import StaticAgent
from mod_sentinel.agents.verdict_agent import VerdictAgent
from mod_sentinel.models.scan import ScanRequest, ScanResult
from mod_sentinel.pipeline.snippet_select import select_snippets


def run_scan(request: ScanRequest) -> tuple[str, ScanResult]:
    intake_agent = IntakeAgent()
    static_agent = StaticAgent()
    behavior_agent = BehaviorAgent()
    reputation_agent = ReputationAgent()
    verdict_agent = VerdictAgent()

    intake = intake_agent.run_intake(request.upload_id)
    static_artifact = static_agent.analyze(request.upload_id)
    snippets = select_snippets(static_artifact.findings, static_artifact.sources)
    behavior = behavior_agent.predict(static_artifact.findings, snippets)

    reputation = None
    if request.author is not None:
        reputation = reputation_agent.score_author(request.author)

    verdict = verdict_agent.synthesize(
        intake=intake,
        static_findings=static_artifact.findings,
        behavior=behavior,
        reputation=reputation,
    )

    result = ScanResult(
        intake=intake,
        static=static_artifact.findings,
        behavior=behavior,
        reputation=reputation,
        verdict=verdict,
    )
    return uuid4().hex, result
