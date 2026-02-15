from __future__ import annotations

from fastapi import APIRouter, HTTPException

from mod_sentinel.agents.behavior_agent import BehaviorAgent
from mod_sentinel.agents.intake_agent import IntakeAgent
from mod_sentinel.agents.reputation_agent import ReputationAgent
from mod_sentinel.agents.static_agent import StaticAgent
from mod_sentinel.models.scan import ScanRequest, ScanResult
from mod_sentinel.pipeline.snippet_select import select_snippets


router = APIRouter()


@router.post("/scan")
def scan_upload(request: ScanRequest) -> dict[str, object]:
    intake_agent = IntakeAgent()
    static_agent = StaticAgent()
    behavior_agent = BehaviorAgent()
    reputation_agent = ReputationAgent()

    try:
        intake = intake_agent.run_intake(request.upload_id)
        static_artifact = static_agent.analyze(request.upload_id)
        snippets = select_snippets(static_artifact.findings, static_artifact.sources)
        behavior = behavior_agent.predict(static_artifact.findings, snippets)
        reputation = None
        if request.author is not None:
            reputation = reputation_agent.score_author(request.author)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Upload not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    result = ScanResult(
        intake=intake,
        static=static_artifact.findings,
        behavior=behavior,
        reputation=reputation,
    )
    return result.model_dump(exclude_none=True)
