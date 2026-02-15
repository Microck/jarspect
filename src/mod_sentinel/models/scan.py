from __future__ import annotations

from pydantic import BaseModel

from mod_sentinel.models.behavior import BehaviorPrediction
from mod_sentinel.models.intake import IntakeResult
from mod_sentinel.models.reputation import AuthorMetadata, ReputationResult
from mod_sentinel.models.static import StaticFindings
from mod_sentinel.models.verdict import Verdict


class ScanRequest(BaseModel):
    upload_id: str
    author: AuthorMetadata | None = None


class ScanResult(BaseModel):
    intake: IntakeResult
    static: StaticFindings
    behavior: BehaviorPrediction
    reputation: ReputationResult | None = None
    verdict: Verdict | None = None


class ScanRunResponse(BaseModel):
    scan_id: str
    result: ScanResult
