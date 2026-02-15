from __future__ import annotations

from mod_sentinel.agents.behavior_agent import BehaviorAgent
from mod_sentinel.llm.client import LLMClient
from mod_sentinel.models.static import StaticFindings


class MarkdownStubLLM(LLMClient):
    def complete_text(self, system_prompt: str, user_prompt: str) -> str:
        _ = (system_prompt, user_prompt)
        return """
Model response:
```json
{
  "network": {
    "urls": ["https://demo.example.invalid"],
    "ports": [443, "8443"],
    "confidence": "high"
  },
  "persistence": "unknown"
}
```
        """


def test_behavior_agent_handles_markdown_wrapped_partial_json() -> None:
    agent = BehaviorAgent(llm_client=MarkdownStubLLM())
    prediction = agent.predict(
        static_findings=StaticFindings(), snippets=["class Demo {}"]
    )

    assert prediction.network.urls == ["https://demo.example.invalid"]
    assert prediction.network.ports == [443, 8443]
    assert prediction.network.confidence == 0.0
    assert prediction.file_system.rationale == "unknown"
    assert prediction.persistence.likely is False
    assert prediction.risk_summary == "unknown"
