from __future__ import annotations

from mod_sentinel.models.static import StaticFindings


def build_behavior_prompts(
    static_findings: StaticFindings,
    snippets: list[str] | None = None,
) -> tuple[str, str]:
    snippet_block = "\n\n".join(snippets or [])
    top_ids = ", ".join(static_findings.matched_pattern_ids[:10]) or "none"

    system_prompt = (
        "You are a security analyst for game mods. Respond with JSON only, matching "
        "the requested schema fields exactly."
    )

    user_prompt = (
        "Use static findings and snippets to predict likely behavior.\n"
        f"Static pattern ids: {top_ids}\n"
        f"Counts by category: {static_findings.counts_by_category}\n"
        f"Counts by severity: {static_findings.counts_by_severity}\n"
        "Return JSON with keys: file_system, network, persistence, risk_summary, confidence.\n"
        "Each section should include rationale and confidence fields.\n"
        f"Relevant snippets:\n{snippet_block}"
    )
    return system_prompt, user_prompt
