from __future__ import annotations

from mod_sentinel.analysis.patterns import PATTERNS
from mod_sentinel.analysis.static_scan import scan_sources_for_patterns


def test_pattern_catalog_has_minimum_rules() -> None:
    assert len(PATTERNS) >= 10
    assert {pattern.id for pattern in PATTERNS}


def test_static_scan_detects_expected_patterns() -> None:
    base64_blob = "QWxhZGRpbjpvcGVuIHNlc2FtZQ" * 8
    source_text = (
        """
        java.net.URLConnection conn = new java.net.URL("http://example.invalid").openConnection();
        Runtime.getRuntime().exec("notepad.exe");
        String token = """
        + base64_blob
        + """;
    """
    )
    findings = scan_sources_for_patterns([("Example.class.txt", source_text)])

    matched_ids = {match.id for match in findings.matches}
    assert "NET-URLCONNECTION" in matched_ids
    assert "EXEC-RUNTIME" in matched_ids
    assert "OBF-LONG-BASE64" in matched_ids
    assert findings.counts_by_category.get("network", 0) >= 1
    assert findings.counts_by_severity.get("high", 0) >= 1
