from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SuspiciousPattern:
    id: str
    title: str
    category: str
    severity: str
    regex: re.Pattern[str]
    rationale: str


PATTERNS: list[SuspiciousPattern] = [
    SuspiciousPattern(
        id="OBF-LONG-BASE64",
        title="Long base64-like literal",
        category="obfuscation",
        severity="med",
        regex=re.compile(r"[A-Za-z0-9+/]{120,}={0,2}"),
        rationale="Large encoded blobs can hide command strings or payload markers.",
    ),
    SuspiciousPattern(
        id="OBF-HEX-PARSE",
        title="Hex decoding sequence",
        category="obfuscation",
        severity="med",
        regex=re.compile(r"Integer\.parseInt\([^,]+,\s*16\)"),
        rationale="Runtime hex decoding can be used to conceal literals.",
    ),
    SuspiciousPattern(
        id="OBF-CHAR-XOR",
        title="Character XOR obfuscation",
        category="obfuscation",
        severity="high",
        regex=re.compile(r"\(char\)\s*\([^\)]*\^\s*0x[0-9A-Fa-f]+\)"),
        rationale="XOR loops are a frequent string deobfuscation pattern.",
    ),
    SuspiciousPattern(
        id="NET-URLCONNECTION",
        title="URLConnection usage",
        category="network",
        severity="med",
        regex=re.compile(r"java\.net\.(URL|URLConnection)"),
        rationale="Direct URL connections can fetch remote payloads.",
    ),
    SuspiciousPattern(
        id="NET-OKHTTP",
        title="OkHttp client usage",
        category="network",
        severity="med",
        regex=re.compile(r"(OkHttpClient|okhttp3\.)"),
        rationale="Third-party HTTP clients can signal dynamic remote control paths.",
    ),
    SuspiciousPattern(
        id="NET-SOCKET",
        title="Raw socket construction",
        category="network",
        severity="high",
        regex=re.compile(r"(new\s+Socket\s*\(|java\.net\.Socket)"),
        rationale="Raw sockets can indicate custom C2 channels.",
    ),
    SuspiciousPattern(
        id="FILE-OUTPUTSTREAM",
        title="FileOutputStream write",
        category="file_io",
        severity="high",
        regex=re.compile(r"FileOutputStream\s*\("),
        rationale="Direct file writes can be used to drop additional artifacts.",
    ),
    SuspiciousPattern(
        id="FILE-FILES-WRITE",
        title="NIO file write",
        category="file_io",
        severity="med",
        regex=re.compile(r"Files\.write(?:String|Bytes)?\s*\("),
        rationale="NIO write APIs often show persistence behavior.",
    ),
    SuspiciousPattern(
        id="REFL-FORNAME",
        title="Reflection class lookup",
        category="reflection",
        severity="med",
        regex=re.compile(r"Class\.forName\s*\("),
        rationale="Reflection may hide dynamically loaded behavior.",
    ),
    SuspiciousPattern(
        id="REFL-METHOD-INVOKE",
        title="Reflection method invoke",
        category="reflection",
        severity="high",
        regex=re.compile(r"Method\.invoke\s*\("),
        rationale="Dynamic invoke can bypass straightforward static review.",
    ),
    SuspiciousPattern(
        id="EXEC-RUNTIME",
        title="Runtime process execution",
        category="process_execution",
        severity="high",
        regex=re.compile(r"(Runtime\.getRuntime\(\)\.exec|ProcessBuilder\s*\()"),
        rationale="Subprocess execution is a high-risk indicator for droppers.",
    ),
]
