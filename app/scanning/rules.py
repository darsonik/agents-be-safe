"""Deterministic risk indicators; matches are not confirmed vulnerabilities."""

import re

from app.models import Finding, SourceFile

RULES = [
    (
        "prompt_injection",
        "high",
        r"ignore (?:all |any |the )?(?:previous|prior|system) instructions|do not (?:tell|inform) the user",
        "Instructions attempt to bypass agent oversight",
        "Remove instruction overrides and require visible approval for sensitive actions.",
    ),
    (
        "unsafe_execution",
        "high",
        r"(?:curl|wget)[^\n]*\|\s*(?:bash|sh)|\b(?:eval|exec)\s*\(|shell\s*=\s*True|child_process|execSync",
        "Potentially unsafe command execution",
        "Use fixed commands and validated arguments; avoid shell evaluation and verify downloaded code.",
    ),
    (
        "data_exfiltration",
        "high",
        r"(?:upload|send|post|curl)[^\n]*(?:\.env|credentials|id_rsa|api[_ -]?key)|(?:\.env|credentials|id_rsa)[^\n]*(?:upload|https?://)",
        "Sensitive data may leave the environment",
        "Keep secrets out of tool output and outbound requests; allowlist destinations and payloads.",
    ),
    (
        "excessive_access",
        "medium",
        r"--privileged|chmod\s+777|/var/run/docker.sock|disable[^\n]*(?:sandbox|security)|allowAll",
        "Broad permissions or weakened isolation",
        "Restrict permissions, filesystem roots, and network access to the minimum required.",
    ),
    (
        "supply_chain",
        "medium",
        r"\bnpx\b|@latest|\buvx\b|\"(?:url|serverUrl)\"\s*:\s*\"https?://",
        "External or mutable tool dependency",
        "Pin versions and integrity; review the server implementation and operator before enabling it.",
    ),
]


def static_findings(files: list[SourceFile]) -> list[Finding]:
    findings = []
    for file in files:
        for category, severity, pattern, title, remedy in RULES:
            match = re.search(pattern, file["content"], re.I)
            if match:
                findings.append(
                    {
                        "path": file["path"],
                        "line": file["content"].count("\n", 0, match.start()) + 1,
                        "category": category,
                        "severity": severity,
                        "title": title,
                        "evidence": match.group(0),
                        "explanation": "A static pattern matched. Review the surrounding context to determine exploitability.",
                        "remediation": remedy,
                        "origin": "Static rule",
                        "verification": "Needs review",
                    }
                )
    return findings
