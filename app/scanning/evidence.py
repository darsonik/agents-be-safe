"""Validate model claims against source and derive trustworthy line numbers."""

from app.errors import ScanError
from app.models import Finding, SourceFile

from .policy import DIMENSIONS


def validate_findings(data: object, files: list[SourceFile]) -> list[Finding]:
    if (
        not isinstance(data, dict)
        or not isinstance(data.get("findings"), list)
        or len(data["findings"]) > 30
    ):
        raise ScanError("Fireworks returned an invalid findings structure.")
    by_path = {f["path"]: f["content"] for f in files}
    findings = []
    for item in data["findings"]:
        if not isinstance(item, dict):
            raise ScanError("Invalid finding.")
        fields = (
            "path",
            "category",
            "severity",
            "title",
            "evidence",
            "explanation",
            "remediation",
        )
        if any(
            not isinstance(item.get(k), str) or not item[k].strip() or len(item[k]) > 5000
            for k in fields
        ):
            raise ScanError("Fireworks returned missing or oversized finding fields.")
        content = by_path.get(item["path"])
        if (
            content is None
            or item["evidence"] not in content
            or item["category"] not in DIMENSIONS
            or item["severity"] not in ("low", "medium", "high", "critical")
        ):
            raise ScanError("Fireworks returned invalid evidence or classification.")
        clean = {k: item[k] for k in fields}
        clean.update(
            line=content[: content.index(item["evidence"])].count("\n") + 1,
            origin="Fireworks",
            verification="Needs review",
        )
        findings.append(clean)
    return findings
