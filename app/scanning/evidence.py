import logging

from app.errors import ScanError
from app.models import Finding, SourceFile

from .policy import DIMENSIONS

logger = logging.getLogger("agents_be_safe.evidence")


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
        category = item["category"].strip().lower().replace(" ", "_")
        severity = item["severity"].strip().lower()
        if content is None:
            logger.warning("Finding rejected: file %s not in inspected files", item["path"])
            raise ScanError("Fireworks returned invalid evidence or classification.")
        ev = item["evidence"]
        clean_evidence = None
        if ev in content:
            clean_evidence = ev
        elif ev.strip() and ev.strip() in content:
            clean_evidence = ev.strip()
        elif ev.strip().strip("'\"`") and ev.strip().strip("'\"`") in content:
            clean_evidence = ev.strip().strip("'\"`")

        if clean_evidence is None:
            logger.warning(
                "Finding rejected: evidence not found in %s: %r",
                item["path"],
                item["evidence"][:100],
            )
            raise ScanError("Fireworks returned invalid evidence or classification.")
        if category not in DIMENSIONS or severity not in ("low", "medium", "high", "critical"):
            logger.warning(
                "Finding rejected: invalid category %r or severity %r", category, severity
            )
            raise ScanError("Fireworks returned invalid evidence or classification.")
        clean = {k: item[k] for k in fields}
        clean["evidence"] = clean_evidence
        clean["category"] = category
        clean["severity"] = severity
        clean.update(
            line=content[: content.index(clean_evidence)].count("\n") + 1,
            origin="Fireworks",
            verification="Needs review",
        )
        findings.append(clean)
    return findings
