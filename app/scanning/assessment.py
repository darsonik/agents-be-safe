"""Compose static checks and AI judgments into the public report contract."""

from datetime import datetime, timezone

from app.config import Settings
from app.errors import ScanError
from app.models import Finding, Progress, Report, ScanMode, Snapshot, ignore_progress
from app.providers.fireworks import FireworksClient
from app.providers.jev import JevClient

from .policy import DISAGREEMENT_THRESHOLD, SEVERITY_ORDER, SUPPORT_THRESHOLD
from .rules import static_findings


def annotate_support(findings: list[Finding], probabilities: list[float]) -> None:
    """Apply application policy to provider judgments, retaining disagreements."""
    if len(findings) != len(probabilities):
        raise ScanError("Jev did not return support for every finding.")
    for finding, probability in zip(findings, probabilities, strict=True):
        finding["support_probability"] = probability
        if probability >= SUPPORT_THRESHOLD:
            finding["verification"] = "Supported by Jev"
        elif probability <= DISAGREEMENT_THRESHOLD:
            finding["verification"] = "Models disagree"
        else:
            finding["verification"] = "Needs review"


class AssessmentService:
    """Provider clients are injectable so the workflow can be tested offline."""

    def __init__(self, fireworks: FireworksClient, jev: JevClient):
        self.fireworks = fireworks
        self.jev = jev

    @classmethod
    def from_settings(cls, settings: Settings) -> "AssessmentService":
        return cls(
            FireworksClient(settings.fireworks_api_key, settings.fireworks_model),
            JevClient(settings.typesafe_api_key, settings.typesafe_model),
        )

    def assess(
        self,
        snapshot: Snapshot,
        mode: ScanMode = "live",
        progress: Progress = ignore_progress,
    ) -> Report:
        files = snapshot["files"]
        findings = static_findings(files)
        warnings = [
            "Static assessment only; no safety certification. External packages, remote MCP servers, runtime behavior, and unselected files are not inspected.",
            "Jev probabilities and review thresholds are experimental and need calibration against labeled security cases.",
        ]
        providers = {"fireworks": "Not run", "jev": "Not run"}
        dimensions = {}
        if mode == "live" and files:
            progress("Fireworks is reviewing skills and tool implementations")
            if self.fireworks.configured:
                try:
                    findings += self.fireworks.analyze(files)
                    providers["fireworks"] = self.fireworks.model
                except ScanError as exc:
                    warnings.append("Fireworks: " + str(exc))
            else:
                warnings.append(
                    "Fireworks is not configured; set FIREWORKS_API_KEY and FIREWORKS_MODEL."
                )
            progress("Jev is evaluating risks and checking finding support")
            if self.jev.configured:
                try:
                    evaluation = self.jev.evaluate(files, findings)
                    annotate_support(findings, evaluation.finding_support)
                    dimensions = evaluation.dimensions
                    providers["jev"] = evaluation.model
                except ScanError as exc:
                    warnings.append("Jev: " + str(exc))
            else:
                warnings.append("Jev is not configured; set TYPESAFE_API_KEY.")
        if mode == "demo":
            warnings.insert(
                0,
                "Sample report: fictional files and static rules only. No AI calls were made.",
            )
        gaps = bool(snapshot["skipped"] or snapshot["tree_truncated"] or not files)
        complete = mode == "live" and not gaps and all(v != "Not run" for v in providers.values())
        high = any(f["severity"] in ("critical", "high") for f in findings) or any(
            p >= SUPPORT_THRESHOLD for p in dimensions.values()
        )
        if high:
            verdict = "High risk indicators"
        elif findings:
            verdict = "Review required"
        elif complete:
            verdict = "No findings in inspected files"
        else:
            verdict = "Inconclusive"
        if gaps:
            warnings.append(
                "Coverage is incomplete: some source could not be inspected. See the coverage section."
            )
        return {
            "repository": snapshot["repository"],
            "commit": snapshot["commit"],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "mode": mode,
            "verdict": verdict,
            "coverage_status": "Bounded scan completed"
            if complete
            else "Incomplete / limited assessment",
            "providers": providers,
            "dimensions": dimensions,
            "findings": sorted(findings, key=lambda f: SEVERITY_ORDER[f["severity"]]),
            "warnings": warnings,
            "files": [
                {
                    "path": f["path"],
                    "kind": f["kind"],
                    "lines": len(f["content"].splitlines()),
                }
                for f in files
            ],
            "skipped": snapshot["skipped"],
            "candidate_count": snapshot["candidate_count"],
            "tree_truncated": snapshot["tree_truncated"],
        }
