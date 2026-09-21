"""Compose static checks and AI judgments into the public report contract."""

import logging
from datetime import datetime, timezone

from app.config import Settings
from app.errors import ScanError
from app.models import Finding, Progress, Report, ScanMode, Snapshot, ignore_progress
from app.providers.fireworks import FireworksClient
from app.providers.jev import JevClient

from .policy import DISAGREEMENT_THRESHOLD, SEVERITY_ORDER, SUPPORT_THRESHOLD
from .rules import static_findings

logger = logging.getLogger("agents_be_safe.assessment")


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
            ai_files = [f for f in files if f["kind"] in ("Skill", "Agent", "MCP / configuration")]
            if ai_files:
                logger.info(
                    "Starting AI assessment on %d target files (%s): %s",
                    len(ai_files),
                    ", ".join({f["kind"] for f in ai_files}),
                    [f["path"] for f in ai_files],
                )
                progress("Fireworks is reviewing skills and tool implementations")
                if self.fireworks.configured:
                    try:
                        fw_findings = self.fireworks.analyze(ai_files)
                        findings += fw_findings
                        providers["fireworks"] = self.fireworks.model
                        logger.info("Fireworks analysis returned %d findings", len(fw_findings))
                    except ScanError as exc:
                        logger.warning("Fireworks analysis error: %s", exc)
                        warnings.append("Fireworks: " + str(exc))
                else:
                    logger.info("Fireworks is not configured")
                    warnings.append(
                        "Fireworks is not configured; set FIREWORKS_API_KEY and FIREWORKS_MODEL."
                    )
                progress("Jev is evaluating risks and checking finding support")
                if self.jev.configured:
                    try:
                        evaluation = self.jev.evaluate(ai_files, findings)
                        annotate_support(findings, evaluation.finding_support)
                        dimensions = evaluation.dimensions
                        providers["jev"] = evaluation.model
                        logger.info(
                            "Jev evaluation completed: model=%s, dimensions=%s",
                            evaluation.model,
                            dimensions,
                        )
                    except ScanError as exc:
                        logger.warning("Jev evaluation error: %s", exc)
                        warnings.append("Jev: " + str(exc))
                else:
                    logger.info("Jev is not configured")
                    warnings.append("Jev is not configured; set TYPESAFE_API_KEY.")
            else:
                logger.info(
                    "No skill, agent, or MCP configuration files identified for AI review among %d collected files",
                    len(files),
                )
                warnings.append(
                    "No agent skills, agent files, or MCP configuration files were identified for AI inspection."
                )
        if not files:
            logger.info(
                "No agent skills, agent files, or MCP configuration files were found in repository %s",
                snapshot["repository"],
            )
            warnings = [
                "No agent skills, agent definition files, or MCP configurations exist in this repository. AI analysis was not run.",
            ]
            providers = {
                "fireworks": "Not applicable (no agent files)",
                "jev": "Not applicable (no agent files)",
            }
            verdict = "No agent, skill, or MCP files found"
            coverage_status = "No agent, skill, or MCP files detected"
        else:
            if mode == "demo":
                warnings.insert(
                    0,
                    "Sample report: fictional files and static rules only. No AI calls were made.",
                )
            gaps = bool(snapshot["skipped"] or snapshot["tree_truncated"])
            complete = (
                mode == "live"
                and bool(files)
                and not gaps
                and all(v != "Not run" for v in providers.values())
            )
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
            coverage_status = (
                "Bounded scan completed" if complete else "Incomplete / limited assessment"
            )
        return {
            "repository": snapshot["repository"],
            "commit": snapshot["commit"],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "mode": mode,
            "verdict": verdict,
            "coverage_status": coverage_status,
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
