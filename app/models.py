"""Shared contracts for collection, analysis, and the JSON report API."""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, NotRequired, TypedDict

Progress = Callable[[str], None]
Severity = Literal["low", "medium", "high", "critical"]
ScanMode = Literal["live", "demo"]


def ignore_progress(message: str) -> None:
    """Default progress callback for non-interactive callers."""


class SourceFile(TypedDict):
    path: str
    content: str
    kind: str


class SkippedFile(TypedDict):
    path: str
    reason: str


class Snapshot(TypedDict):
    repository: str
    commit: str
    files: list[SourceFile]
    skipped: list[SkippedFile]
    tree_truncated: bool
    candidate_count: int


class Finding(TypedDict):
    path: str
    line: int
    category: str
    severity: Severity
    title: str
    evidence: str
    explanation: str
    remediation: str
    origin: str
    verification: str
    support_probability: NotRequired[float]


@dataclass(frozen=True)
class JevEvaluation:
    """Model judgments only; application policy decides how to display them."""

    dimensions: dict[str, float]
    finding_support: list[float]
    model: str


class InspectedFile(TypedDict):
    path: str
    kind: str
    lines: int


class Report(TypedDict):
    repository: str
    commit: str
    created_at: str
    mode: ScanMode
    verdict: str
    coverage_status: str
    providers: dict[str, str]
    provider_runs: dict[str, dict[str, str]]
    dimensions: dict[str, float]
    findings: list[Finding]
    warnings: list[str]
    files: list[InspectedFile]
    skipped: list[SkippedFile]
    candidate_count: int
    tree_truncated: bool
