"""In-memory scan jobs owned by one server, with bounded concurrency and retention."""

import copy
import logging
import secrets
import threading
import time
from typing import NotRequired, TypedDict

from app.config import Settings
from app.errors import ScanError
from app.models import Report
from app.scanning.assessment import AssessmentService
from app.scanning.demo import demo_snapshot
from app.scanning.repository import collect

logger = logging.getLogger("agents_be_safe.jobs")


class Job(TypedDict):
    status: str
    message: str
    started: float
    report: NotRequired[Report]


class JobManager:
    def __init__(
        self,
        settings: Settings,
        assessment: AssessmentService,
        *,
        max_concurrent: int = 2,
    ):
        self.settings = settings
        self.assessment = assessment
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(max_concurrent)

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return copy.deepcopy(self._jobs.get(job_id))

    def submit(self, url: str, demo: bool = False) -> str | None:
        """Return None when capacity is exhausted; callers can respond with 429."""
        if not self._slots.acquire(blocking=False):
            return None
        job_id = secrets.token_urlsafe(24)
        try:
            with self._lock:
                self._prune()
                self._jobs[job_id] = {
                    "status": "running",
                    "message": "Preparing scan",
                    "started": time.time(),
                }
            logger.info("Scan job %s submitted for %s (demo=%s)", job_id, url or "(demo)", demo)
            threading.Thread(target=self._run, args=(job_id, url, demo), daemon=True).start()
        except Exception:
            with self._lock:
                self._jobs.pop(job_id, None)
            self._slots.release()
            raise
        return job_id

    def _prune(self) -> None:
        """Called only while holding the job lock."""
        expired = [
            key
            for key, job in self._jobs.items()
            if job["status"] != "running" and time.time() - job["started"] > 3600
        ]
        for key in expired:
            del self._jobs[key]
        completed = [key for key, job in self._jobs.items() if job["status"] != "running"]
        for key in completed[:-18]:
            del self._jobs[key]

    def _run(self, job_id: str, url: str, demo: bool) -> None:
        start_time = time.time()
        logger.info("[Job %s] Starting scan for url=%s (demo=%s)", job_id, url or "(demo)", demo)

        def update(message: str) -> None:
            logger.info("[Job %s] Progress: %s", job_id, message)
            with self._lock:
                self._jobs[job_id]["message"] = message

        try:
            snapshot = demo_snapshot() if demo else collect(url, update, settings=self.settings)
            report = self.assessment.assess(snapshot, "demo" if demo else "live", update)
            elapsed = time.time() - start_time
            logger.info(
                "[Job %s] Scan completed in %.1fs: verdict=%s, findings=%d, warnings=%d",
                job_id,
                elapsed,
                report.get("verdict"),
                len(report.get("findings", [])),
                len(report.get("warnings", [])),
            )
            with self._lock:
                self._jobs[job_id].update(status="completed", report=report, message="Report ready")
        except Exception as exc:
            elapsed = time.time() - start_time
            logger.warning("[Job %s] Scan failed after %.1fs: %s", job_id, elapsed, exc)
            message = (
                str(exc)
                if isinstance(exc, ScanError)
                else "Scan failed unexpectedly. Please try again."
            )
            with self._lock:
                self._jobs[job_id].update(status="failed", message=message)
        finally:
            self._slots.release()
