import threading
import time
import unittest
from unittest.mock import Mock

from app.config import Settings
from app.errors import ScanError
from app.scanning.assessment import AssessmentService
from app.web.jobs import JobManager


class JobTests(unittest.TestCase):
    def wait_for_job(self, manager, job_id):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            job = manager.get(job_id)
            if job["status"] != "running":
                return job
            time.sleep(0.01)
        self.fail("Background job did not finish")

    def test_capacity_is_released_after_failure(self):
        started = threading.Event()
        release = threading.Event()

        def fail(*args):
            started.set()
            release.wait(3)
            raise ScanError("Provider unavailable")

        service = Mock(spec=AssessmentService)
        service.assess.side_effect = fail
        manager = JobManager(Settings(), service, max_concurrent=1)
        job_id = manager.submit("", demo=True)
        try:
            self.assertTrue(started.wait(1))
            self.assertIsNone(manager.submit("", demo=True))
        finally:
            release.set()
        job = self.wait_for_job(manager, job_id)
        self.assertEqual(job["status"], "failed")
        self.assertEqual(job["message"], "Provider unavailable")
        next_id = manager.submit("", demo=True)
        self.assertIsNotNone(next_id)
        self.wait_for_job(manager, next_id)

    def test_managers_do_not_share_reports_and_reads_are_copies(self):
        service = AssessmentService.from_settings(Settings())
        first = JobManager(Settings(), service)
        second = JobManager(Settings(), service)
        job_id = first.submit("", demo=True)
        job = self.wait_for_job(first, job_id)
        self.assertIsNone(second.get(job_id))
        job["report"]["findings"].clear()
        self.assertEqual(len(first.get(job_id)["report"]["findings"]), 5)

    def test_unexpected_errors_do_not_leak_details(self):
        service = Mock(spec=AssessmentService)
        service.assess.side_effect = RuntimeError("secret internal detail")
        manager = JobManager(Settings(), service)
        job = self.wait_for_job(manager, manager.submit("", demo=True))
        self.assertEqual(job["status"], "failed")
        self.assertNotIn("secret", job["message"])
