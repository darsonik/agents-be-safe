import json
import unittest
from unittest.mock import patch

from app import http_client
from app.config import Settings
from app.errors import ScanError
from app.models import JevEvaluation
from app.providers.fireworks import FireworksClient
from app.providers.jev import JevClient
from app.scanning.assessment import AssessmentService
from app.scanning.demo import demo_snapshot
from app.scanning.policy import DIMENSIONS


class AssessmentTests(unittest.TestCase):
    def test_empty_files_produces_no_agent_files_verdict(self):
        snap = demo_snapshot()
        snap["files"] = []
        snap["candidate_count"] = 0
        result = AssessmentService.from_settings(Settings()).assess(snap)
        self.assertEqual(result["verdict"], "No agent, skill, or MCP files found")
        self.assertEqual(result["coverage_status"], "No agent, skill, or MCP files detected")
        self.assertTrue(
            any(
                "No agent skills, agent definition files, or MCP configurations exist" in w
                for w in result["warnings"]
            )
        )

    def test_missing_providers_never_certify_safety(self):
        snap = demo_snapshot()
        snap["files"] = [{"path": "SKILL.md", "kind": "Skill", "content": "# Hello"}]
        result = AssessmentService.from_settings(Settings()).assess(snap)
        self.assertEqual(result["verdict"], "Inconclusive")
        self.assertEqual(result["providers"]["jev"], "Not configured")
        self.assertEqual(result["provider_runs"]["jev"]["status"], "skipped")

    def test_demo_makes_no_network_calls(self):
        with patch.object(http_client, "request_json") as request:
            result = AssessmentService.from_settings(Settings()).assess(demo_snapshot(), "demo")
        request.assert_not_called()
        self.assertEqual(result["mode"], "demo")

    def test_provider_failure_retains_static_findings(self):
        settings = Settings(
            fireworks_api_key="fake", fireworks_model="test", typesafe_api_key="fake"
        )
        with patch.object(http_client, "request_json", side_effect=ScanError("Unavailable")):
            report = AssessmentService.from_settings(settings).assess(demo_snapshot())
        self.assertEqual(len(report["findings"]), 5)
        self.assertEqual(report["providers"], {"fireworks": "Failed", "jev": "Failed"})
        self.assertEqual(report["provider_runs"]["fireworks"]["reason"], "Unavailable")
        self.assertIn("Incomplete", report["coverage_status"])

    def test_failed_reasoning_with_successful_jev_is_still_incomplete(self):
        service = AssessmentService(FireworksClient("fake", "test"), JevClient("fake"))
        with (
            patch.object(FireworksClient, "analyze", side_effect=ScanError("Output truncated")),
            patch.object(
                JevClient, "evaluate", return_value=JevEvaluation({}, [0.5] * 5, "jev-test")
            ),
        ):
            report = service.assess(demo_snapshot())
        self.assertEqual(report["provider_runs"]["fireworks"]["status"], "failed")
        self.assertEqual(report["provider_runs"]["jev"]["status"], "completed")
        self.assertIn("Incomplete", report["coverage_status"])

    def test_reasoning_runs_on_every_eligible_scan(self):
        service = AssessmentService(FireworksClient("fake", "test"), JevClient(""))
        with patch.object(FireworksClient, "analyze", return_value=[]) as analyze:
            for _ in range(2):
                report = service.assess(demo_snapshot())
                self.assertEqual(report["provider_runs"]["fireworks"]["status"], "completed")
        self.assertEqual(analyze.call_count, 2)

    def test_skipped_files_keep_report_incomplete(self):
        snap = demo_snapshot()
        snap["skipped"] = [{"path": "large.py", "reason": "budget"}]
        settings = Settings(
            fireworks_api_key="fake", fireworks_model="test", typesafe_api_key="fake"
        )
        with (
            patch.object(FireworksClient, "analyze", return_value=[]),
            patch.object(JevClient, "evaluate", return_value=JevEvaluation({}, [0.5] * 5, "test")),
        ):
            result = AssessmentService.from_settings(settings).assess(snap)
        self.assertIn("Incomplete", result["coverage_status"])

    def test_both_provider_modules_produce_a_complete_report(self):
        settings = Settings(
            fireworks_api_key="fake-fw", fireworks_model="test-model", typesafe_api_key="fake-jev"
        )
        replies = [
            {
                "choices": [
                    {"finish_reason": "stop", "message": {"content": json.dumps({"findings": []})}}
                ]
            },
            {
                "model": "jev-test",
                "answers": {
                    **{key: {"type": "noul", "noul": 0.9} for key in DIMENSIONS},
                    **{f"finding_{i}": {"type": "noul", "noul": 0.9} for i in range(5)},
                },
            },
        ]
        with patch.object(http_client, "request_json", side_effect=replies) as request:
            report = AssessmentService.from_settings(settings).assess(demo_snapshot())
        self.assertEqual(report["providers"], {"fireworks": "test-model", "jev": "jev-test"})
        self.assertEqual(report["coverage_status"], "Bounded scan completed")
        self.assertEqual(report["verdict"], "High risk indicators")
        self.assertTrue(all(f["verification"] == "Supported by Jev" for f in report["findings"]))
        self.assertEqual(request.call_args_list[0].kwargs["token"], "fake-fw")
        self.assertEqual(request.call_args_list[1].kwargs["token"], "fake-jev")
