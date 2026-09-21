import json
import unittest
from unittest.mock import patch

from app import http_client
from app.errors import ScanError
from app.providers.fireworks import FireworksClient
from app.providers.jev import JevClient
from app.scanning.assessment import annotate_support
from app.scanning.demo import demo_snapshot
from app.scanning.policy import DIMENSIONS
from app.scanning.rules import static_findings


class ProvidersTests(unittest.TestCase):
    def test_redirects_are_never_followed(self):
        with self.assertRaises(ScanError):
            http_client.NoRedirect().redirect_request(None, None, 302, "", {}, "http://127.0.0.1")

    def test_jev_contract_and_disagreement_preserved(self):
        findings = static_findings(demo_snapshot()["files"])[:1]
        answers = {k: {"type": "noul", "noul": 0.1} for k in [*DIMENSIONS, "finding_0"]}
        with (
            patch.object(
                http_client,
                "request_json",
                return_value={"answers": answers, "model": "jev-test"},
            ) as request,
        ):
            evaluation = JevClient("fake").evaluate(demo_snapshot()["files"], findings)
        self.assertNotIn("support_probability", findings[0])
        annotate_support(findings, evaluation.finding_support)
        self.assertEqual(findings[0]["verification"], "Models disagree")
        self.assertEqual(len(evaluation.dimensions), 5)
        self.assertEqual(evaluation.model, "jev-test")
        self.assertEqual(request.call_args.args[1]["questions"]["finding_0"]["type"], "noul")

    def test_jev_invalid_probabilities_fail_closed(self):
        for value in [None, True, float("nan"), 1.1, -0.1, "0.5"]:
            answers = {k: {"type": "noul", "noul": value} for k in DIMENSIONS}
            with (
                self.subTest(value=value),
                patch.object(http_client, "request_json", return_value={"answers": answers}),
                self.assertRaises(ScanError),
            ):
                JevClient("fake").evaluate([], [])

    def test_truncated_fireworks_rejected(self):
        with (
            patch.object(
                http_client,
                "request_json",
                return_value={"choices": [{"finish_reason": "length"}]},
            ),
            self.assertRaises(ScanError),
        ):
            FireworksClient("fake", "test").analyze([])

    def test_fireworks_successful_contract(self):
        files = demo_snapshot()["files"]
        finding = static_findings(files)[0]
        reply = {
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"content": json.dumps({"findings": [finding]})},
                }
            ]
        }
        with (
            patch.object(http_client, "request_json", return_value=reply) as request,
        ):
            result = FireworksClient("fake", "test").analyze(files)
        self.assertEqual(result[0]["origin"], "Fireworks")
        self.assertEqual(request.call_args.args[1]["response_format"], {"type": "json_object"})

    def test_truncated_response_retries_once_with_more_budget(self):
        replies = [
            {"choices": [{"finish_reason": "length", "message": {"content": "partial"}}]},
            {"choices": [{"finish_reason": "stop", "message": {"content": '{"findings": []}'}}]},
        ]
        with patch.object(http_client, "request_json", side_effect=replies) as request:
            self.assertEqual(FireworksClient("fake", "test").analyze([]), [])
        self.assertEqual([c.args[1]["max_tokens"] for c in request.call_args_list], [16000, 32000])

    def test_retry_exhaustion_reports_truncation(self):
        with patch.object(
            http_client, "request_json", return_value={"choices": [{"finish_reason": "length"}]}
        ) as request:
            with self.assertRaisesRegex(ScanError, "token budget after two attempts"):
                FireworksClient("fake", "test").analyze([])
        self.assertEqual(request.call_count, 2)

    def test_non_length_finish_is_not_retried(self):
        with patch.object(
            http_client,
            "request_json",
            return_value={"choices": [{"finish_reason": "content_filter"}]},
        ) as request:
            with self.assertRaisesRegex(ScanError, "content_filter"):
                FireworksClient("fake", "test").analyze([])
        self.assertEqual(request.call_count, 1)
