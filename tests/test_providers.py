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
