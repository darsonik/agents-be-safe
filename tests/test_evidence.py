import unittest

from app.errors import ScanError
from app.scanning.demo import demo_snapshot
from app.scanning.evidence import validate_findings
from app.scanning.rules import static_findings


class EvidenceTests(unittest.TestCase):
    def test_static_evidence_is_real_and_line_numbered(self):
        snap = demo_snapshot()
        findings = static_findings(snap["files"])
        self.assertEqual(len(findings), 5)
        for f in findings:
            source = next(x["content"] for x in snap["files"] if x["path"] == f["path"])
            self.assertIn(f["evidence"], source)
        self.assertEqual(findings[0]["line"], 2)

    def test_fabricated_model_evidence_rejected(self):
        files = demo_snapshot()["files"]
        finding = static_findings(files)[0]
        finding["evidence"] = "This is invented"
        with self.assertRaises(ScanError):
            validate_findings({"findings": [finding]}, files)

    def test_line_numbers_are_computed_not_trusted(self):
        files = demo_snapshot()["files"]
        finding = static_findings(files)[0]
        finding["line"] = 999
        self.assertEqual(validate_findings({"findings": [finding]}, files)[0]["line"], 2)
