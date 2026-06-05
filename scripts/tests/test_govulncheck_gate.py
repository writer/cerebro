import tempfile
import unittest
from pathlib import Path

import scripts.govulncheck_gate as gate


class GovulncheckGateTests(unittest.TestCase):
    def test_severity_prefers_highest_affected_severity(self):
        osv = {
            "affected": [
                {"ecosystem_specific": {"severity": "MEDIUM"}},
                {"ecosystem_specific": {"severity": "CRITICAL"}},
            ]
        }
        self.assertEqual(gate.severity_from_osv(osv), "CRITICAL")

    def test_ignore_file_requires_justification(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".govulncheck-ignore"
            path.write_text("GO-2026-0001\nGO-2026-0002 # accepted until patched\n", encoding="utf-8")
            ignored, errors = gate.parse_ignore_file(path)
        self.assertEqual(ignored, {"GO-2026-0002"})
        self.assertEqual(len(errors), 1)
        self.assertIn("justification", errors[0])

    def test_finding_osv_id_accepts_string_and_object_shapes(self):
        self.assertEqual(gate.finding_osv_id({"osv": "GO-2026-0001"}), "GO-2026-0001")
        self.assertEqual(gate.finding_osv_id({"osv": {"id": "GO-2026-0002"}}), "GO-2026-0002")

    def test_parse_json_stream_accepts_pretty_concatenated_objects(self):
        output = '{\n  "osv": {"id": "GO-2026-0001"}\n}\n{\n  "finding": {"osv": "GO-2026-0001"}\n}\n'
        messages = gate.parse_json_stream(output)
        self.assertEqual(messages[0]["osv"]["id"], "GO-2026-0001")
        self.assertEqual(messages[1]["finding"]["osv"], "GO-2026-0001")


if __name__ == "__main__":
    unittest.main()
