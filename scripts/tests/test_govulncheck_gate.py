import tempfile
import unittest
from pathlib import Path

import scripts.govulncheck_gate as gate


class GovulncheckGateTests(unittest.TestCase):
    def test_severity_reads_top_level_cvss_vectors(self):
        osv = {
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
            ]
        }
        self.assertEqual(gate.severity_from_osv(osv), "CRITICAL")

    def test_severity_prefers_highest_available_rating(self):
        osv = {
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"},
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"},
            ]
        }
        self.assertEqual(gate.severity_from_osv(osv), "CRITICAL")

    def test_unknown_and_unparsed_vector_severities_block(self):
        self.assertEqual(
            gate.severity_from_osv({"severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"}]}),
            "UNKNOWN",
        )
        self.assertTrue(gate.is_blocking_severity("UNKNOWN", "HIGH"))

    def test_low_severity_does_not_block_high_threshold(self):
        self.assertFalse(gate.is_blocking_severity("LOW", "HIGH"))

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

    def test_reachable_finding_requires_symbol_trace(self):
        self.assertFalse(gate.is_reachable_finding({"osv": "GO-2026-0001"}))
        self.assertFalse(gate.is_reachable_finding({"osv": "GO-2026-0001", "trace": [{"package": "net/http"}]}))
        self.assertTrue(gate.is_reachable_finding({"osv": "GO-2026-0001", "trace": [{"function": "ReadMIMEHeader"}]}))

    def test_parse_json_stream_accepts_pretty_concatenated_objects(self):
        output = '{\n  "osv": {"id": "GO-2026-0001"}\n}\n{\n  "finding": {"osv": "GO-2026-0001"}\n}\n'
        messages = gate.parse_json_stream(output)
        self.assertEqual(messages[0]["osv"]["id"], "GO-2026-0001")
        self.assertEqual(messages[1]["finding"]["osv"], "GO-2026-0001")


if __name__ == "__main__":
    unittest.main()
