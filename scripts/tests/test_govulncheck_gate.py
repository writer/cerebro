import tempfile
import unittest
from pathlib import Path

import scripts.govulncheck_gate as gate


class GovulncheckGateTests(unittest.TestCase):
    def test_scanner_environment_applies_default_resource_bounds(self):
        env = gate.govulncheck_environment({"PATH": "/bin"})
        self.assertEqual(env["GOFLAGS"], "")
        self.assertEqual(env["GOTOOLCHAIN"], "go1.26.6")
        self.assertEqual(env["GOMEMLIMIT"], "4GiB")
        self.assertEqual(env["GOMAXPROCS"], "2")

    def test_scanner_environment_replaces_invalid_or_unbounded_values(self):
        cases = [
            {
                "GOMEMLIMIT": "off",
                "GOMAXPROCS": "128",
                "CEREBRO_GOVULNCHECK_GOMEMLIMIT": "100GiB",
                "CEREBRO_GOVULNCHECK_GOMAXPROCS": "0",
            },
            {
                "GOMEMLIMIT": "",
                "GOMAXPROCS": "",
                "CEREBRO_GOVULNCHECK_GOMEMLIMIT": "",
                "CEREBRO_GOVULNCHECK_GOMAXPROCS": "",
            },
            {
                "GOMEMLIMIT": "not-a-limit",
                "GOMAXPROCS": "many",
                "CEREBRO_GOVULNCHECK_GOMEMLIMIT": "malformed",
                "CEREBRO_GOVULNCHECK_GOMAXPROCS": "malformed",
            },
        ]
        for source in cases:
            with self.subTest(source=source):
                env = gate.govulncheck_environment({"GOTOOLCHAIN": "local", **source})
                self.assertEqual(env["GOTOOLCHAIN"], "local")
                self.assertEqual(env["GOMEMLIMIT"], "4GiB")
                self.assertEqual(env["GOMAXPROCS"], "2")

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
