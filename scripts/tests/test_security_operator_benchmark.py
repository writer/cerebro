import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import scripts.security_operator_benchmark as benchmark


def test_scenario(tenant_id):
    return {
        "tenant_id": tenant_id,
        "expected": {
            "finding_rule_id": "public-to-privileged",
            "resource_urn": "urn:cerebro:benchmark:asset:1",
            "minimum_severity": "HIGH",
        },
    }


class SecurityOperatorBenchmarkTests(unittest.TestCase):
    def test_compares_complete_security_journey_and_writes_redacted_receipt(self):
        with benchmark_server() as origin, tempfile.TemporaryDirectory() as tmp:
            scenario = Path(tmp) / "scenario.json"
            scenario.write_text(
                json.dumps(test_scenario("tenant-secret")), encoding="utf-8"
            )
            json_out = Path(tmp) / "receipt.json"
            markdown_out = Path(tmp) / "receipt.md"

            code = benchmark.main(
                [
                    "--baseline-url",
                    origin,
                    "--candidate-url",
                    origin,
                    "--scenario",
                    str(scenario),
                    "--samples",
                    "3",
                    "--warmup",
                    "0",
                    "--json-out",
                    str(json_out),
                    "--markdown-out",
                    str(markdown_out),
                ]
            )

            self.assertEqual(code, 0)
            receipt_text = json_out.read_text(encoding="utf-8")
            receipt = json.loads(receipt_text)
            self.assertEqual(receipt["status"], "passed")
            self.assertEqual(receipt["baseline"]["journeys"], 3)
            self.assertEqual(receipt["candidate"]["journeys"], 3)
            self.assertEqual(receipt["candidate"]["actionable_answer_rate"], 1.0)
            self.assertEqual(receipt["candidate"]["question_coverage_rate"], 1.0)
            self.assertEqual(receipt["comparison"]["answer_retention_rate"], 1.0)
            self.assertEqual(receipt["comparison"]["semantic_parity_rate"], 1.0)
            self.assertNotIn("tenant-secret", receipt_text)
            self.assertIn("Decision measured", markdown_out.read_text(encoding="utf-8"))

    def test_fails_when_candidate_loses_actionable_security_context(self):
        with (
            benchmark_server(incomplete=True) as origin,
            tempfile.TemporaryDirectory() as tmp,
        ):
            scenario = Path(tmp) / "scenario.json"
            scenario.write_text(
                json.dumps(test_scenario("benchmark")), encoding="utf-8"
            )
            code = benchmark.main(
                [
                    "--baseline-url",
                    origin,
                    "--candidate-url",
                    origin,
                    "--scenario",
                    str(scenario),
                    "--samples",
                    "1",
                    "--warmup",
                    "0",
                    "--json-out",
                    str(Path(tmp) / "receipt.json"),
                    "--markdown-out",
                    str(Path(tmp) / "receipt.md"),
                ]
            )
            self.assertEqual(code, 1)

    def test_passes_when_candidate_adds_missing_answers_without_changing_existing_ones(
        self,
    ):
        with (
            benchmark_server(inventory_unavailable=True) as baseline,
            benchmark_server() as candidate,
            tempfile.TemporaryDirectory() as tmp,
        ):
            scenario = Path(tmp) / "scenario.json"
            scenario.write_text(
                json.dumps(test_scenario("benchmark")), encoding="utf-8"
            )
            receipt_path = Path(tmp) / "receipt.json"
            code = benchmark.main(
                [
                    "--baseline-url",
                    baseline,
                    "--candidate-url",
                    candidate,
                    "--scenario",
                    str(scenario),
                    "--samples",
                    "2",
                    "--warmup",
                    "0",
                    "--json-out",
                    str(receipt_path),
                    "--markdown-out",
                    str(Path(tmp) / "receipt.md"),
                ]
            )
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(code, 0)
            self.assertEqual(receipt["baseline"]["question_coverage_rate"], 0.5)
            self.assertEqual(receipt["candidate"]["question_coverage_rate"], 1.0)
            self.assertEqual(
                receipt["comparison"]["question_coverage_uplift_points"], 50.0
            )
            self.assertEqual(
                receipt["comparison"]["actionable_answer_uplift_points"], 100.0
            )
            self.assertEqual(receipt["comparison"]["answer_retention_rate"], 1.0)
            self.assertEqual(receipt["comparison"]["semantic_parity_rate"], 1.0)
            self.assertFalse(receipt["comparison"]["latency_comparable"])

    def test_rejects_target_url_credentials(self):
        with self.assertRaises(benchmark.BenchmarkUsageError):
            benchmark.normalize_origin("https://user:secret@example.com")


class benchmark_server:
    def __init__(self, incomplete=False, inventory_unavailable=False):
        self.incomplete = incomplete
        self.inventory_unavailable = inventory_unavailable

    def __enter__(self):
        incomplete = self.incomplete
        inventory_unavailable = self.inventory_unavailable

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if inventory_unavailable and self.path.startswith(
                    "/grc/inventory/assets"
                ):
                    self.send_error(503)
                    return
                if self.path.startswith("/grc/findings"):
                    payload = {
                        "findings": [
                            {
                                "id": "finding-1",
                                "rule_id": "public-to-privileged",
                                "severity": "CRITICAL",
                                "resource_urns": ["urn:cerebro:benchmark:asset:1"],
                                "owner": "security",
                                "evidence_count": 2,
                                "risk_score": 95,
                                "risk_reasons": ["public to privileged"],
                            }
                        ]
                    }
                elif self.path.startswith("/platform/graph/attack-paths"):
                    edge = {"source_id": "inventory", "source_event_id": "event-1"}
                    payload = {
                        "paths": [
                            {
                                "exposed_resource": {
                                    "urn": "urn:cerebro:benchmark:asset:1"
                                },
                                "exposure_edge": edge,
                                "resource_account_edge": edge,
                                "privilege_edge": edge,
                                "permission_account_edge": edge,
                            }
                        ]
                    }
                elif self.path.startswith("/grc/inventory/assets/detail"):
                    payload = {
                        "asset": {"urn": "urn:cerebro:benchmark:asset:1"},
                        "findings": [
                            {"id": "finding-1", "rule_id": "public-to-privileged"}
                        ],
                        "evidence": [{"id": "evidence-1"}],
                        "actions": [] if incomplete else [{"kind": "remediate"}],
                    }
                else:
                    payload = {"assets": [{"urn": "urn:cerebro:benchmark:asset:1"}]}
                body = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        return f"http://{host}:{port}"

    def __exit__(self, exc_type, exc, tb):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
