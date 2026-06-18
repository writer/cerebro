import json
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import scripts.load_smoke as load_smoke


class LoadSmokeTests(unittest.TestCase):
    def test_passes_against_healthy_endpoint_and_writes_outputs(self):
        with load_smoke_server() as base_url, tempfile.TemporaryDirectory() as tmp:
            json_out = Path(tmp) / "summary.json"
            markdown_out = Path(tmp) / "summary.md"

            code = load_smoke.main([
                "--base-url",
                base_url,
                "--duration",
                "0.4",
                "--rps",
                "6",
                "--concurrency",
                "2",
                "--json-out",
                str(json_out),
                "--markdown-out",
                str(markdown_out),
            ])

            self.assertEqual(code, 0)
            summary = json.loads(json_out.read_text(encoding="utf-8"))
            self.assertTrue(summary["healthy"])
            self.assertGreaterEqual(summary["request_count"], 1)
            self.assertEqual(summary["error_count"], 0)
            self.assertIn("Status: passed", markdown_out.read_text(encoding="utf-8"))

    def test_fails_when_5xx_rate_exceeds_threshold(self):
        with load_smoke_server() as base_url:
            code = load_smoke.main([
                "--base-url",
                base_url,
                "--path",
                "/fail",
                "--duration",
                "0.3",
                "--rps",
                "5",
                "--concurrency",
                "2",
                "--max-error-rate",
                "0",
            ])

            self.assertEqual(code, 1)

    def test_fails_when_p95_latency_exceeds_threshold(self):
        with load_smoke_server() as base_url:
            code = load_smoke.main([
                "--base-url",
                base_url,
                "--path",
                "/slow",
                "--duration",
                "0.3",
                "--rps",
                "4",
                "--concurrency",
                "1",
                "--max-p95-ms",
                "1",
                "--max-error-rate",
                "1",
                "--max-5xx-rate",
                "1",
            ])

            self.assertEqual(code, 1)

    def test_rejects_full_url_path(self):
        code = load_smoke.main([
            "--base-url",
            "http://127.0.0.1:1",
            "--path",
            "https://example.com/health",
        ])

        self.assertEqual(code, 2)

    def test_redacts_query_and_path_from_base_url_in_summary(self):
        args = load_smoke.build_parser().parse_args([
            "--base-url",
            "https://example.com/private?token=secret",
            "--duration",
            "0.1",
        ])

        with self.assertRaises(load_smoke.SmokeUsageError):
            load_smoke.normalize_base_url(args.base_url)

        self.assertEqual(load_smoke.safe_base_url("https://example.com/private?token=secret"), "https://example.com")


class load_smoke_server:
    def __enter__(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), LoadSmokeHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        return f"http://{host}:{port}"

    def __exit__(self, exc_type, exc, tb):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class LoadSmokeHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/fail":
            self.send_response(503)
            self.end_headers()
            self.wfile.write(b"unavailable")
            return
        if self.path == "/slow":
            time.sleep(0.04)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    unittest.main()
