import json
import tempfile
import unittest
from pathlib import Path

import scripts.droid_sast_context as ctx


class DroidSastContextTests(unittest.TestCase):
    def test_collect_deepsec_scan_context_reports_changed_file_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / ".deepsec"
            files_dir = workspace / "data" / "cerebro" / "files" / "internal"
            files_dir.mkdir(parents=True)
            (files_dir / "handler.go.json").write_text(
                json.dumps(
                    {
                        "filePath": "internal/handler.go",
                        "lastScannedRunId": "run-1",
                        "candidates": [
                            {
                                "vulnSlug": "go-ssrf",
                                "lineNumbers": [42],
                                "matchedPattern": "http.Get(userURL)",
                                "snippet": "http.Get(userURL)",
                            },
                            {
                                "vulnSlug": "go-ssrf",
                                "lineNumbers": [7, 42],
                                "matchedPattern": "http.Get(userURL)",
                                "snippet": "http.Get(userURL)",
                            },
                            {
                                "vulnSlug": "process-env-access",
                                "lineNumbers": [7],
                                "matchedPattern": "os.Getenv",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )

            findings, notes = ctx.collect_deepsec_scan_context(
                workspace,
                "cerebro",
                "run-1",
                ["internal/handler.go"],
                {"internal/handler.go": {42}},
            )

        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["rule"], "go-ssrf")
        self.assertEqual(findings[0]["severity"], "INFO")
        self.assertEqual(findings[0]["confidence"], "SIGNAL")
        self.assertEqual(findings[0]["line"], 42)
        self.assertTrue(findings[0]["changed_line"])
        self.assertFalse(findings[1]["changed_line"])
        self.assertIn("3 candidate(s)", notes[0])
        self.assertIn("3 candidate(s) on changed files", notes[0])

    def test_collect_deepsec_scan_context_filters_unchanged_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / ".deepsec"
            files_dir = workspace / "data" / "cerebro" / "files" / "api"
            files_dir.mkdir(parents=True)
            (files_dir / "spec_embed.go.json").write_text(
                json.dumps(
                    {
                        "filePath": "api/spec_embed.go",
                        "lastScannedRunId": "run-1",
                        "candidates": [{"vulnSlug": "go-embed-asset", "lineNumbers": [7]}],
                    }
                ),
                encoding="utf-8",
            )

            findings, notes = ctx.collect_deepsec_scan_context(
                workspace,
                "cerebro",
                "run-1",
                ["internal/handler.go"],
                {"internal/handler.go": {42}},
            )

        self.assertEqual(findings, [])
        self.assertIn("1 candidate(s)", notes[0])
        self.assertIn("0 candidate(s) on changed files", notes[0])


if __name__ == "__main__":
    unittest.main()
