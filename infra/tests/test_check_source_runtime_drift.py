from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import datetime
from io import BytesIO
from pathlib import Path
from urllib.error import HTTPError
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.check_source_runtime_drift import Drift, _load_actual, _load_stack_runtimes, _normalize_api_url, _summary_markdown, find_drift


EXPECTED = {
    "writer-okta-audit": {
        "id": "writer-okta-audit",
        "sourceId": "okta",
        "tenantId": "writer",
        "config": {
            "domain": "env:OKTA_DOMAIN",
            "family": "audit",
            "per_page": "200",
        },
    }
}


class SourceRuntimeDriftTest(unittest.TestCase):
    def _stack_file(self, domain: str = "cerebro.adm.prod.writer.com") -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "Pulumi.go-prod.yaml"
        path.write_text(
            "config:\n"
            f"  cerebro:domain: {domain}\n"
            "  cerebro:sourceRuntimes: []\n",
            encoding="utf-8",
        )
        return path

    def test_matching_runtime_has_no_drift(self) -> None:
        actual = [{
            "id": "writer-okta-audit",
            "source_id": "okta",
            "tenant_id": "writer",
            "config": {"family": "audit", "per_page": "200"},
        }]

        self.assertEqual(find_drift(EXPECTED, actual), [])

    def test_missing_runtime_is_error(self) -> None:
        drift = find_drift(EXPECTED, [])

        self.assertTrue(any(finding.severity == "error" and "missing" in finding.message for finding in drift))

    def test_config_mismatch_is_error(self) -> None:
        actual = [{
            "id": "writer-okta-audit",
            "source_id": "okta",
            "tenant_id": "writer",
            "config": {"family": "user", "per_page": "200"},
        }]

        drift = find_drift(EXPECTED, actual)

        self.assertTrue(any(finding.severity == "error" and "config.family" in finding.message for finding in drift))

    def test_unexpected_runtime_is_warning(self) -> None:
        actual = [
            {"id": "writer-okta-audit", "source_id": "okta", "tenant_id": "writer", "config": {"family": "audit"}},
            {"id": "writer-extra", "source_id": "okta", "tenant_id": "writer", "config": {}},
        ]

        drift = find_drift(EXPECTED, actual)

        self.assertTrue(any(finding.severity == "warning" and finding.runtime_id == "writer-extra" for finding in drift))

    def test_allowed_unexpected_runtime_is_ignored(self) -> None:
        actual = [
            {"id": "writer-okta-audit", "source_id": "okta", "tenant_id": "writer", "config": {"family": "audit"}},
            {"id": "trusted-endpoint", "source_id": "sdk", "tenant_id": "writer", "config": {"managed_by": "control-plane"}},
        ]

        drift = find_drift(EXPECTED, actual, allowed_unexpected={"trusted-endpoint"})

        self.assertEqual(drift, [])

    def test_stack_external_runtimes_are_expected(self) -> None:
        path = self._stack_file()
        path.write_text(
            "config:\n"
            "  cerebro:domain: cerebro.adm.prod.writer.com\n"
            "  cerebro:sourceRuntimes:\n"
            "    - id: writer-okta-audit\n"
            "      sourceId: okta\n"
            "      tenantId: writer\n"
            "      config:\n"
            "        family: audit\n"
            "  cerebro:externalSourceRuntimes:\n"
            "    - id: writer-slack-companion\n"
            "      sourceId: sdk\n"
            "      tenantId: writer\n"
            "      owner: cerebro-slack-companion\n"
            "      reason: External service runtime.\n",
            encoding="utf-8",
        )

        expected = _load_stack_runtimes(path)
        actual = [
            {"id": "writer-okta-audit", "source_id": "okta", "tenant_id": "writer", "config": {"family": "audit"}},
            {"id": "writer-slack-companion", "source_id": "sdk", "tenant_id": "writer", "config": {}},
        ]

        self.assertEqual(find_drift(expected, actual), [])

    def test_canonical_last_synced_at_satisfies_freshness_check(self) -> None:
        actual = [{
            "id": "writer-okta-audit",
            "source_id": "okta",
            "tenant_id": "writer",
            "config": {"family": "audit"},
            "last_synced_at": datetime.now().astimezone().isoformat(),
        }]

        drift = find_drift(EXPECTED, actual, max_age_hours=24)

        self.assertFalse(any(finding.check == "freshness" for finding in drift if hasattr(finding, "check")))
        self.assertFalse(any("last activity" in finding.message for finding in drift))

    def test_normalize_api_url_rewrites_alb_hostname_to_stack_domain(self) -> None:
        self.assertEqual(
            _normalize_api_url(
                "https://internal-cerebro-go-production-alb-1917539768.us-east-1.elb.amazonaws.com",
                self._stack_file(),
            ),
            "https://cerebro.adm.prod.writer.com",
        )

    def test_normalize_api_url_rewrites_scheme_less_alb_hostname_to_stack_domain(self) -> None:
        self.assertEqual(
            _normalize_api_url(
                "internal-cerebro-go-production-alb-1917539768.us-east-1.elb.amazonaws.com",
                self._stack_file(),
            ),
            "https://cerebro.adm.prod.writer.com",
        )

    def test_normalize_api_url_keeps_canonical_domain(self) -> None:
        self.assertEqual(
            _normalize_api_url("https://cerebro.adm.prod.writer.com", self._stack_file()),
            "https://cerebro.adm.prod.writer.com",
        )

    def test_normalize_api_url_uses_stack_domain_when_url_missing(self) -> None:
        self.assertEqual(_normalize_api_url("", self._stack_file()), "https://cerebro.adm.prod.writer.com")

    def test_normalize_api_url_keeps_alb_hostname_when_domain_missing(self) -> None:
        self.assertEqual(
            _normalize_api_url(
                "https://internal-cerebro-go-production-alb-1917539768.us-east-1.elb.amazonaws.com",
                self._stack_file(""),
            ),
            "https://internal-cerebro-go-production-alb-1917539768.us-east-1.elb.amazonaws.com",
        )

    def test_load_actual_includes_http_error_body(self) -> None:
        error = HTTPError(
            url="https://cerebro.example/source-runtimes",
            code=400,
            msg="Bad Request",
            hdrs={},
            fp=BytesIO(b'{"error":"limit must be <= 500"}'),
        )
        with patch("scripts.check_source_runtime_drift.urlopen", side_effect=error):
            with self.assertRaisesRegex(RuntimeError, "HTTP 400: .*limit must be <= 500"):
                _load_actual(None, "https://cerebro.example", "token", "writer", 20)

    def test_summary_markdown_lists_drift_counts(self) -> None:
        summary = _summary_markdown(
            "go-prod",
            2,
            1,
            [
                Drift("error", "writer-okta-audit", "expected runtime is missing from the live API"),
                Drift("warning", "writer-extra", "live runtime is not declared in stack config"),
            ],
        )

        self.assertIn("Status: **failed**", summary)
        self.assertIn("Declared runtimes: `2`", summary)
        self.assertIn("Live runtimes: `1`", summary)
        self.assertIn("Errors: `1`", summary)
        self.assertIn("Warnings: `1`", summary)
        self.assertIn("`writer-okta-audit`", summary)
        self.assertIn("`writer-extra`", summary)

    def test_summary_markdown_reports_success(self) -> None:
        summary = _summary_markdown("sec-dev", 1, 1, [])

        self.assertIn("Status: **passed**", summary)
        self.assertIn("Live source runtimes match the stack declaration.", summary)


if __name__ == "__main__":
    unittest.main()
