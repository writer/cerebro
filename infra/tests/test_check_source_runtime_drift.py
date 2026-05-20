from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.check_source_runtime_drift import _normalize_api_url, find_drift


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


if __name__ == "__main__":
    unittest.main()
