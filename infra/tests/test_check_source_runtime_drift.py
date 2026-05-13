from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.check_source_runtime_drift import find_drift


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


if __name__ == "__main__":
    unittest.main()
