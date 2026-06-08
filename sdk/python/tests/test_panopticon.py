import os
import unittest
from pathlib import Path
from unittest.mock import patch

import cerebro_sdk.panopticon as panopticon


class RecordingClient:
    requests = []

    def __init__(self, base_url, api_key=None):
        self.base_url = base_url
        self.api_key = api_key

    def put_source_runtime(self, runtime_id, runtime):
        self.requests.append(("PUT", f"/source-runtimes/{runtime_id}", {"runtime": runtime}))
        return {"runtime": {"id": runtime_id, **runtime}}

    def write_claims(self, runtime_id, claims, options=None):
        payload = dict(options or {})
        payload["claims"] = claims
        self.requests.append(("POST", f"/source-runtimes/{runtime_id}/claims", payload))
        return {"claims_written": len(claims)}

    def list_claims(self, runtime_id, filters=None):
        self.requests.append(("GET", f"/source-runtimes/{runtime_id}/claims", dict(filters or {})))
        return {"claims": []}

    def integration(self, runtime_id, tenant_id, integration):
        from cerebro_sdk.client import IntegrationClient

        return IntegrationClient(self, runtime_id=runtime_id, tenant_id=tenant_id, integration=integration)


class PanopticonPushClaimTests(unittest.TestCase):
    def setUp(self) -> None:
        RecordingClient.requests = []

    def test_onboard_panopticon_push_claims_writes_exact_canonical_claim_payload(self) -> None:
        raw_claims = [
            {
                "subject_ref": {
                    "urn": "urn:cerebro:writer:runtime:writer-panopticon-push:alert:alert-123",
                    "entity_type": "alert",
                    "label": "Alert 123",
                },
                "subject_urn": "urn:cerebro:writer:runtime:writer-panopticon-push:alert:alert-123",
                "predicate": "exists",
                "claim_type": "existence",
                "status": "asserted",
                "source_event_id": "panopticon-alert-123",
                "observed_at": "2026-06-08T12:00:00Z",
                "valid_from": "2026-06-08T12:00:00Z",
                "attributes": {"family": "alert", "severity": "high"},
            },
            {
                "subject_ref": {
                    "urn": "urn:cerebro:writer:runtime:writer-panopticon-push:alert:alert-123",
                    "entity_type": "alert",
                    "label": "Alert 123",
                },
                "subject_urn": "urn:cerebro:writer:runtime:writer-panopticon-push:alert:alert-123",
                "predicate": "severity",
                "object_value": "high",
                "claim_type": "attribute",
                "status": "asserted",
                "source_event_id": "panopticon-alert-123",
                "observed_at": "2026-06-08T12:00:00Z",
                "valid_from": "2026-06-08T12:00:00Z",
                "attributes": {"family": "alert"},
            },
            {
                "subject_ref": {
                    "urn": "urn:cerebro:writer:runtime:writer-panopticon-push:alert:alert-123",
                    "entity_type": "alert",
                    "label": "Alert 123",
                },
                "subject_urn": "urn:cerebro:writer:runtime:writer-panopticon-push:alert:alert-123",
                "predicate": "linked_to_case",
                "object_ref": {
                    "urn": "urn:cerebro:writer:runtime:writer-panopticon-push:case:case-9",
                    "entity_type": "case",
                    "label": "Case 9",
                },
                "object_urn": "urn:cerebro:writer:runtime:writer-panopticon-push:case:case-9",
                "claim_type": "relation",
                "status": "asserted",
                "source_event_id": "panopticon-alert-123",
                "observed_at": "2026-06-08T12:00:00Z",
                "valid_from": "2026-06-08T12:00:00Z",
                "attributes": {"family": "alert", "relation_source": "panopticon"},
            },
            {
                "subject_ref": {
                    "urn": "urn:cerebro:writer:runtime:writer-panopticon-push:ioc:ioc-7",
                    "entity_type": "ioc",
                    "label": "IOC 7",
                },
                "subject_urn": "urn:cerebro:writer:runtime:writer-panopticon-push:ioc:ioc-7",
                "predicate": "classification",
                "object_value": "malicious_ip",
                "claim_type": "classification",
                "status": "asserted",
                "source_event_id": "panopticon-ioc-7",
                "observed_at": "2026-06-08T12:05:00Z",
                "valid_from": "2026-06-08T12:05:00Z",
                "attributes": {"family": "ioc", "ioc_type": "ip"},
            },
        ]

        with patch.object(panopticon, "Client", RecordingClient):
            result = panopticon.onboard_panopticon_push_claims(
                "https://cerebro.example.com",
                "writer",
                "writer-panopticon-push",
                raw_claims,
                api_key="test-key",
            )

        self.assertEqual(result["write_result"], {"claims_written": 4})
        self.assertEqual(result["submitted_claims"], raw_claims)
        self.assertEqual(
            RecordingClient.requests,
            [
                (
                    "PUT",
                    "/source-runtimes/writer-panopticon-push",
                    {
                        "runtime": {
                            "source_id": "sdk",
                            "tenant_id": "writer",
                            "config": {"integration": "panopticon", "source": "panopticon", "mode": "push_claims"},
                        }
                    },
                ),
                (
                    "POST",
                    "/source-runtimes/writer-panopticon-push/claims",
                    {"replace_existing": True, "claims": raw_claims},
                ),
            ],
        )
        for claim in result["submitted_claims"]:
            self.assertIn(claim["claim_type"], panopticon.SUPPORTED_CLAIM_TYPES)
            self.assertTrue(all(isinstance(key, str) and isinstance(value, str) for key, value in claim.get("attributes", {}).items()))
            self.assertFalse(any(key in claim for key in ("subjectUrn", "objectValue", "claimType", "sourceEventId", "observedAt", "validFrom")))

    def test_build_panopticon_push_claims_rejects_unsupported_claim_types(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported claim_type"):
            panopticon.build_panopticon_push_claims(
                [
                    {
                        "subject_urn": "urn:cerebro:writer:runtime:writer-panopticon-push:alert:alert-123",
                        "predicate": "severity",
                        "object_value": "high",
                        "claim_type": "finding",
                    }
                ]
            )

    def test_build_panopticon_push_claims_rejects_non_string_attributes(self) -> None:
        with self.assertRaisesRegex(ValueError, r"attributes\.severity must be a string"):
            panopticon.build_panopticon_push_claims(
                [
                    {
                        "subject_urn": "urn:cerebro:writer:runtime:writer-panopticon-push:alert:alert-123",
                        "predicate": "severity",
                        "object_value": "high",
                        "claim_type": "attribute",
                        "attributes": {"severity": 3},
                    }
                ]
            )

    def test_build_panopticon_push_claims_rejects_noncanonical_field_names(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported field"):
            panopticon.build_panopticon_push_claims(
                [
                    {
                        "subjectUrn": "urn:cerebro:writer:runtime:writer-panopticon-push:alert:alert-123",
                        "predicate": "exists",
                        "claim_type": "existence",
                    }
                ]
            )

    def test_onboard_panopticon_push_claims_validates_before_runtime_upsert(self) -> None:
        with patch.object(panopticon, "Client", RecordingClient):
            with self.assertRaisesRegex(ValueError, "unsupported claim_type"):
                panopticon.onboard_panopticon_push_claims(
                    "https://cerebro.example.com",
                    "writer",
                    "writer-panopticon-push",
                    [
                        {
                            "subject_urn": "urn:cerebro:writer:runtime:writer-panopticon-push:alert:alert-123",
                            "predicate": "bad",
                            "claim_type": "unsupported",
                        }
                    ],
                )

        self.assertEqual(RecordingClient.requests, [])

    def test_no_claim_archive_ingestion_route_or_source_is_registered(self) -> None:
        repo_root = Path(__file__).resolve().parents[3]
        routes = (repo_root / "internal" / "bootstrap" / "routes.go").read_text()
        self.assertIn('"POST /source-runtimes/{runtimeID}/claims"', routes)
        self.assertNotIn("/claims/ndjson", routes.lower())
        self.assertNotIn("/claims/import", routes.lower())
        self.assertNotIn("claims-ndjson", routes.lower())

        searched_roots = [
            repo_root / "internal",
            repo_root / "sources",
            repo_root / "sdk" / "python" / "cerebro_sdk",
            repo_root / "scripts",
        ]
        blocked_fragments = ("claims-ndjson", "claims_ndjson", "claimsndjson")
        for root in searched_roots:
            for path in root.rglob("*"):
                if path.is_dir() or path.suffix not in {".go", ".py", ".yaml", ".yml", ".json"}:
                    continue
                rel = os.fspath(path.relative_to(repo_root))
                text = path.read_text(errors="ignore").lower()
                for fragment in blocked_fragments:
                    self.assertNotIn(fragment, text, f"{fragment} unexpectedly present in {rel}")


if __name__ == "__main__":
    unittest.main()
