from __future__ import annotations

import hashlib
import importlib.util
import json
import unittest
from pathlib import Path


spec = importlib.util.spec_from_file_location("neo4j", Path(__file__).resolve().parents[1] / "aws" / "neo4j.py")
neo4j = importlib.util.module_from_spec(spec)
spec.loader.exec_module(neo4j)


class RuntimeSecretTest(unittest.TestCase):
    def test_api_credentials_json_hashes_legacy_api_keys(self) -> None:
        payload = json.loads(neo4j._api_credentials_json_from_api_keys("token-a:principal-a:writer,token-b"))

        self.assertEqual(
            payload,
            [
                {
                    "client_id": "legacy-api-key",
                    "credential_id": "legacy-api-key-1",
                    "key_sha256": hashlib.sha256(b"token-a").hexdigest(),
                    "principal": "principal-a",
                    "tenant_id": "writer",
                },
                {
                    "client_id": "legacy-api-key",
                    "credential_id": "legacy-api-key-2",
                    "key_sha256": hashlib.sha256(b"token-b").hexdigest(),
                    "principal": "legacy-api-key-2",
                    "tenant_id": "writer",
                },
            ],
        )

    def test_api_credentials_json_omits_plaintext_tokens(self) -> None:
        payload = neo4j._api_credentials_json_from_api_keys("secret-token")

        self.assertNotIn("secret-token", payload)

    def test_configured_api_credentials_override_legacy_derivation(self) -> None:
        configured = json.dumps(
            [
                {
                    "credential_id": "service-b",
                    "client_id": "service-client",
                    "principal": "service-principal",
                    "tenant_id": "writer",
                    "key_sha256": "B" * 64,
                    "kind": "service",
                    "name": "Service B",
                    "scopes": ["write", "read"],
                },
                {
                    "credential_id": "service-a",
                    "client_id": "service-client",
                    "principal": "service-principal",
                    "tenant_id": "writer",
                    "key_sha256": "a" * 64,
                },
            ]
        )

        payload = neo4j._api_credentials_json('[{"credential_id":"legacy"}]', configured)

        parsed = json.loads(payload)
        self.assertEqual([item["credential_id"] for item in parsed], ["service-a", "service-b"])
        self.assertEqual(parsed[1]["key_sha256"], "b" * 64)
        self.assertEqual(parsed[1]["scopes"], ["read", "write"])
        self.assertNotIn("legacy", payload)

    def test_configured_api_credentials_reject_invalid_json(self) -> None:
        with self.assertRaisesRegex(ValueError, "must be valid JSON"):
            neo4j._api_credentials_json("[]", "not-json")

    def test_configured_api_credentials_require_non_empty_array(self) -> None:
        for configured in ("{}", "[]"):
            with self.subTest(configured=configured):
                with self.assertRaisesRegex(ValueError, "non-empty JSON array"):
                    neo4j._api_credentials_json("[]", configured)

    def test_configured_api_credentials_require_complete_string_fields(self) -> None:
        base = {
            "credential_id": "service",
            "client_id": "service-client",
            "principal": "service-principal",
            "tenant_id": "writer",
            "key_sha256": "a" * 64,
        }
        for field in base:
            with self.subTest(field=field):
                configured = {**base}
                configured.pop(field)
                with self.assertRaisesRegex(ValueError, "missing required fields"):
                    neo4j._api_credentials_json("[]", json.dumps([configured]))

                configured = {**base, field: " "}
                with self.assertRaisesRegex(ValueError, f"{field} must be a non-empty string"):
                    neo4j._api_credentials_json("[]", json.dumps([configured]))

    def test_configured_api_credentials_reject_unsupported_fields(self) -> None:
        configured = json.dumps(
            [
                {
                    "credential_id": "service",
                    "client_id": "service-client",
                    "principal": "service-principal",
                    "tenant_id": "writer",
                    "key_sha256": "a" * 64,
                    "api_key": "placeholder",
                }
            ]
        )

        with self.assertRaisesRegex(ValueError, "unsupported fields: api_key"):
            neo4j._api_credentials_json("[]", configured)

    def test_configured_api_credentials_require_sha256_digest(self) -> None:
        configured = json.dumps(
            [
                {
                    "credential_id": "service",
                    "client_id": "service-client",
                    "principal": "service-principal",
                    "tenant_id": "writer",
                    "key_sha256": "not-a-digest",
                }
            ]
        )

        with self.assertRaisesRegex(ValueError, "64-character hexadecimal SHA-256 digest"):
            neo4j._api_credentials_json("[]", configured)

    def test_configured_api_credentials_reject_duplicate_identity_and_digest(self) -> None:
        base = {
            "credential_id": "service-a",
            "client_id": "service-client",
            "principal": "service-principal",
            "tenant_id": "writer",
            "key_sha256": "a" * 64,
        }
        duplicate_id = [{**base}, {**base, "key_sha256": "b" * 64}]
        with self.assertRaisesRegex(ValueError, "duplicate credential_id"):
            neo4j._api_credentials_json("[]", json.dumps(duplicate_id))

        duplicate_digest = [{**base}, {**base, "credential_id": "service-b"}]
        with self.assertRaisesRegex(ValueError, "duplicate key_sha256"):
            neo4j._api_credentials_json("[]", json.dumps(duplicate_digest))

    def test_configured_api_credentials_validate_scopes(self) -> None:
        base = {
            "credential_id": "service",
            "client_id": "service-client",
            "principal": "service-principal",
            "tenant_id": "writer",
            "key_sha256": "a" * 64,
        }
        for scopes in ([], ["read", "read"], ["read", " "]):
            with self.subTest(scopes=scopes):
                with self.assertRaisesRegex(ValueError, "scopes"):
                    neo4j._api_credentials_json("[]", json.dumps([{**base, "scopes": scopes}]))

    def test_blank_api_credentials_use_legacy_derivation(self) -> None:
        legacy = '[{"credential_id":"legacy"}]'

        payload = neo4j._api_credentials_json(legacy, " ")

        self.assertEqual(payload, legacy)


if __name__ == "__main__":
    unittest.main()
