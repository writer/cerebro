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


if __name__ == "__main__":
    unittest.main()
