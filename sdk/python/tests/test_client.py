import json
import unittest
from unittest.mock import patch

from cerebro_sdk.client import Client


class FakeResponse:
    headers = {"Content-Type": "application/json"}

    def __init__(self, payload):
        self._body = json.dumps(payload).encode("utf-8")

    def read(self):
        return self._body

    def close(self):
        pass


class ClientTests(unittest.TestCase):
    def test_list_source_runtimes_builds_supported_query_filters(self) -> None:
        seen = {}

        def fake_urlopen(req, timeout):
            seen["url"] = req.full_url
            seen["method"] = req.get_method()
            seen["timeout"] = timeout
            seen["headers"] = dict(req.header_items())
            return FakeResponse({"source_runtimes": [{"id": "runtime-1"}]})

        client = Client("https://cerebro.example.com/", api_key="test-token", timeout=7)
        with patch("cerebro_sdk.client.request.urlopen", fake_urlopen):
            result = client.list_source_runtimes(
                {
                    "runtime_id": "",
                    "runtime_ids": ["runtime-1", "runtime/2"],
                    "tenant_id": "writer",
                    "source_id": None,
                    "limit": 50,
                }
            )

        self.assertEqual(result, {"source_runtimes": [{"id": "runtime-1"}]})
        self.assertEqual(seen["method"], "GET")
        self.assertEqual(seen["timeout"], 7)
        self.assertEqual(
            seen["url"],
            "https://cerebro.example.com/source-runtimes?runtime_ids=runtime-1%2Cruntime%2F2&tenant_id=writer&limit=50",
        )
        self.assertEqual(seen["headers"].get("Authorization"), "Bearer test-token")
        self.assertEqual(seen["headers"].get("Accept"), "application/json")

    def test_list_source_runtimes_omits_empty_query(self) -> None:
        seen = {}

        def fake_urlopen(req, timeout):
            seen["url"] = req.full_url
            return FakeResponse({"source_runtimes": []})

        client = Client("https://cerebro.example.com")
        with patch("cerebro_sdk.client.request.urlopen", fake_urlopen):
            client.list_source_runtimes({"runtime_ids": [], "tenant_id": None})

        self.assertEqual(seen["url"], "https://cerebro.example.com/source-runtimes")


if __name__ == "__main__":
    unittest.main()
