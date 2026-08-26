import io
import json
import unittest
from urllib.error import HTTPError
from unittest.mock import patch

from cerebro.graph.v1 import organizational_graph_pb2
from cerebro_sdk.client import APIError, Client


class FakeResponse:
    headers = {"Content-Type": "application/json"}

    def __init__(self, payload):
        self._body = json.dumps(payload).encode("utf-8")

    def read(self):
        return self._body

    def close(self):
        pass


class GraphNeighborhoodContractTests(unittest.TestCase):
    def test_caller_uses_bounded_product_route_and_preserves_auth_and_scope(self) -> None:
        seen = {}
        root_urn = "urn:cerebro:tenant-a:repository:writer/cerebro"
        fixture_token = "-".join(("fixture", "sdk", "token"))

        def fake_urlopen(req, timeout):
            seen["url"] = req.full_url
            seen["method"] = req.get_method()
            seen["headers"] = {key.lower(): value for key, value in req.header_items()}
            seen["timeout"] = timeout
            return FakeResponse(
                {
                    "root": {"urn": root_urn, "entity_type": "repository", "label": "cerebro"},
                    "neighbors": [{"urn": "urn:cerebro:tenant-a:user:alice", "entity_type": "user", "label": "Alice"}],
                    "relations": [{"from_urn": root_urn, "relation": "owned_by", "to_urn": "urn:cerebro:tenant-a:user:alice"}],
                }
            )

        client = Client("https://cerebro.example.com/api/", api_key=fixture_token, timeout=7)
        with patch("cerebro_sdk.client.request.urlopen", fake_urlopen):
            result = client.get_entity_neighborhood(f" {root_urn} ", 50)

        self.assertEqual(result["root"]["urn"], root_urn)
        self.assertEqual(result["neighbors"][0]["entity_type"], "user")
        self.assertEqual(result["relations"][0]["relation"], "owned_by")
        self.assertEqual(seen["method"], "GET")
        self.assertEqual(
            seen["url"],
            "https://cerebro.example.com/api/platform/graph/neighborhood?root_urn=urn%3Acerebro%3Atenant-a%3Arepository%3Awriter%2Fcerebro&limit=50",
        )
        self.assertEqual(seen["headers"]["authorization"], f"Bearer {fixture_token}")
        self.assertEqual(seen["headers"]["accept"], "application/json")
        self.assertNotIn("tenant_id", seen["url"])
        self.assertNotIn("workspace_id", seen["url"])
        self.assertEqual(seen["timeout"], 7)

    def test_caller_forwards_limits_for_authority_clamping_and_preserves_errors(self) -> None:
        seen = {}
        fixture_token = "-".join(("fixture", "sdk", "token"))

        def fake_urlopen(req, timeout):
            seen["url"] = req.full_url
            seen["headers"] = {key.lower(): value for key, value in req.header_items()}
            raise HTTPError(
                req.full_url,
                503,
                "Service Unavailable",
                {"Content-Type": "application/json"},
                io.BytesIO(
                    b'{"error":"graph runtime unavailable","code":"graph_unavailable"}'
                ),
            )

        client = Client("https://cerebro.example.com", api_key=fixture_token)
        with patch("cerebro_sdk.client.request.urlopen", fake_urlopen):
            with self.assertRaises(APIError) as raised:
                client.get_entity_neighborhood("urn:cerebro:tenant-a:repository:writer/cerebro", 51)

        self.assertEqual(raised.exception.status_code, 503)
        self.assertEqual(raised.exception.code, "graph_unavailable")
        self.assertIn("graph runtime unavailable", str(raised.exception))
        self.assertNotIn(fixture_token, str(raised.exception))
        self.assertIn("limit=51", seen["url"])
        self.assertEqual(seen["headers"]["authorization"], f"Bearer {fixture_token}")

    def test_caller_rejects_an_empty_root_before_request(self) -> None:
        requests = 0

        def fake_urlopen(req, timeout):
            nonlocal requests
            requests += 1
            return FakeResponse({})

        client = Client("https://cerebro.example.com")
        with patch("cerebro_sdk.client.request.urlopen", fake_urlopen):
            with self.assertRaisesRegex(ValueError, "root_urn is required"):
                client.get_entity_neighborhood("  \t")

        self.assertEqual(requests, 0)


class GeneratedGraphContractTests(unittest.TestCase):
    def test_generated_connect_descriptor_keeps_typed_expand_contract(self) -> None:
        service = organizational_graph_pb2.DESCRIPTOR.services_by_name["OrganizationalGraphService"]
        expand = service.methods_by_name["Expand"]

        self.assertEqual(expand.input_type.full_name, "cerebro.graph.v1.ExpandRequest")
        self.assertEqual(expand.output_type.full_name, "cerebro.graph.v1.ExpandResponse")
        self.assertEqual(
            [(field.name, field.number) for field in expand.input_type.fields],
            [("tenant_id", 1), ("root_key", 2), ("depth", 3), ("limit", 4)],
        )
        self.assertEqual(
            [(field.name, field.number) for field in expand.output_type.fields],
            [("tenant_id", 1), ("graph_revision", 2), ("root", 3), ("entities", 4), ("edges", 5), ("truncated", 6)],
        )


if __name__ == "__main__":
    unittest.main()
