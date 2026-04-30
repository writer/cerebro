"""Regression tests for IntegrationClient.ensure_runtime."""

from __future__ import annotations

import unittest
from typing import Any, Dict, Optional

from cerebro_sdk.client import Client, IntegrationClient


class _RecordingClient:
    def __init__(self) -> None:
        self.last_runtime_id: Optional[str] = None
        self.last_runtime: Optional[Dict[str, Any]] = None

    def put_source_runtime(self, runtime_id: str, runtime: Dict[str, Any]) -> Dict[str, Any]:
        self.last_runtime_id = runtime_id
        self.last_runtime = runtime
        return {"ok": True}


class IntegrationClientEnsureRuntimeTests(unittest.TestCase):
    def test_caller_config_cannot_override_integration(self) -> None:
        recorder = _RecordingClient()
        client = IntegrationClient(
            client=recorder,  # type: ignore[arg-type]
            runtime_id="rt-1",
            tenant_id="writer",
            integration="github",
        )
        client.ensure_runtime({"integration": "evil", "extra": "ok"})
        self.assertIsNotNone(recorder.last_runtime)
        config = recorder.last_runtime["config"]
        self.assertEqual(config["integration"], "github")
        self.assertEqual(config["extra"], "ok")

    def test_default_config_uses_integration_name(self) -> None:
        recorder = _RecordingClient()
        client = IntegrationClient(
            client=recorder,  # type: ignore[arg-type]
            runtime_id="rt-2",
            tenant_id="writer",
            integration="okta",
        )
        client.ensure_runtime()
        self.assertEqual(recorder.last_runtime["config"], {"integration": "okta"})


if __name__ == "__main__":
    unittest.main()
