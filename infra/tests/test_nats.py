from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "aws"))
spec = importlib.util.spec_from_file_location("nats", Path(__file__).resolve().parents[1] / "aws" / "nats.py")
nats = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = nats
spec.loader.exec_module(nats)


class NatsContainerDefinitionTest(unittest.TestCase):
    def test_nats_containers_are_hardened(self) -> None:
        containers = json.loads(
            nats._build_container_definitions(
                name="cerebro-sec-dev",
                log_group_name="/ecs/cerebro-sec-dev/nats",
                region="us-east-1",
                stream_name="CEREBRO_EVENTS",
                subject_prefix="events",
                lag_probe_image="probe:latest",
                lag_probe_interval_seconds=60,
                enable_lag_probe=True,
            )
        )
        by_name = {container["name"]: container for container in containers}

        self.assertEqual(by_name["nats"]["user"], "10001")
        self.assertIs(by_name["nats"]["readonlyRootFilesystem"], True)
        self.assertEqual(by_name["jetstream-bootstrap"]["user"], "10001")
        self.assertEqual(by_name["jetstream-lag-probe"]["user"], "10001")
        self.assertIs(by_name["jetstream-lag-probe"]["readonlyRootFilesystem"], True)


if __name__ == "__main__":
    unittest.main()
