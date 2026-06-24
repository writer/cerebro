from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest


spec = importlib.util.spec_from_file_location(
    "verify_latest_runtime_contracts",
    Path(__file__).resolve().parents[1] / "scripts" / "verify_latest_runtime_contracts.py",
)
verify_latest_runtime_contracts = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = verify_latest_runtime_contracts
spec.loader.exec_module(verify_latest_runtime_contracts)


class VerifyLatestRuntimeContractsTest(unittest.TestCase):
    def _write_contract(self, root: Path, environment: str, image_tag: str = "v2.1.60") -> Path:
        contract = root / f"cerebro-runtime-contract-{environment}.json"
        contract.write_text(
            json.dumps(
                {
                    "schema_version": "cerebro.runtime-deploy-contract/v1",
                    "image_tag": image_tag,
                    "required_secrets": [],
                    "sources": [
                        {
                            "source_id": "aws",
                            "supported_families": ["public_endpoint"],
                            "runtimes": [],
                            "source_health_receipt": {
                                "receipt_kind": "source_health.receipt",
                                "source_type": "cloud_api",
                                "auth_model": "aws_sigv4",
                                "adapter_health_path": "sts:GetCallerIdentity",
                                "expected_cadence_seconds": 86400,
                                "stale_after_seconds": 86400,
                                "evidence_cas_reference_kind": "aws.evidence_cas_reference",
                            },
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        return contract

    def _write_stack(self, root: Path, environment: str, image_tag: str = "v2.1.1") -> Path:
        stack = root / f"Pulumi.{environment}.yaml"
        stack.write_text(
            f"""
config:
  cerebro:imageTag: {image_tag}
  cerebro:environment: {environment}
  cerebro:graphAgentLlmProvider: openrouter
  cerebro:graphAgentLlmModel: anthropic/claude-sonnet-4.6
  cerebro:openrouterApiKeySecret: OPENROUTER_RUNTIME_TOKEN
  cerebro:sourceRuntimes:
    - id: writer-aws-public-endpoint
      sourceId: aws
      tenantId: writer
      config:
        family: public_endpoint
        region: us-east-1
""",
            encoding="utf-8",
        )
        return stack

    def test_verify_environment_simulates_image_tag_promotion(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw)
            contract = self._write_contract(root, "sec-dev")
            stack = self._write_stack(root, "sec-dev", image_tag="v2.1.1")

            errors = verify_latest_runtime_contracts.verify_environment("sec-dev", contract, stack)

        self.assertEqual(errors, [])

    def test_verify_contracts_reports_missing_environment_contract(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw)
            stack = self._write_stack(root, "go-prod")

            errors = verify_latest_runtime_contracts.verify_contracts({}, {"go-prod": stack})

        self.assertEqual(errors, ["go-prod: missing runtime contract"])

    def test_parse_mapping_requires_environment_and_path(self) -> None:
        self.assertEqual(
            verify_latest_runtime_contracts._parse_mapping("sec-dev=aws/Pulumi.sec-dev.yaml"),
            ("sec-dev", Path("aws/Pulumi.sec-dev.yaml")),
        )
        with self.assertRaises(Exception):
            verify_latest_runtime_contracts._parse_mapping("aws/Pulumi.sec-dev.yaml")


if __name__ == "__main__":
    unittest.main()
