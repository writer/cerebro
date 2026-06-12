import importlib.util
import json
from pathlib import Path
import random
import string
import sys
from tempfile import TemporaryDirectory
import unittest


spec = importlib.util.spec_from_file_location(
    "build_deploy_preflight_receipt",
    Path(__file__).resolve().parents[1] / "scripts" / "build_deploy_preflight_receipt.py",
)
build_deploy_preflight_receipt = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = build_deploy_preflight_receipt
spec.loader.exec_module(build_deploy_preflight_receipt)


class DeployPreflightReceiptTest(unittest.TestCase):
    def _write_inputs(self, tmp: Path, *, openrouter_import_ref: str = "OPENROUTER_RUNTIME_TOKEN") -> tuple[Path, Path]:
        contract = tmp / "contract.json"
        contract.write_text(
            json.dumps(
                {
                    "schema_version": "cerebro.runtime-deploy-contract/v1",
                    "image_tag": "v2.1.60",
                    "required_secrets": [],
                    "sources": [],
                }
            ),
            encoding="utf-8",
        )
        stack = tmp / "Pulumi.sec-dev.yaml"
        import_line = f"  cerebro:openrouterApiKeySecret: {openrouter_import_ref}\n" if openrouter_import_ref else ""
        stack.write_text(
            f"""
config:
  cerebro:imageTag: v2.1.60
  cerebro:environment: sec-dev
  cerebro:graphAgentLlmProvider: openrouter
  cerebro:graphAgentLlmModel: anthropic/claude-sonnet-4.6
{import_line}""",
            encoding="utf-8",
        )
        return contract, stack

    def test_receipt_passes_with_openrouter_import_ref(self) -> None:
        with TemporaryDirectory() as raw:
            contract, stack = self._write_inputs(Path(raw))
            receipt = build_deploy_preflight_receipt.build_receipt(contract, stack)

        self.assertEqual(receipt["status"], "pass")
        graph_check = next(check for check in receipt["checks"] if check["name"] == "graph_agent_llm")
        self.assertEqual(graph_check["status"], "pass")
        self.assertTrue(graph_check["details"]["openrouter_secret_configured"])

    def test_receipt_matches_runtime_contract_default_leniency(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw)
            contract, stack = self._write_inputs(root)
            payload = json.loads(contract.read_text(encoding="utf-8"))
            payload["sources"] = [{"source_id": "okta", "runtimes": [{"id": "runtime-from-manifest", "config": {}}]}]
            contract.write_text(json.dumps(payload), encoding="utf-8")

            receipt = build_deploy_preflight_receipt.build_receipt(contract, stack)

        contract_check = next(check for check in receipt["checks"] if check["name"] == "runtime_contract")
        self.assertEqual(contract_check["status"], "pass")

    def test_receipt_fails_without_leaking_openrouter_import_ref(self) -> None:
        with TemporaryDirectory() as raw:
            contract, stack = self._write_inputs(Path(raw), openrouter_import_ref="")
            receipt = build_deploy_preflight_receipt.build_receipt(contract, stack)

        body = json.dumps(receipt)
        self.assertEqual(receipt["status"], "fail")
        self.assertIn("OpenRouter provider is missing its secret import", body)
        self.assertNotIn("OPENROUTER_RUNTIME_TOKEN", body)

    def test_receipt_passes_with_bedrock_model_and_region(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw)
            contract, stack = self._write_inputs(root)
            stack.write_text(
                """
config:
  cerebro:imageTag: v2.1.60
  cerebro:environment: sec-dev
  cerebro:graphAgentLlmProvider: bedrock
  cerebro:graphAgentLlmModel: us.anthropic.claude-sonnet-4-6
  cerebro:bedrockRegion: us-east-1
""",
                encoding="utf-8",
            )
            receipt = build_deploy_preflight_receipt.build_receipt(contract, stack)

        self.assertEqual(receipt["status"], "pass")
        graph_check = next(check for check in receipt["checks"] if check["name"] == "graph_agent_llm")
        self.assertEqual(graph_check["status"], "pass")
        self.assertTrue(graph_check["details"]["bedrock_model_configured"])
        self.assertTrue(graph_check["details"]["bedrock_region_configured"])

    def test_receipt_fails_with_incomplete_bedrock_config(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw)
            contract, stack = self._write_inputs(root)
            stack.write_text(
                """
config:
  cerebro:imageTag: v2.1.60
  cerebro:environment: sec-dev
  cerebro:graphAgentLlmProvider: bedrock
""",
                encoding="utf-8",
            )
            receipt = build_deploy_preflight_receipt.build_receipt(contract, stack)

        body = json.dumps(receipt)
        self.assertEqual(receipt["status"], "fail")
        self.assertIn("Bedrock provider is missing its model or inference profile id", body)
        self.assertIn("Bedrock provider is missing its runtime region", body)

    def test_import_plan_uses_fingerprints_not_names(self) -> None:
        with TemporaryDirectory() as raw:
            contract, stack = self._write_inputs(Path(raw))
            receipt = build_deploy_preflight_receipt.build_receipt(contract, stack)

        body = json.dumps(receipt)
        self.assertIn("import_fingerprints", body)
        self.assertNotIn("OPENROUTER_RUNTIME_TOKEN", body)

    def test_adversarial_openrouter_import_refs_are_redacted(self) -> None:
        rng = random.Random(923)
        alphabet = string.ascii_letters + string.digits + "_-/"
        with TemporaryDirectory() as raw:
            root = Path(raw)
            for index in range(75):
                import_ref = "OPENROUTER_" + "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 24)))
                import_ref = import_ref.strip() or f"OPENROUTER_{index}"
                with self.subTest(index=index):
                    contract, stack = self._write_inputs(root, openrouter_import_ref=import_ref)
                    receipt = build_deploy_preflight_receipt.build_receipt(contract, stack)
                    body = json.dumps(receipt)

                    self.assertIn(receipt["status"], {"pass", "fail"})
                    self.assertNotIn(import_ref, body)


if __name__ == "__main__":
    unittest.main()
