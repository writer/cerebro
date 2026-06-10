from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


spec = importlib.util.spec_from_file_location(
    "verify_runtime_contract",
    Path(__file__).resolve().parents[1] / "scripts" / "verify_runtime_contract.py",
)
verify_runtime_contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify_runtime_contract)


CONTRACT = {
    "schema_version": "cerebro.runtime-deploy-contract/v1",
    "image_tag": "v2.1.60",
    "required_secrets": ["GITHUB_TOKEN", "OKTA_API_TOKEN", "OKTA_DOMAIN"],
    "sources": [
        {
            "source_id": "github",
            "supported_families": ["audit"],
            "required_secrets": ["GITHUB_TOKEN"],
            "runtimes": [
                {
                    "id": "writer-github-audit",
                    "source_id": "github",
                    "tenant_id": "writer",
                    "family": "audit",
                    "required_secrets": ["GITHUB_TOKEN"],
                    "config": {"family": "audit", "owner": "writer", "token": "env:GITHUB_TOKEN"},
                }
            ],
        },
        {
            "source_id": "okta",
            "supported_families": ["audit", "user"],
            "required_secrets": ["OKTA_API_TOKEN", "OKTA_DOMAIN"],
            "runtimes": [],
        },
    ],
}


STACK = {
    "imageTag": "v2.1.60",
    "sourceSecretKeys": ["GITHUB_TOKEN", "OKTA_API_TOKEN", "OKTA_DOMAIN"],
    "sourceRuntimes": [
        {
            "id": "writer-github-audit",
            "sourceId": "github",
            "tenantId": "writer",
            "config": {"family": "audit", "owner": "writer", "token": "env:GITHUB_TOKEN"},
        },
        {
            "id": "writer-okta-user",
            "sourceId": "okta",
            "tenantId": "writer",
            "config": {"family": "user", "token": "env:OKTA_API_TOKEN", "domain": "env:OKTA_DOMAIN"},
        },
    ],
}


def _contract_with_source_health_receipt() -> dict:
    return {
        **CONTRACT,
        "sources": [
            *CONTRACT["sources"],
            {
                "source_id": "demo_source",
                "supported_families": ["asset_host", "evidence_cas_reference"],
                "required_secrets": ["DEMO_SOURCE_TOKEN"],
                "runtimes": [],
                "source_health_receipt": {
                    "receipt_kind": "source_health.receipt",
                    "source_type": "json_api",
                    "auth_model": "bearer_token",
                    "adapter_health_path": "/readyz",
                    "expected_cadence_seconds": 7200,
                    "stale_after_seconds": 7200,
                    "evidence_cas_reference_kind": "demo_source.evidence_cas_reference",
                },
            },
        ],
    }


def _contract_with_generated_deploy_runtime() -> dict:
    return {
        **CONTRACT,
        "sources": [
            *CONTRACT["sources"],
            {
                "source_id": "demo_source",
                "supported_families": ["asset_host"],
                "required_secrets": ["DEMO_SOURCE_TOKEN"],
                "runtimes": [
                    {
                        "id": "writer-demo-source-asset-host",
                        "tenant_id": "writer",
                        "config": {
                            "family": "asset_host",
                            "health_path": "/readyz",
                            "expected_cadence_seconds": 7200,
                            "stale_after_seconds": 7200,
                        },
                    }
                ],
            },
        ],
    }


def _generated_source_stack_runtime() -> dict:
    return {
        "id": "writer-demo-source-asset-host",
        "sourceId": "demo_source",
        "tenantId": "writer",
        "config": {
            "family": "asset_host",
            "health_path": "/readyz",
            "expected_cadence_seconds": "7200",
            "stale_after_seconds": "7200",
            "token": "env:DEMO_SOURCE_TOKEN",
        },
    }


class RuntimeContractTest(unittest.TestCase):
    def test_valid_contract_matches_stack(self) -> None:
        self.assertEqual(verify_runtime_contract.verify_contract(CONTRACT, STACK, require_manifest_runtimes=True), [])

    def test_rejects_image_tag_mismatch(self) -> None:
        stack = {**STACK, "imageTag": "v2.1.59"}
        self.assertTrue(any("image_tag" in error for error in verify_runtime_contract.verify_contract(CONTRACT, stack)))

    def test_rejects_unknown_source_id(self) -> None:
        stack = {**STACK, "sourceRuntimes": [{**STACK["sourceRuntimes"][0], "sourceId": "unknown"}]}
        self.assertTrue(any("not present in contract" in error for error in verify_runtime_contract.verify_contract(CONTRACT, stack)))

    def test_rejects_unsupported_family(self) -> None:
        runtime = {**STACK["sourceRuntimes"][0], "config": {"family": "pull_request"}}
        stack = {**STACK, "sourceRuntimes": [runtime]}
        self.assertTrue(any("unsupported github family" in error for error in verify_runtime_contract.verify_contract(CONTRACT, stack)))

    def test_allows_aws_asset_metadata_when_contract_declares_it(self) -> None:
        contract = {
            **CONTRACT,
            "sources": [
                *CONTRACT["sources"],
                {"source_id": "aws", "supported_families": ["iam_role", "asset_metadata"], "runtimes": []},
            ],
        }
        stack = {
            **STACK,
            "sourceRuntimes": [
                {
                    "id": "writer-aws-test-asset-metadata",
                    "sourceId": "aws",
                    "tenantId": "writer",
                    "config": {"family": "asset_metadata"},
                }
            ],
        }
        self.assertEqual(verify_runtime_contract.verify_contract(contract, stack), [])

    def test_rejects_aws_asset_metadata_when_contract_omits_it(self) -> None:
        contract = {
            **CONTRACT,
            "sources": [
                *CONTRACT["sources"],
                {"source_id": "aws", "supported_families": ["iam_role"], "runtimes": []},
            ],
        }
        stack = {
            **STACK,
            "sourceRuntimes": [
                {
                    "id": "writer-aws-test-asset-metadata",
                    "sourceId": "aws",
                    "tenantId": "writer",
                    "config": {"family": "asset_metadata"},
                }
            ],
        }
        self.assertTrue(
            any("unsupported aws family 'asset_metadata'" in error for error in verify_runtime_contract.verify_contract(contract, stack))
        )

    def test_rejects_missing_secret_ref(self) -> None:
        stack = {**STACK, "sourceSecretKeys": ["OKTA_API_TOKEN", "OKTA_DOMAIN"]}
        errors = verify_runtime_contract.verify_contract(CONTRACT, stack, require_manifest_runtimes=True)
        self.assertTrue(any("missing 1 contract-required sourceSecretKeys" in error for error in errors))
        self.assertFalse(any("GITHUB_TOKEN" in error for error in errors))

    def test_redacts_env_ref_mismatches(self) -> None:
        runtime = {**STACK["sourceRuntimes"][0], "config": {"family": "audit", "owner": "writer", "token": "env:OTHER_TOKEN"}}
        stack = {**STACK, "sourceRuntimes": [runtime]}
        errors = verify_runtime_contract.verify_contract(CONTRACT, stack, require_manifest_runtimes=True)
        self.assertTrue(any("does not match contract env reference" in error for error in errors))
        self.assertFalse(any("GITHUB_TOKEN" in error or "OTHER_TOKEN" in error for error in errors))

    def test_nested_env_ref_mismatches_are_redacted(self) -> None:
        contract = {
            **CONTRACT,
            "sources": [
                {
                    **CONTRACT["sources"][0],
                    "runtimes": [
                        {
                            **CONTRACT["sources"][0]["runtimes"][0],
                            "config": {"family": "audit", "auth": {"token": "env:GITHUB_TOKEN"}},
                        }
                    ],
                },
                CONTRACT["sources"][1],
            ],
        }
        runtime = {
            **STACK["sourceRuntimes"][0],
            "config": {"family": "audit", "auth": {"token": "env:OTHER_TOKEN"}},
        }
        stack = {**STACK, "sourceRuntimes": [runtime]}

        errors = verify_runtime_contract.verify_contract(contract, stack, require_manifest_runtimes=True)

        self.assertTrue(any("auth.token" in error and "does not match contract env reference" in error for error in errors))
        self.assertFalse(any("GITHUB_TOKEN" in error or "OTHER_TOKEN" in error for error in errors))

    def test_nested_runtime_env_refs_must_be_declared(self) -> None:
        runtime = {
            **STACK["sourceRuntimes"][0],
            "config": {"family": "audit", "auth": {"token": "env:UNDECLARED_TOKEN"}},
        }
        stack = {**STACK, "sourceRuntimes": [runtime]}

        errors = verify_runtime_contract.verify_contract(CONTRACT, stack)

        self.assertTrue(any("references 1 undeclared sourceSecretKeys" in error for error in errors))
        self.assertFalse(any("UNDECLARED_TOKEN" in error for error in errors))

    def test_rejects_missing_manifest_runtime_when_required(self) -> None:
        stack = {**STACK, "sourceRuntimes": [STACK["sourceRuntimes"][1]]}
        self.assertTrue(
            any("contract runtime 'writer-github-audit' is missing" in error for error in verify_runtime_contract.verify_contract(CONTRACT, stack, require_manifest_runtimes=True))
        )

    def test_allows_missing_manifest_runtime_when_not_required(self) -> None:
        stack = {**STACK, "sourceRuntimes": [STACK["sourceRuntimes"][1]]}
        self.assertFalse(
            any("contract runtime 'writer-github-audit' is missing" in error for error in verify_runtime_contract.verify_contract(CONTRACT, stack))
        )

    def test_rejects_manifest_runtime_source_mismatch_when_required(self) -> None:
        runtime = {**STACK["sourceRuntimes"][0], "sourceId": "okta"}
        stack = {**STACK, "sourceRuntimes": [runtime]}
        self.assertTrue(
            any("runtime 'writer-github-audit' sourceId is 'okta', expected 'github'" in error for error in verify_runtime_contract.verify_contract(CONTRACT, stack, require_manifest_runtimes=True))
        )

    def test_rejects_manifest_runtime_tenant_mismatch_when_required(self) -> None:
        runtime = {**STACK["sourceRuntimes"][0], "tenantId": "other"}
        stack = {**STACK, "sourceRuntimes": [runtime]}
        self.assertTrue(
            any("runtime 'writer-github-audit' tenantId is 'other', expected 'writer'" in error for error in verify_runtime_contract.verify_contract(CONTRACT, stack, require_manifest_runtimes=True))
        )

    def test_contract_drift_is_empty_when_stack_aligned(self) -> None:
        self.assertEqual(verify_runtime_contract.contract_drift(CONTRACT, STACK), [])

    def test_contract_drift_reports_missing_runtime_without_blocking(self) -> None:
        stack = {**STACK, "sourceRuntimes": [STACK["sourceRuntimes"][1]]}
        warnings = verify_runtime_contract.contract_drift(CONTRACT, stack)
        self.assertTrue(any("contract runtime 'writer-github-audit' is not configured" in warning for warning in warnings))
        self.assertEqual(verify_runtime_contract.verify_contract(CONTRACT, stack), [])

    def test_contract_drift_counts_missing_secrets_without_names(self) -> None:
        stack = {**STACK, "sourceSecretKeys": ["OKTA_API_TOKEN", "OKTA_DOMAIN"]}
        warnings = verify_runtime_contract.contract_drift(CONTRACT, stack)
        self.assertTrue(any("missing 1 contract-required sourceSecretKeys" in warning for warning in warnings))
        self.assertFalse(any("GITHUB_TOKEN" in warning for warning in warnings))

    def test_source_health_receipt_matches_generated_runtime_config(self) -> None:
        contract = _contract_with_source_health_receipt()
        stack = {
            **STACK,
            "sourceSecretKeys": [*STACK["sourceSecretKeys"], "DEMO_SOURCE_TOKEN"],
            "sourceRuntimes": [_generated_source_stack_runtime()],
        }

        self.assertEqual(verify_runtime_contract.verify_contract(contract, stack), [])

    def test_matching_runtime_deploy_metadata_rejects_freshness_drift_without_requiring_manifest(self) -> None:
        contract = _contract_with_generated_deploy_runtime()
        runtime = _generated_source_stack_runtime()
        runtime["config"] = {**runtime["config"], "expected_cadence_seconds": "3600"}
        stack = {
            **STACK,
            "sourceSecretKeys": [*STACK["sourceSecretKeys"], "DEMO_SOURCE_TOKEN"],
            "sourceRuntimes": [runtime],
        }

        errors = verify_runtime_contract.verify_contract(contract, stack, require_manifest_runtimes=False)
        self.assertTrue(any("expected_cadence_seconds" in error and "runtime deploy contract value" in error for error in errors))

    def test_source_health_receipt_rejects_freshness_mismatch(self) -> None:
        contract = _contract_with_source_health_receipt()
        runtime = _generated_source_stack_runtime()
        runtime["config"] = {**runtime["config"], "stale_after_seconds": "3600"}
        stack = {
            **STACK,
            "sourceSecretKeys": [*STACK["sourceSecretKeys"], "DEMO_SOURCE_TOKEN"],
            "sourceRuntimes": [runtime],
        }

        errors = verify_runtime_contract.verify_contract(contract, stack)
        self.assertTrue(any("stale_after_seconds" in error and "expected source health receipt value" in error for error in errors))

    def test_source_health_receipt_rejects_health_path_mismatch(self) -> None:
        contract = _contract_with_source_health_receipt()
        runtime = _generated_source_stack_runtime()
        runtime["config"] = {**runtime["config"], "health_path": "/other"}
        stack = {
            **STACK,
            "sourceSecretKeys": [*STACK["sourceSecretKeys"], "DEMO_SOURCE_TOKEN"],
            "sourceRuntimes": [runtime],
        }

        errors = verify_runtime_contract.verify_contract(contract, stack)
        self.assertTrue(any("health_path" in error and "source health receipt" in error for error in errors))

    def test_source_health_receipt_rejects_unknown_source_and_invalid_values(self) -> None:
        contract = {
            **CONTRACT,
            "source_health_receipts": [
                {
                    "receipt_kind": "source_health.receipt",
                    "source_id": "missing_source",
                    "expected_cadence_seconds": 0,
                    "stale_after_seconds": "invalid",
                }
            ],
        }

        errors = verify_runtime_contract.verify_contract(contract, STACK)
        self.assertTrue(any("missing_source" in error and "not present in contract sources" in error for error in errors))

    def test_source_health_receipt_rejects_malformed_receipt(self) -> None:
        contract = _contract_with_source_health_receipt()
        source = {**contract["sources"][-1], "source_health_receipt": {"receipt_kind": "wrong", "source_id": "demo_source"}}
        contract = {**contract, "sources": [*contract["sources"][:-1], source]}

        errors = verify_runtime_contract.verify_contract(contract, STACK)
        self.assertTrue(any("receipt_kind" in error for error in errors))

    def test_source_health_receipt_drift_warns_when_not_configured(self) -> None:
        contract = _contract_with_source_health_receipt()

        warnings = verify_runtime_contract.contract_drift(contract, STACK)
        self.assertTrue(any("source health receipt source_id 'demo_source' is not configured" in warning for warning in warnings))
        self.assertEqual(verify_runtime_contract.verify_contract(contract, STACK), [])


if __name__ == "__main__":
    unittest.main()
