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

    def test_rejects_missing_manifest_runtime_when_required(self) -> None:
        stack = {**STACK, "sourceRuntimes": [STACK["sourceRuntimes"][1]]}
        self.assertTrue(
            any("contract runtime 'writer-github-audit' is missing" in error for error in verify_runtime_contract.verify_contract(CONTRACT, stack, require_manifest_runtimes=True))
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


if __name__ == "__main__":
    unittest.main()
