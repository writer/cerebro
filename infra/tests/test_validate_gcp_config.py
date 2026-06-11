from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import textwrap
import unittest


spec = importlib.util.spec_from_file_location(
    "validate_gcp_config",
    Path(__file__).resolve().parents[1] / "scripts" / "validate_gcp_config.py",
)
validate_gcp_config = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = validate_gcp_config
spec.loader.exec_module(validate_gcp_config)


VALID = """
config:
  cerebro:trustedAwsAccountId: "944130631940"
  cerebro:trustedAwsRoleArns:
    - arn:aws:iam::944130631940:role/cerebro-sec-dev-task-role
    - arn:aws:iam::944130631940:role/cerebro-sec-dev-worker-task-role
  cerebro:scannerRoleProjects:
    - writer-iam
    - qordoba-devel
  cerebro:scannerRoles:
    - roles/viewer
    - roles/compute.viewer
    - roles/logging.privateLogViewer
"""


class GCPConfigValidationTest(unittest.TestCase):
    def _validate(self, content: str, name: str = "Pulumi.gcp-dev.yaml"):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / name
            path.write_text(textwrap.dedent(content), encoding="utf-8")
            return validate_gcp_config.validate_stack(path)

    def test_valid_config_passes(self) -> None:
        self.assertEqual(self._validate(VALID), [])

    def test_role_account_must_match_trusted_account(self) -> None:
        content = VALID.replace("arn:aws:iam::944130631940:role", "arn:aws:iam::837279440628:role")
        self.assertTrue(any("must match trustedAwsAccountId" in finding.message for finding in self._validate(content)))

    def test_dev_stack_rejects_prod_project_scope(self) -> None:
        content = VALID.replace("qordoba-devel", "qordoba-prod")
        self.assertTrue(any("production-like project" in finding.message for finding in self._validate(content)))

    def test_scanner_roles_are_allowlisted(self) -> None:
        content = VALID.replace("roles/viewer", "roles/owner")
        self.assertTrue(any("not in the scanner role allowlist" in finding.message for finding in self._validate(content)))

    def test_role_arns_are_required(self) -> None:
        content = VALID.replace("    - arn:aws:iam::944130631940:role/cerebro-sec-dev-task-role", "    - not-an-arn")
        self.assertTrue(any("valid AWS IAM role ARN" in finding.message for finding in self._validate(content)))

    def test_worker_role_must_be_trusted_with_task_role(self) -> None:
        content = VALID.replace("    - arn:aws:iam::944130631940:role/cerebro-sec-dev-worker-task-role\n", "")
        self.assertTrue(any("must be paired with worker role" in finding.message for finding in self._validate(content)))


if __name__ == "__main__":
    unittest.main()
