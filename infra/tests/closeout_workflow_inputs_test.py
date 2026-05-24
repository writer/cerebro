"""Static assertions over .github/workflows/closeout.yml.

This test guards the closeout workflow_dispatch surface so we catch
regressions before a dispatch ever happens. It does NOT execute any
AWS or GitHub Actions API calls; everything here is a YAML parse plus
structural checks (VAL-INFRA-001, VAL-INFRA-002, VAL-INFRA-003,
VAL-INFRA-007, VAL-INFRA-014, VAL-INFRA-017, VAL-INFRA-018).
"""

from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "closeout.yml"


def _load_workflow() -> dict:
    with WORKFLOW_PATH.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


class CloseoutWorkflowMetadataTest(unittest.TestCase):
    """Top-level workflow metadata: name, triggers, concurrency."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = _load_workflow()

    def test_workflow_file_exists(self) -> None:
        self.assertTrue(WORKFLOW_PATH.is_file(), f"missing workflow file: {WORKFLOW_PATH}")

    def test_workflow_name(self) -> None:
        self.assertEqual(self.workflow.get("name"), "Cerebro Bulk Closeout")

    def test_only_workflow_dispatch_trigger(self) -> None:
        # PyYAML rewrites the bareword `on:` to the boolean key True. Accept
        # either to be resilient across PyYAML versions.
        triggers = self.workflow.get("on", self.workflow.get(True))
        self.assertIsInstance(triggers, dict, "workflow 'on' must be a mapping")
        self.assertEqual(list(triggers.keys()), ["workflow_dispatch"])

    def test_concurrency_serialises_per_env(self) -> None:
        concurrency = self.workflow.get("concurrency")
        self.assertIsInstance(concurrency, dict)
        group = concurrency.get("group", "")
        self.assertTrue(group.startswith("cerebro-closeout-"),
                        f"unexpected concurrency group: {group!r}")
        self.assertIn("github.event.inputs.env", group,
                      f"concurrency group must reference inputs.env: {group!r}")
        self.assertEqual(concurrency.get("cancel-in-progress"), False)


class CloseoutWorkflowInputsTest(unittest.TestCase):
    """Workflow input declarations: type, required, default. VAL-INFRA-002."""

    @classmethod
    def setUpClass(cls) -> None:
        workflow = _load_workflow()
        triggers = workflow.get("on", workflow.get(True))
        cls.inputs = triggers["workflow_dispatch"]["inputs"]

    def test_env_input(self) -> None:
        spec = self.inputs["env"]
        self.assertEqual(spec["type"], "choice")
        self.assertTrue(spec.get("required"))
        self.assertEqual(sorted(spec.get("options", [])), ["go-prod", "sec-dev"])

    def test_dry_run_input(self) -> None:
        spec = self.inputs["dry_run"]
        self.assertEqual(spec["type"], "boolean")
        self.assertIs(spec.get("default"), True)

    def test_rule_ids_input(self) -> None:
        spec = self.inputs["rule_ids"]
        self.assertEqual(spec["type"], "string")
        self.assertFalse(spec.get("required", False))

    def test_source_input(self) -> None:
        spec = self.inputs["source"]
        self.assertEqual(spec["type"], "string")
        self.assertFalse(spec.get("required", False))

    def test_older_than_input(self) -> None:
        spec = self.inputs["older_than"]
        self.assertEqual(spec["type"], "string")
        self.assertFalse(spec.get("required", False))

    def test_reason_input(self) -> None:
        spec = self.inputs["reason"]
        self.assertEqual(spec["type"], "string")
        self.assertTrue(spec.get("required"), "reason must be required")

    def test_change_ticket_input(self) -> None:
        spec = self.inputs["change_ticket"]
        self.assertEqual(spec["type"], "string")
        self.assertFalse(spec.get("required", False))

    def test_exact_input_set(self) -> None:
        self.assertEqual(
            sorted(self.inputs.keys()),
            sorted([
                "env",
                "dry_run",
                "rule_ids",
                "source",
                "older_than",
                "reason",
                "change_ticket",
            ]),
        )


class CloseoutJobsTest(unittest.TestCase):
    """Job-level structure: preflight runs first, env gating, OIDC roles."""

    @classmethod
    def setUpClass(cls) -> None:
        workflow = _load_workflow()
        cls.jobs = workflow["jobs"]

    def test_preflight_job_exists(self) -> None:
        self.assertIn("preflight", self.jobs)
        preflight = self.jobs["preflight"]
        self.assertEqual(preflight.get("runs-on"), "ubuntu-latest")

    def test_preflight_runs_before_aws_credentials(self) -> None:
        """VAL-INFRA-017: preflight validates inputs before AWS role assumption.

        The closeout-* jobs must depend on preflight, and preflight itself
        must NOT contain a Configure AWS credentials step.
        """
        for job_name in ("closeout-sec-dev", "closeout-go-prod"):
            needs = self.jobs[job_name].get("needs")
            if isinstance(needs, str):
                needs = [needs]
            self.assertIn(
                "preflight",
                needs or [],
                f"job {job_name} must declare needs: preflight",
            )

        preflight_steps = self.jobs["preflight"]["steps"]
        for step in preflight_steps:
            uses = (step.get("uses") or "").lower()
            self.assertNotIn(
                "aws-git-roles",
                uses,
                "preflight must not assume an AWS role",
            )
            self.assertNotIn(
                "configure-aws-credentials",
                uses,
                "preflight must not configure AWS credentials",
            )

    def test_sec_dev_job_no_production_environment(self) -> None:
        sec_dev = self.jobs["closeout-sec-dev"]
        self.assertNotIn(
            "environment",
            sec_dev,
            "sec-dev job must NOT declare an environment (VAL-INFRA-003)",
        )
        if_expr = sec_dev.get("if", "")
        self.assertIn("sec-dev", if_expr)

    def test_go_prod_job_requires_production_environment(self) -> None:
        go_prod = self.jobs["closeout-go-prod"]
        self.assertEqual(
            go_prod.get("environment"),
            "production",
            "go-prod job must require the production environment (VAL-INFRA-003)",
        )
        if_expr = go_prod.get("if", "")
        self.assertIn("go-prod", if_expr)

    def test_sec_dev_uses_sec_dev_oidc_role(self) -> None:
        steps = self.jobs["closeout-sec-dev"]["steps"]
        roles = []
        for step in steps:
            if (step.get("uses") or "").startswith("WriterInternal/aws-git-roles"):
                roles.append(step.get("with", {}).get("assume-role-arn", ""))
        self.assertIn(
            "arn:aws:iam::944130631940:role/writer-aws-deployment-role",
            roles,
            "sec-dev must assume the writer-aws-deployment-role in 944130631940",
        )

    def test_go_prod_uses_documented_role(self) -> None:
        steps = self.jobs["closeout-go-prod"]["steps"]
        roles = []
        for step in steps:
            if (step.get("uses") or "").startswith("WriterInternal/aws-git-roles"):
                roles.append(step.get("with", {}).get("assume-role-arn", ""))
        # Documented go-prod deployment role lives in the sec-prod account
        # (837279440628), matching infra-deploy.yml.
        self.assertTrue(
            any(role.endswith(":role/writer-aws-deployment-role") for role in roles),
            f"go-prod must assume writer-aws-deployment-role via OIDC; saw {roles}",
        )
        self.assertTrue(
            any("837279440628" in role for role in roles),
            f"go-prod role must live in the sec-prod account; saw {roles}",
        )

    def test_id_token_write_permission_for_oidc(self) -> None:
        for job_name in ("closeout-sec-dev", "closeout-go-prod"):
            perms = self.jobs[job_name].get("permissions") or {}
            self.assertEqual(
                perms.get("id-token"),
                "write",
                f"job {job_name} requires id-token: write for OIDC",
            )


class CloseoutPreflightOlderThanTest(unittest.TestCase):
    """Preflight does NOT regex-validate 'older_than'; syntax is checked by the CLI."""

    @classmethod
    def setUpClass(cls) -> None:
        workflow = _load_workflow()
        preflight_steps = workflow["jobs"]["preflight"]["steps"]
        validate_step = next(
            step for step in preflight_steps
            if step.get("name") == "Validate workflow inputs"
        )
        cls.script = validate_step["run"]

    def _run_validate(self, older_than: str) -> int:
        env = {
            **os.environ,
            "INPUT_ENV": "sec-dev",
            "INPUT_REASON": "preflight-older-than-test",
            "INPUT_OLDER_THAN": older_than,
            "INPUT_CHANGE_TICKET": "",
        }
        result = subprocess.run(
            ["bash", "-c", self.script],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        return result.returncode

    def test_accepts_any_nonempty_older_than(self) -> None:
        # Preflight delegates syntax validation to the cerebro CLI itself,
        # so any non-empty value (including compound Go durations) must pass.
        for value in ("1h30m", "90m", "36h", "2h45m30s", "1ms"):
            with self.subTest(older_than=value):
                self.assertEqual(
                    self._run_validate(value),
                    0,
                    f"older_than={value!r} must be accepted by preflight",
                )

    def test_empty_older_than_is_skipped(self) -> None:
        self.assertEqual(
            self._run_validate(""),
            0,
            "empty older_than is the default and must not trigger validation failure",
        )

    def test_preflight_script_does_not_regex_older_than(self) -> None:
        # Older_than syntax validation now lives in the cerebro CLI; the
        # preflight script must not regex-match the value.
        self.assertNotIn("INPUT_OLDER_THAN", self.script,
                         "preflight must not reference INPUT_OLDER_THAN")


class CloseoutWorkflowNoHardcodedBucketTest(unittest.TestCase):
    """VAL-INFRA-018: bucket name must come from pulumi stack output."""

    def test_no_hardcoded_audit_bucket_literal(self) -> None:
        raw = WORKFLOW_PATH.read_text(encoding="utf-8")
        for literal in ("cerebro-sec-dev-audit", "cerebro-go-prod-audit"):
            self.assertNotIn(
                literal,
                raw,
                f"workflow YAML must not hard-code {literal!r} (use pulumi stack output)",
            )

    def test_workflow_references_pulumi_stack_output(self) -> None:
        raw = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertIn(
            "pulumi stack output",
            raw,
            "workflow must resolve audit bucket via 'pulumi stack output'",
        )
        self.assertIn(
            "cerebro_audit_bucket",
            raw,
            "workflow must reference the 'cerebro_audit_bucket' Pulumi stack output",
        )


class CloseoutEnvMappingTest(unittest.TestCase):
    """VAL-INFRA-005: per-env ECS cluster / task-family / log-group mapping.

    Pin the per-env mapping to the live AWS resources discovered in sec-dev
    (944130631940) and go-prod (837279440628). The sec-dev API task family
    is `cerebro-sec-dev` (no -api suffix) and go-prod is `cerebro-go-production`
    (matching the existing /ecs/cerebro-go-production log group).
    """

    SEC_DEV_EXPECTED = {
        "CEREBRO_ENV": "sec-dev",
        "CEREBRO_CLUSTER": "cerebro-sec-dev-cluster",
        "CEREBRO_TASK_FAMILY": "cerebro-sec-dev",
        "CEREBRO_SERVICE": "cerebro-sec-dev-api",
        "CEREBRO_LOG_GROUP": "/ecs/cerebro-sec-dev",
        "CEREBRO_TASK_ROLE_NAME": "cerebro-sec-dev-task-role",
    }

    GO_PROD_EXPECTED = {
        "CEREBRO_ENV": "go-prod",
        "CEREBRO_CLUSTER": "cerebro-go-production-cluster",
        "CEREBRO_TASK_FAMILY": "cerebro-go-production",
        "CEREBRO_SERVICE": "cerebro-go-production-api",
        "CEREBRO_LOG_GROUP": "/ecs/cerebro-go-production",
        "CEREBRO_TASK_ROLE_NAME": "cerebro-go-production-task-role",
    }

    @classmethod
    def setUpClass(cls) -> None:
        workflow = _load_workflow()
        cls.jobs = workflow["jobs"]

    def _assert_env_mapping(self, job_name: str, expected: dict) -> None:
        env = self.jobs[job_name].get("env") or {}
        for key, value in expected.items():
            self.assertEqual(
                env.get(key),
                value,
                f"{job_name} env {key} must equal {value!r}, got {env.get(key)!r}",
            )

    def test_sec_dev_env_mapping(self) -> None:
        self._assert_env_mapping("closeout-sec-dev", self.SEC_DEV_EXPECTED)

    def test_go_prod_env_mapping(self) -> None:
        self._assert_env_mapping("closeout-go-prod", self.GO_PROD_EXPECTED)

    def test_sec_dev_task_family_has_no_api_suffix(self) -> None:
        env = self.jobs["closeout-sec-dev"]["env"]
        self.assertEqual(
            env["CEREBRO_TASK_FAMILY"],
            "cerebro-sec-dev",
            "sec-dev API task family is 'cerebro-sec-dev' (no -api suffix); "
            "the -api suffix only exists on the service name, not the task family",
        )
        self.assertNotEqual(
            env["CEREBRO_TASK_FAMILY"],
            "cerebro-sec-dev-api",
            "regression guard: -api suffix points at a non-existent task family",
        )

    def test_go_prod_uses_go_production_naming(self) -> None:
        env = self.jobs["closeout-go-prod"]["env"]
        self.assertEqual(env["CEREBRO_CLUSTER"], "cerebro-go-production-cluster")
        self.assertEqual(env["CEREBRO_TASK_FAMILY"], "cerebro-go-production")
        self.assertEqual(env["CEREBRO_LOG_GROUP"], "/ecs/cerebro-go-production")
        self.assertNotIn(
            "cerebro-go-prod-cluster",
            env.values(),
            "regression guard: 'cerebro-go-prod-cluster' is not a real cluster",
        )

    def test_log_group_matches_env(self) -> None:
        for job_name, expected in (
            ("closeout-sec-dev", "/ecs/cerebro-sec-dev"),
            ("closeout-go-prod", "/ecs/cerebro-go-production"),
        ):
            env = self.jobs[job_name]["env"]
            self.assertEqual(env["CEREBRO_LOG_GROUP"], expected)


class CloseoutEcsScriptEnvCaseTest(unittest.TestCase):
    """The helper script encodes the per-env mapping in a `case ${CEREBRO_ENV}`
    block so the workflow and any future caller share the same source of truth."""

    SCRIPT_PATH = REPO_ROOT / "infra" / "scripts" / "run_closeout_ecs.sh"

    @classmethod
    def setUpClass(cls) -> None:
        cls.script = cls.SCRIPT_PATH.read_text(encoding="utf-8")

    def test_script_exists(self) -> None:
        self.assertTrue(self.SCRIPT_PATH.is_file())

    def test_case_dispatches_on_cerebro_env(self) -> None:
        self.assertIn('case "${CEREBRO_ENV}"', self.script)

    def test_case_pins_sec_dev_family_and_cluster(self) -> None:
        for literal in (
            'CEREBRO_CLUSTER:=cerebro-sec-dev-cluster',
            'CEREBRO_TASK_FAMILY:=cerebro-sec-dev',
            'CEREBRO_SERVICE:=cerebro-sec-dev-api',
            'CEREBRO_LOG_GROUP:=/ecs/cerebro-sec-dev',
            'CEREBRO_TASK_ROLE_NAME:=cerebro-sec-dev-task-role',
        ):
            self.assertIn(literal, self.script,
                          f"sec-dev case must set {literal}")

    def test_case_pins_go_prod_family_and_cluster(self) -> None:
        for literal in (
            'CEREBRO_CLUSTER:=cerebro-go-production-cluster',
            'CEREBRO_TASK_FAMILY:=cerebro-go-production',
            'CEREBRO_SERVICE:=cerebro-go-production-api',
            'CEREBRO_LOG_GROUP:=/ecs/cerebro-go-production',
            'CEREBRO_TASK_ROLE_NAME:=cerebro-go-production-task-role',
        ):
            self.assertIn(literal, self.script,
                          f"go-prod case must set {literal}")

    def test_describe_services_uses_service_name(self) -> None:
        self.assertIn('--services "${CEREBRO_SERVICE}"', self.script,
                      "describe-services must target the service, not the task family")


class CloseoutKmsAssertionScriptTest(unittest.TestCase):
    """Regression coverage for assert-kms-allow.

    IAM simulation is useful diagnostic output, but KMS key-policy evaluation
    makes it non-authoritative for this workflow. The assertion must be driven
    by real KMS DescribeKey + Encrypt + GenerateDataKey probes instead.
    """

    SCRIPT_PATH = REPO_ROOT / "infra" / "scripts" / "run_closeout_ecs.sh"

    @classmethod
    def setUpClass(cls) -> None:
        cls.script = cls.SCRIPT_PATH.read_text(encoding="utf-8")

    def test_attempts_task_role_assume_for_real_kms_probe(self) -> None:
        self.assertIn("aws sts assume-role", self.script)
        self.assertIn('--role-arn "${role_arn}"', self.script)
        self.assertIn("task_role_session_policy", self.script)

    def test_real_kms_probe_uses_describe_key_encrypt_and_generate_data_key(self) -> None:
        self.assertIn("aws kms describe-key", self.script)
        self.assertIn("aws kms encrypt", self.script)
        self.assertIn("aws kms generate-data-key", self.script)
        self.assertIn("--query 'CiphertextBlob'", self.script)
        self.assertIn("kms:Encrypt succeeded and returned a CiphertextBlob", self.script)
        self.assertIn("kms:GenerateDataKey succeeded", self.script)

    def test_simulate_principal_policy_is_informational_only(self) -> None:
        self.assertIn("Informational IAM simulation", self.script)
        self.assertIn("(informational only)", self.script)
        self.assertNotIn("is NOT allowed to perform", self.script)
        self.assertNotIn("unexpectedly allowed for", self.script)

    def test_policy_fallback_still_fails_when_task_role_policy_lacks_kms(self) -> None:
        self.assertIn("assert_task_role_policy_allows_kms", self.script)
        self.assertIn("assert_kms_key_policy_delegates_to_iam", self.script)
        self.assertIn("policies do not allow required KMS actions", self.script)
        self.assertIn("does not delegate required KMS actions", self.script)


if __name__ == "__main__":
    unittest.main()
