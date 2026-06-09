from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from cerebro_task_roles import derive_task_role_arns, resolve_task_role_arns


class CerebroTaskRoleArnTest(unittest.TestCase):
    def test_derives_sec_dev_task_and_worker_role_arns(self) -> None:
        roles = derive_task_role_arns(
            "sec-dev",
            {"environment": "sec-dev"},
            "944130631940",
        )

        self.assertEqual(
            roles.as_principals(),
            [
                "arn:aws:iam::944130631940:role/cerebro-sec-dev-task-role",
                "arn:aws:iam::944130631940:role/cerebro-sec-dev-worker-task-role",
            ],
        )

    def test_derives_go_prod_task_and_worker_role_arns(self) -> None:
        roles = derive_task_role_arns(
            "go-prod",
            {"environment": "go-production"},
            "837279440628",
        )

        self.assertEqual(
            roles.as_principals(),
            [
                "arn:aws:iam::837279440628:role/cerebro-go-production-task-role",
                "arn:aws:iam::837279440628:role/cerebro-go-production-worker-task-role",
            ],
        )

    def test_falls_back_to_derived_arns_when_outputs_are_absent(self) -> None:
        roles = resolve_task_role_arns(
            "sec-dev",
            {"environment": "sec-dev"},
            "944130631940",
            {},
        )

        self.assertEqual(roles.task_role_arn, "arn:aws:iam::944130631940:role/cerebro-sec-dev-task-role")
        self.assertEqual(roles.worker_task_role_arn, "arn:aws:iam::944130631940:role/cerebro-sec-dev-worker-task-role")

    def test_accepts_matching_pulumi_outputs(self) -> None:
        roles = resolve_task_role_arns(
            "go-prod",
            {"environment": "go-production"},
            "837279440628",
            {
                "task_role_arn": "arn:aws:iam::837279440628:role/cerebro-go-production-task-role",
                "worker_task_role_arn": "arn:aws:iam::837279440628:role/cerebro-go-production-worker-task-role",
            },
        )

        self.assertEqual(roles.as_principals(), [
            "arn:aws:iam::837279440628:role/cerebro-go-production-task-role",
            "arn:aws:iam::837279440628:role/cerebro-go-production-worker-task-role",
        ])

    def test_rejects_mismatched_pulumi_task_role_output(self) -> None:
        with self.assertRaisesRegex(ValueError, "disagrees with derived fallback"):
            resolve_task_role_arns(
                "sec-dev",
                {"environment": "sec-dev"},
                "944130631940",
                {"task_role_arn": "arn:aws:iam::944130631940:role/cerebro-production-task-role"},
            )

    def test_rejects_unresolved_pulumi_worker_role_output(self) -> None:
        with self.assertRaisesRegex(ValueError, "unresolved"):
            resolve_task_role_arns(
                "go-prod",
                {"environment": "go-production"},
                "837279440628",
                {"worker_task_role_arn": ""},
            )

    def test_omits_worker_role_when_orchestrator_is_disabled(self) -> None:
        roles = derive_task_role_arns(
            "sec-dev",
            {"environment": "sec-dev", "orchestratorEnabled": False},
            "944130631940",
        )

        self.assertEqual(roles.as_principals(), ["arn:aws:iam::944130631940:role/cerebro-sec-dev-task-role"])


if __name__ == "__main__":
    unittest.main()
