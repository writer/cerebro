from __future__ import annotations

import unittest

from scripts.clear_pending_pulumi_operation import clear_pending_operation


class ClearPendingPulumiOperationTest(unittest.TestCase):
    def test_removes_matching_pending_operation(self) -> None:
        state = {
            "deployment": {
                "pending_operations": [
                    {"type": "updating", "resource": {"urn": "urn:target"}},
                    {"type": "updating", "resource": {"urn": "urn:other"}},
                ]
            }
        }

        self.assertTrue(clear_pending_operation(state, "urn:target"))

        self.assertEqual(
            state["deployment"]["pending_operations"],
            [{"type": "updating", "resource": {"urn": "urn:other"}}],
        )

    def test_handles_camel_case_pending_operations(self) -> None:
        state = {"deployment": {"pendingOperations": [{"urn": "urn:target"}]}}

        self.assertTrue(clear_pending_operation(state, "urn:target"))

        self.assertEqual(state["deployment"]["pendingOperations"], [])

    def test_noops_without_matching_operation(self) -> None:
        state = {"deployment": {"pending_operations": [{"resource": {"urn": "urn:other"}}]}}

        self.assertFalse(clear_pending_operation(state, "urn:target"))

        self.assertEqual(state["deployment"]["pending_operations"], [{"resource": {"urn": "urn:other"}}])


if __name__ == "__main__":
    unittest.main()
