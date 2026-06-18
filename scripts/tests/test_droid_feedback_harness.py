import unittest

import scripts.droid_feedback_harness as fb


class DroidFeedbackHarnessTests(unittest.TestCase):
    def test_classify_pass(self):
        comment = fb.DroidComment(kind="review", url="", path="internal/graphagent/ask.go", line=10, body="cypher tenant scope failure")
        self.assertEqual(fb.classify_pass(comment), "tenant-security-invariants")

    def test_comments_json_shape(self):
        comments = [
            fb.DroidComment(kind="review", url="https://example", path="internal/findings/foo.go", line=42, body="candidate state atomic issue")
        ]
        payload = fb.comments_json(comments)
        self.assertEqual(payload["kind"], "droid_feedback_context")
        self.assertEqual(len(payload["active_comments"]), 1)
        self.assertEqual(payload["active_comments"][0]["pass"], "finding-state")
        self.assertTrue(payload["active_comments"][0]["suggested_checks"])

    def test_is_droid_requires_bot_login(self):
        self.assertTrue(fb.is_droid({"user": {"login": "factory-droid[bot]", "type": "Bot"}}))
        self.assertFalse(fb.is_droid({"user": {"login": "factory-droid", "type": "User"}}))


if __name__ == "__main__":
    unittest.main()
