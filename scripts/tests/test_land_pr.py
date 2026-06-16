import unittest

import scripts.land_pr as land_pr


class LandPRTests(unittest.TestCase):
    def test_check_named_status_accepts_pass_bucket(self):
        ok, reason = land_pr.check_named_status(
            [{"name": "tenant-data leak check", "bucket": "pass", "link": "https://check"}],
            "tenant-data leak check",
        )
        self.assertTrue(ok)
        self.assertEqual(reason, "")

    def test_check_named_status_rejects_missing_check(self):
        ok, reason = land_pr.check_named_status([], "tenant-data leak check")
        self.assertFalse(ok)
        self.assertIn("missing", reason)

    def test_check_droid_finished_accepts_finished_review(self):
        ok, reason = land_pr.check_droid_finished(
            [
                {
                    "user": "factory-droid[bot]",
                    "body": "**Droid finished @alice's task**\n\nNo actionable findings.",
                    "url": "https://comment",
                }
            ]
        )
        self.assertTrue(ok)
        self.assertEqual(reason, "")

    def test_check_droid_finished_rejects_error(self):
        ok, reason = land_pr.check_droid_finished(
            [
                {
                    "user": "factory-droid[bot]",
                    "body": "**Droid encountered an error**\n\nFailed to checkout PR branch.",
                    "url": "https://comment",
                }
            ]
        )
        self.assertFalse(ok)
        self.assertIn("error", reason)

    def test_check_droid_finished_rejects_in_progress(self):
        ok, reason = land_pr.check_droid_finished(
            [
                {
                    "user": "factory-droid[bot]",
                    "body": "Droid is reviewing code and running a security check...",
                    "url": "https://comment",
                }
            ]
        )
        self.assertFalse(ok)
        self.assertIn("in progress", reason)

    def test_check_droid_finished_accepts_superseded_error_then_finished_review(self):
        ok, reason = land_pr.check_droid_finished(
            [
                {
                    "user": "factory-droid[bot]",
                    "body": "**Superseded Droid error** -- rerun completed successfully.",
                    "url": "https://old-comment",
                },
                {
                    "user": "factory-droid[bot]",
                    "body": "**Droid finished @alice's task**\n\nLGTM.",
                    "url": "https://new-comment",
                },
            ]
        )
        self.assertTrue(ok)
        self.assertEqual(reason, "")


if __name__ == "__main__":
    unittest.main()
