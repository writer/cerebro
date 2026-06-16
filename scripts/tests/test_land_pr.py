import unittest
from unittest import mock

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
                    "user": {"login": "factory-droid[bot]", "type": "Bot"},
                    "body": "**Droid finished @alice's task**\n\nNo actionable findings.",
                    "url": "https://comment",
                }
            ]
        )
        self.assertTrue(ok)
        self.assertEqual(reason, "")

    def test_check_droid_finished_accepts_review_complete_comment(self):
        ok, reason = land_pr.check_droid_finished(
            [
                {
                    "user": {"login": "factory-droid[bot]", "type": "Bot"},
                    "body": "Review complete for PR #42. No actionable findings.",
                    "url": "https://comment",
                }
            ]
        )
        self.assertTrue(ok)
        self.assertEqual(reason, "")

    def test_check_droid_finished_rejects_bare_login_spoof(self):
        ok, reason = land_pr.check_droid_finished(
            [
                {
                    "user": {"login": "factory-droid", "type": "User"},
                    "body": "**Droid finished @alice's task**\n\nLGTM.",
                    "url": "https://comment",
                }
            ]
        )
        self.assertFalse(ok)
        self.assertIn("missing", reason)

    def test_check_droid_finished_rejects_error(self):
        ok, reason = land_pr.check_droid_finished(
            [
                {
                    "user": {"login": "factory-droid[bot]", "type": "Bot"},
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
                    "user": {"login": "factory-droid[bot]", "type": "Bot"},
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
                    "user": {"login": "factory-droid[bot]", "type": "Bot"},
                    "body": "**Superseded Droid error** -- rerun completed successfully.",
                    "url": "https://old-comment",
                },
                {
                    "user": {"login": "factory-droid[bot]", "type": "Bot"},
                    "body": "**Droid finished @alice's task**\n\nLGTM.",
                    "url": "https://new-comment",
                },
            ]
        )
        self.assertTrue(ok)
        self.assertEqual(reason, "")

    def test_check_droid_finished_rejects_stale_finished_review(self):
        ok, reason = land_pr.check_droid_finished(
            [
                {
                    "user": {"login": "factory-droid[bot]", "type": "Bot"},
                    "body": "**Droid finished @alice's task**\n\nLGTM.",
                    "url": "https://old-comment",
                },
                {
                    "user": {"login": "factory-droid[bot]", "type": "Bot"},
                    "body": "Droid posted a non-terminal status update.",
                    "url": "https://new-comment",
                },
            ]
        )
        self.assertFalse(ok)
        self.assertIn("not a finished review", reason)

    def test_delete_branch_if_safe_skips_already_deleted_branch(self):
        pr = {
            "headRefName": "codex/test-branch",
            "headRepository": {"nameWithOwner": "writer/cerebro"},
            "headRepositoryOwner": {"login": "writer"},
        }

        def fake_run(args, **kwargs):
            if args[:4] == ["git", "ls-remote", "--exit-code", "--heads"]:
                return land_pr.subprocess.CompletedProcess(args, 2, "", "")
            raise AssertionError(f"unexpected command: {args}")

        with mock.patch("scripts.land_pr.subprocess.run", side_effect=fake_run):
            land_pr.delete_branch_if_safe(pr, "writer/cerebro")


if __name__ == "__main__":
    unittest.main()
