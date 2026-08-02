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

    def test_check_required_statuses_accepts_all_required_checks(self):
        ok, reason = land_pr.check_required_statuses(
            [
                {"name": "build", "bucket": "pass"},
                {"name": "test", "bucket": "pass"},
            ],
            ("build", "test"),
        )
        self.assertTrue(ok)
        self.assertEqual(reason, "")

    def test_check_required_statuses_rejects_failed_or_missing_checks(self):
        ok, reason = land_pr.check_required_statuses(
            [
                {"name": "build", "bucket": "pass"},
                {"name": "catalog", "bucket": "fail", "link": "https://check"},
            ],
            ("build", "catalog", "verify"),
        )
        self.assertFalse(ok)
        self.assertIn("catalog", reason)
        self.assertIn("verify", reason)

    def test_check_pr_size_rejects_large_pr_without_override(self):
        ok, reason = land_pr.check_pr_size(
            {"additions": 5001, "deletions": 0, "changedFiles": 3},
            max_changed_lines=5000,
            max_changed_files=50,
            allow_large_pr=False,
        )
        self.assertFalse(ok)
        self.assertIn("--allow-large-pr", reason)

    def test_check_pr_size_allows_large_pr_with_override(self):
        ok, reason = land_pr.check_pr_size(
            {"additions": 5001, "deletions": 0, "changedFiles": 3},
            max_changed_lines=5000,
            max_changed_files=50,
            allow_large_pr=True,
        )
        self.assertTrue(ok)
        self.assertEqual(reason, "")

    def test_default_required_checks_use_deterministic_review(self):
        self.assertIn("deterministic-review", land_pr.DEFAULT_REQUIRED_CHECKS)
        self.assertNotIn("droid-review", land_pr.DEFAULT_REQUIRED_CHECKS)
        self.assertNotIn("droid-review-preflight", land_pr.DEFAULT_REQUIRED_CHECKS)

    def test_check_no_active_review_threads_accepts_empty_threads(self):
        ok, reason = land_pr.check_no_active_review_threads([])
        self.assertTrue(ok)
        self.assertEqual(reason, "")

    def test_check_no_active_review_threads_rejects_open_threads(self):
        ok, reason = land_pr.check_no_active_review_threads(
            [{"path": "internal/example.go", "line": 42, "url": "https://thread"}]
        )
        self.assertFalse(ok)
        self.assertIn("active review thread", reason)
        self.assertIn("internal/example.go:42", reason)

    def test_fetch_active_review_threads_filters_resolved_and_outdated(self):
        raw = {
            "data": {
                "repository": {
                    "pullRequest": {
                        "reviewThreads": {
                            "nodes": [
                                {
                                    "isResolved": True,
                                    "isOutdated": False,
                                    "path": "resolved.go",
                                    "line": 1,
                                    "comments": {"nodes": [{"url": "https://resolved", "body": "done"}]},
                                },
                                {
                                    "isResolved": False,
                                    "isOutdated": True,
                                    "path": "outdated.go",
                                    "line": 2,
                                    "comments": {"nodes": [{"url": "https://outdated", "body": "old"}]},
                                },
                                {
                                    "isResolved": False,
                                    "isOutdated": False,
                                    "path": "active.go",
                                    "line": 3,
                                    "comments": {"nodes": [{"url": "https://active", "body": "fix me"}]},
                                },
                            ]
                        }
                    }
                }
            }
        }

        with mock.patch("scripts.land_pr.run_gh", return_value=land_pr.json.dumps(raw)):
            threads = land_pr.fetch_active_review_threads(12, "writer/cerebro")

        self.assertEqual(len(threads), 1)
        self.assertEqual(threads[0]["path"], "active.go")
        self.assertEqual(threads[0]["url"], "https://active")

    def test_fetch_active_review_threads_paginates(self):
        first_page = {
            "data": {
                "repository": {
                    "pullRequest": {
                        "reviewThreads": {
                            "nodes": [],
                            "pageInfo": {"hasNextPage": True, "endCursor": "cursor-1"},
                        }
                    }
                }
            }
        }
        second_page = {
            "data": {
                "repository": {
                    "pullRequest": {
                        "reviewThreads": {
                            "nodes": [
                                {
                                    "isResolved": False,
                                    "isOutdated": False,
                                    "path": "late.go",
                                    "line": 9,
                                    "comments": {"nodes": [{"url": "https://late", "body": "late thread"}]},
                                }
                            ],
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                        }
                    }
                }
            }
        }

        with mock.patch(
            "scripts.land_pr.run_gh",
            side_effect=[land_pr.json.dumps(first_page), land_pr.json.dumps(second_page)],
        ) as run_gh:
            threads = land_pr.fetch_active_review_threads(12, "writer/cerebro")

        self.assertEqual(len(threads), 1)
        self.assertEqual(threads[0]["path"], "late.go")
        self.assertIn("after=cursor-1", run_gh.call_args_list[1].args[0])

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
