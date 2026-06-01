import unittest

import scripts.droid_ci_context as ci


class DroidCIContextTests(unittest.TestCase):
    def test_redact_hides_tokens(self):
        text = "authorization: bearer secret123 token=abc api_key=xyz"
        redacted = ci.redact(text)
        self.assertNotIn("secret123", redacted)
        self.assertNotIn("abc", redacted)
        self.assertNotIn("xyz", redacted)
        self.assertIn("[redacted]", redacted)

    def test_bounded_lines_truncates(self):
        value = "\n".join(f"line {index}" for index in range(120))
        lines = ci.bounded_lines(value, limit=10)
        self.assertEqual(len(lines), 11)
        self.assertTrue(lines[-1].startswith("... truncated"))

    def test_render_markdown_includes_failed_context(self):
        markdown = ci.render_markdown(
            {
                "head_sha": "abc123",
                "checks": [{"name": "verify", "status": "completed", "conclusion": "failure"}],
                "failed_checks": [
                    {
                        "name": "verify",
                        "details_url": "https://example/job",
                        "annotations": [{"path": "internal/foo.go", "start_line": 12, "title": "lint", "message": "bad"}],
                        "log_excerpt": ["::error::boom"],
                    }
                ],
            }
        )
        self.assertIn("Failed Checks", markdown)
        self.assertIn("Untrusted failed-step log excerpt", markdown)
        self.assertIn("internal/foo.go:12", markdown)


if __name__ == "__main__":
    unittest.main()
