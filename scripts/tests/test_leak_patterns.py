import pathlib
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


def public_patterns() -> list[str]:
    return [
        line
        for raw in (ROOT / "scripts" / "leak_patterns.txt").read_text().splitlines()
        if (line := raw.strip()) and not line.startswith("#")
    ]


def matches(pattern: str, value: str) -> bool:
    result = subprocess.run(
        ["grep", "-Eq", "-e", pattern],
        input=value,
        text=True,
        check=False,
    )
    return result.returncode == 0


class LeakPatternCaseSensitivityTest(unittest.TestCase):
    def test_lowercase_okta_shaped_identifier_still_fails(self):
        okta_pattern = next(pattern for pattern in public_patterns() if "00[uoga]" in pattern)
        self.assertTrue(matches(okta_pattern, "00a" + "b" * 61))

    def test_uppercase_fixture_proof_hash_passes_public_patterns(self):
        # Fixture parity v2 emits uppercase hexadecimal and comparison is
        # deliberately case-sensitive; do not add a case normalizer here.
        proof_hash = "00A" + "B" * 61
        self.assertFalse(any(matches(pattern, proof_hash) for pattern in public_patterns()))


if __name__ == "__main__":
    unittest.main()
