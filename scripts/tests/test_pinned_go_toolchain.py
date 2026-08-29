from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = ROOT / "Makefile"
GO_MOD = ROOT / "go.mod"


class PinnedGoToolchainTest(unittest.TestCase):
    def setUp(self) -> None:
        self.makefile = MAKEFILE.read_text(encoding="utf-8")

    def test_toolchain_pin_matches_go_mod(self) -> None:
        declared = re.search(
            r"^GO_TOOLCHAIN := (\S+)$", self.makefile, re.MULTILINE
        )
        self.assertIsNotNone(declared, "Makefile must define GO_TOOLCHAIN")

        go_mod = re.search(r"^toolchain (\S+)$", GO_MOD.read_text(encoding="utf-8"), re.MULTILINE)
        self.assertIsNotNone(go_mod, "go.mod must carry a toolchain directive")

        self.assertEqual(
            declared.group(1),
            go_mod.group(1),
            "Makefile GO_TOOLCHAIN drifted from the go.mod toolchain directive",
        )

    def test_no_toolchain_version_is_hardcoded(self) -> None:
        # Every site must go through PINNED_GO so the pin has one home.
        self.assertNotIn("GOTOOLCHAIN=go1.", self.makefile)
        self.assertIn("PINNED_GO := GOFLAGS= GOTOOLCHAIN=$(GO_TOOLCHAIN)", self.makefile)

    def test_structural_linter_is_run_under_the_pinned_toolchain(self) -> None:
        # The linter loads repository sources through go/packages, which shells
        # out to `go list`. Building it under the pin but running it under the
        # ambient go makes every package fail to load ("analysis skipped due to
        # errors in package") on any machine whose go is newer than the pin.
        recipe = self.makefile.split("check-structural: check-structural-build", 1)[1]
        recipe = recipe.split("\n\n", 1)[0]
        self.assertIn("$(PINNED_GO) $(LINTER_BIN) $(APP_PACKAGES)", recipe)

    def test_structural_linter_build_and_run_use_the_same_pin(self) -> None:
        for target in ("check-structural-build:", "check-structural-test:"):
            recipe = self.makefile.split(target, 1)[1].split("\n\n", 1)[0]
            self.assertIn("$(PINNED_GO)", recipe, target)


if __name__ == "__main__":
    unittest.main()
