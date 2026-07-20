import assert from "node:assert/strict";
import { test } from "node:test";
import { InstallationLifecycleController } from "../src/installation.js";
import { isInstallationTransitionAllowed } from "../src/lifecycle.js";

test("installation lifecycle reaches active through explicit provisioning states", () => {
  assert.equal(isInstallationTransitionAllowed("authorizing", "binding"), true);
  assert.equal(isInstallationTransitionAllowed("binding", "verifying"), true);
  assert.equal(isInstallationTransitionAllowed("verifying", "active"), true);
  assert.equal(isInstallationTransitionAllowed("authorizing", "active"), false);
  assert.equal(isInstallationTransitionAllowed("retired", "verifying"), false);
});

test("installation controller rejects an invalid transition before storage", async () => {
  let called = false;
  const controller = new InstallationLifecycleController({
    compareAndSet: async () => {
      called = true;
      throw new Error("unexpected storage call");
    },
  });

  await assert.rejects(
    controller.transition({
      binding_id: "binding-1",
      expected_generation: 1,
      from: "authorizing",
      reason_code: "skip-verification",
      to: "active",
    }),
    /not allowed/,
  );
  assert.equal(called, false);
});
