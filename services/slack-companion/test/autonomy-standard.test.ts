import assert from "node:assert/strict";
import test from "node:test";
import { autonomyOperatingStandard } from "../src/agent/autonomy-standard.js";

test("autonomy standard defaults to long-horizon action with exfil boundaries", () => {
  const standard = autonomyOperatingStandard().join("\n");
  assert.match(standard, /broad operator requests as goals/i);
  assert.match(standard, /Default to action/i);
  assert.match(standard, /long-horizon work/i);
  assert.match(standard, /evidence ledger/i);
  assert.match(standard, /EvidenceCAS as artifact verification/i);
  assert.match(standard, /Ask for input only when/i);
  assert.match(standard, /reviewable artifacts/i);
  assert.match(standard, /secret exfiltration/i);
  assert.match(standard, /workspace escape/i);
  assert.match(standard, /irreversible production/i);
});
