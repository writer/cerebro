import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { filesMatch } from "../scripts/check-runtime-sync.mjs";

test("filesMatch compares file bytes", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "cerebro-sdk-runtime-sync-"));
  t.after(() => rm(directory, { recursive: true, force: true }));

  const committed = path.join(directory, "committed.js");
  const emitted = path.join(directory, "emitted.js");
  await writeFile(committed, "export const value = 1;\n");
  await writeFile(emitted, "export const value = 1;\n");
  assert.equal(await filesMatch(committed, emitted), true);

  await writeFile(emitted, "export const value = 2;\n");
  assert.equal(await filesMatch(committed, emitted), false);
});
