import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { WorkingMemoryFiles } from "../src/learning/working-memory.js";

function withStore(work: (store: WorkingMemoryFiles) => void): void {
  const directory = mkdtempSync(join(tmpdir(), "cerebro-working-memory-"));
  try {
    work(new WorkingMemoryFiles({
      enabled: true,
      directory,
      memoryCharLimit: 160,
      teamCharLimit: 120,
    }));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test("working memory adds, reads, replaces, and removes entries", () => {
  withStore((store) => {
    const added = store.write({
      action: "add",
      target: "memory",
      content: "Okta login posture answers should check runtime health and open identity findings.",
    });
    assert.equal(added.success, true);
    assert.equal(store.read("memory").entries.length, 1);

    const replaced = store.write({
      action: "replace",
      target: "memory",
      oldText: "Okta login posture",
      content: "Login posture answers should check Okta runtime health, open identity findings, and recent graph evidence.",
    });
    assert.equal(replaced.success, true);
    assert.match(store.read("memory").entries[0] ?? "", /recent graph evidence/);

    const removed = store.write({
      action: "remove",
      target: "memory",
      oldText: "Login posture answers",
    });
    assert.equal(removed.success, true);
    assert.equal(store.read("memory").entries.length, 0);
  });
});

test("working memory rejects secrets and over-limit entries", () => {
  withStore((store) => {
    const secret = store.write({
      action: "add",
      target: "team",
      content: "token=xoxb-123-abc",
    });
    assert.equal(secret.success, false);
    assert.match(secret.error ?? "", /secrets/);

    const overLimit = store.write({
      action: "add",
      target: "team",
      content: "a".repeat(200),
    });
    assert.equal(overLimit.success, false);
    assert.match(overLimit.error ?? "", /exceed/);
  });
});

test("working memory prompt block renders bounded file contents", () => {
  withStore((store) => {
    store.write({
      action: "add",
      target: "team",
      content: "Default to silence unless a reply changes what someone checks or decides.",
    });

    const prompt = store.promptBlock();
    assert.match(prompt, /CEREBRO WORKING MEMORY/);
    assert.match(prompt, /TEAM.md/);
    assert.match(prompt, /Default to silence/);
    assert.match(prompt, /§|No entries saved/);
  });
});
