import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));

const removedEntrypoints = [
  "src/agent/security-tools.ts",
  "src/config.ts",
  "src/learning/security-memory.ts",
  "src/schedules/scheduled-jobs.ts",
  "src/slack/actions.ts",
  "src/slack/blocks.ts",
  "src/slack/commands.ts",
  "src/slack/events.ts",
  "src/slack/research.ts",
];

const activeEntrypoints = [
  "src/agent/tools/index.ts",
  "src/config/index.ts",
  "src/learning/security-memory/index.ts",
  "src/schedules/scheduled-jobs/index.ts",
  "src/slack/actions/index.ts",
  "src/slack/blocks/index.ts",
  "src/slack/commands/index.ts",
  "src/slack/events/index.ts",
  "src/slack/research/index.ts",
];

const removedImportFragments = [
  "/security-tools.js",
  "/config.js",
  "/security-memory.js",
  "/scheduled-jobs.js",
  "/actions.js",
  "/blocks.js",
  "/commands.js",
  "/events.js",
  "/research.js",
];

function sourceFiles(root: string): string[] {
  return readdirSync(root).flatMap((name) => {
    const path = join(root, name);
    const stat = statSync(path);
    if (stat.isDirectory()) return sourceFiles(path);
    return path.endsWith(".ts") ? [path] : [];
  });
}

test("legacy module entrypoints stay removed", () => {
  assert.deepEqual(
    removedEntrypoints.filter((path) => existsSync(join(repoRoot, path))),
    [],
  );
  assert.deepEqual(
    activeEntrypoints.filter((path) => !existsSync(join(repoRoot, path))),
    [],
  );
});

test("imports use domain indexes instead of removed entrypoints", () => {
  const files = [...sourceFiles(join(repoRoot, "src")), ...sourceFiles(join(repoRoot, "test"))]
    .filter((path) => relative(repoRoot, path) !== "test/deprecated-entrypoints.test.ts");
  const violations = files.flatMap((path) => {
    const contents = readFileSync(path, "utf8");
    const matches = removedImportFragments.filter((fragment) => contents.includes(fragment));
    return matches.map((fragment) => `${relative(repoRoot, path)} contains ${fragment}`);
  });

  assert.deepEqual(violations, []);
});
