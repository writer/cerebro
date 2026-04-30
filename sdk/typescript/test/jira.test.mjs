import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const srcDir = path.resolve(here, "../src");

test("buildJiraWorkspaceClaims rejects object-coerced identifiers", async () => {
  const source = await readFile(path.join(srcDir, "jira.ts"), "utf8");
  assert.match(source, /const workspaceKey = requireValue\(posture\.workspaceKey, "posture\.workspaceKey"\)/);
  assert.match(source, /const key = requireValue\(project\.key, "posture\.projects\[\]\.key"\)/);
  assert.match(source, /const admins = objectArray\(posture\.admins, "posture\.admins"\)/);
  assert.match(source, /throw new Error\(`\$\{name\}\[\$\{index\}\] must be an object`\)/);
  assert.match(source, /throw new Error\(`invalid boolean string: \$\{value\}`\)/);
  assert.match(source, /throw new Error\(`invalid boolean value: \$\{String\(value\)\}`\)/);
  assert.ok(source.indexOf("const claims = buildJiraWorkspaceClaims") < source.indexOf("await integration.ensureRuntime"));
  assert.match(source, /function optionalString\(value: unknown\): string \| undefined \{[\s\S]*?if \(typeof value === "string"\)[\s\S]*?if \(typeof value === "number" \|\| typeof value === "bigint"\)[\s\S]*?return undefined;/);
});

test("jira subpath imports the exported source entrypoint", async () => {
  const source = await readFile(path.join(srcDir, "jira.ts"), "utf8");
  assert.doesNotMatch(source, /from "\.\/index\.js"/);
  assert.doesNotMatch(source, /from "\.\/index\.ts"/);
  assert.match(source, /from "\.\/index"/);
});

test("admin sprawl findings account for posture admins", async () => {
  const source = await readFile(path.join(srcDir, "jira.ts"), "utf8");
  assert.match(source, /const postureAdminCount = objectArray\(posture\.admins, "posture\.admins"\)\.length;/);
  assert.match(source, /const adminCount = Math\.max\(relationCounts\.administers \?\? 0, postureAdminCount\);/);
});
