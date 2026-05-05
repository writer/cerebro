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
  assert.doesNotMatch(source, /from "\.\/index\.ts"/);
  assert.doesNotMatch(source, /from "\.\/index"/);
  assert.match(source, /from "\.\/index\.js"/);

  const example = await readFile(path.resolve(here, "../examples/jira_posture_onboarding.ts"), "utf8");
  assert.doesNotMatch(example, /from "\.\.\/src\/jira\.ts"/);
  assert.doesNotMatch(example, /from "\.\.\/src\/jira"/);
  assert.match(example, /from "\.\.\/src\/jira\.js"/);

  const bridge = await readFile(path.join(srcDir, "index.js"), "utf8");
  assert.doesNotMatch(bridge, /\.ts"/);
});

test("source bridge is importable at runtime", async () => {
  const mod = await import(path.join(srcDir, "index.js"));
  assert.equal(typeof mod.Client, "function");

  const pkg = JSON.parse(await readFile(path.resolve(here, "../package.json"), "utf8"));
  assert.equal(pkg.main, "./src/index.js");
  assert.equal(pkg.exports["."], "./src/index.js");
  assert.equal(pkg.exports["./jira"], "./src/jira.js");

  const jira = await import(path.join(srcDir, "jira.js"));
  assert.equal(typeof jira.buildJiraWorkspaceClaims, "function");
});

test("admin sprawl findings account for posture admins", async () => {
  const source = await readFile(path.join(srcDir, "jira.ts"), "utf8");
  assert.match(source, /const postureAdminEmails = new Set\([\s\S]*optionalString\(admin\.email\)[\s\S]*email\.toLowerCase\(\)/);
  assert.match(source, /const postureAdminCount = postureAdminEmails\.size;/);
  assert.match(source, /const adminCount = Math\.max\(relationCounts\.administers \?\? 0, postureAdminCount\);/);
});

test("jira claims normalize duplicate admin identities", async () => {
  const { Client } = await import(path.join(srcDir, "index.js"));
  const { buildJiraWorkspaceClaims } = await import(path.join(srcDir, "jira.js"));
  const integration = new Client({ baseUrl: "https://cerebro.example.com" }).integration({
    tenantId: "writer",
    runtimeId: "writer-jira",
    integration: "jira",
  });
  const claims = buildJiraWorkspaceClaims(integration, {
    workspaceKey: "writer",
    admins: [{ email: "ADMIN@writer.com" }, { email: "admin@writer.com" }],
  });

  const administers = claims.filter((claim) => claim.predicate === "administers");
  assert.deepEqual(new Set(administers.map((claim) => claim.subject_urn)), new Set(["urn:cerebro:writer:runtime:writer-jira:user:admin@writer.com"]));
  const adminCount = claims.find((claim) => claim.predicate === "admin_count");
  assert.equal(adminCount.object_value, "1");
});

test("onboarding lists all submitted claims", async () => {
  const source = await readFile(path.join(srcDir, "jira.ts"), "utf8");
  assert.doesNotMatch(source, /limit:\s*100/);
  assert.match(source, /limit:\s*claims\.length/);
});
