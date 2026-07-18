import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const failures = [];

function fail(message) {
  failures.push(message);
}

function read(path) {
  return readFileSync(join(repoRoot, path), "utf8");
}

function listFiles(dir) {
  const root = join(repoRoot, dir);
  if (!existsSync(root)) return [];
  const files = [];
  const visit = (current) => {
    for (const entry of readdirSync(current)) {
      const resolved = join(current, entry);
      const stat = statSync(resolved);
      if (stat.isDirectory()) {
        visit(resolved);
      } else {
        files.push(relative(repoRoot, resolved));
      }
    }
  };
  visit(root);
  return files;
}

const detachedToolFiles = listFiles("src/tools").filter((file) => file.endsWith(".ts"));
if (detachedToolFiles.length > 0) {
  fail(`Agent tools must live under src/agent/tools, found: ${detachedToolFiles.join(", ")}`);
}

const agents = read("AGENTS.md");
for (const required of [
  "docs/operating-contracts.md",
  "docs/testing-strategy.md",
  "TELEMETRY.md",
  "src/agent/tools/tool-metadata.ts",
]) {
  if (!agents.includes(required)) {
    fail(`AGENTS.md must link ${required}`);
  }
}

const telemetry = read("TELEMETRY.md");
if (!telemetry.startsWith("---\nspec: ./TELEMETRY.spec.md\n---")) {
  fail("TELEMETRY.md must start with spec frontmatter.");
}
for (const heading of [
  "## Goal",
  "## Where To Query",
  "## Investigation Pivots",
  "## Query Recipes",
  "## Domains",
  "## Configuration",
]) {
  if (!telemetry.includes(heading)) {
    fail(`TELEMETRY.md missing ${heading}`);
  }
}

if (failures.length > 0) {
  for (const failure of failures) {
    console.error(`architecture-check: ${failure}`);
  }
  process.exit(1);
}

console.log("architecture-check: ok");
