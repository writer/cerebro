import { cp, rm, stat, writeFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";

const execFileAsync = promisify(execFile);
const root = process.cwd();
const cerebroRepo = process.env.CEREBRO_REPO_PATH ?? "../cerebro";
const source = path.resolve(root, cerebroRepo, "sdk/typescript");
const target = path.resolve(root, "vendor/cerebro-sdk");

await stat(source);
await rm(target, { recursive: true, force: true });
await cp(source, target, {
  recursive: true,
  filter: (entry) => !entry.includes("node_modules") && !entry.includes("dist"),
});

const sourceCommit = await git(source, "rev-parse", "HEAD");
const sourceRemote = await git(source, "config", "--get", "remote.origin.url").catch(() => "unknown");
await writeFile(path.join(target, "SOURCE.md"), [
  "# Vendored Source",
  "",
  "This SDK snapshot is copied from the Cerebro repository.",
  "",
  `- Source repo: ${sourceRemote.trim() || "unknown"}`,
  "- Source path: sdk/typescript",
  `- Source commit: ${sourceCommit.trim() || "unknown"}`,
  `- Synced at: ${new Date().toISOString()}`,
  "",
  "Update with `npm run sync:cerebro-sdk` from the companion repository root.",
  "",
].join("\n"));

console.log(`Synced ${source} -> ${target}`);

async function git(cwd, ...args) {
  const { stdout } = await execFileAsync("git", args, { cwd });
  return stdout;
}
