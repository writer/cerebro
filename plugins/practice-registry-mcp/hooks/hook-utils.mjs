import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

export async function readHookInput() {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  const text = Buffer.concat(chunks).toString("utf8").trim();
  if (!text) {
    return {};
  }
  try {
    return JSON.parse(text);
  } catch {
    return { raw: text };
  }
}

export function pluginRoot() {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
}

export function repoRoot() {
  try {
    return execFileSync("git", ["rev-parse", "--show-toplevel"], {
      cwd: process.cwd(),
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    return process.cwd();
  }
}

export function currentPracticeDiff(cwd = repoRoot()) {
  const result = spawnSync("git", ["diff", "--", "*.py", "*.scala", "*.sc", "*.ts", "*.tsx", "*.js", "*.jsx", "*.mjs", "*.cjs", "*.rs", "Cargo.toml", "Cargo.lock", "**/Cargo.toml", "**/Cargo.lock"], {
    cwd,
    encoding: "utf8",
    maxBuffer: 20 * 1024 * 1024,
  });
  return result.stdout ?? "";
}

export function extractPatchText(value) {
  const direct = findPatchString(value);
  return direct ?? "";
}

export function runScan(diff, { failOnActionable = true, failOnBlocking = false } = {}) {
  if (!diff.trim()) {
    return { status: 0, stdout: "", stderr: "" };
  }

  const root = pluginRoot();
  const cli = path.join(root, "dist", "cli.js");
  if (!fs.existsSync(cli)) {
    return {
      status: 1,
      stdout: "",
      stderr: `Practice Registry is not built. Run npm ci && npm run build in ${root}.\n`,
    };
  }

  const args = [cli, "scan-diff"];
  if (failOnActionable) {
    args.push("--fail-on-actionable");
  }
  if (failOnBlocking) {
    args.push("--fail-on-blocking");
  }

  const env = {
    ...process.env,
    PRACTICE_REGISTRY_ROOT: path.join(root, "practices"),
    PRACTICE_SEMGREP_RULES: path.join(root, "semgrep", "practice-rules.yml"),
    PRACTICE_REGISTRY_DB: path.join(repoRoot(), ".practice-registry", "practices.db"),
  };

  const result = spawnSync(process.execPath, args, {
    cwd: repoRoot(),
    env,
    input: diff,
    encoding: "utf8",
    maxBuffer: 20 * 1024 * 1024,
  });

  return {
    status: result.status ?? (result.error ? 1 : 0),
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? result.error?.message ?? "",
  };
}

export function finishFromScan(result) {
  if (result.stdout.trim()) {
    process.stderr.write(`${result.stdout.trim()}\n`);
  }
  if (result.stderr.trim()) {
    process.stderr.write(`${result.stderr.trim()}\n`);
  }
  process.exit(result.status);
}

function findPatchString(value) {
  if (typeof value === "string") {
    if (looksLikePatch(value)) {
      return value;
    }
    return undefined;
  }
  if (!value || typeof value !== "object") {
    return undefined;
  }

  for (const [key, child] of Object.entries(value)) {
    const normalizedKey = key.toLowerCase();
    if (typeof child === "string" && (normalizedKey.includes("patch") || normalizedKey.includes("diff"))) {
      if (looksLikePatch(child)) {
        return child;
      }
    }
    const nested = findPatchString(child);
    if (nested) {
      return nested;
    }
  }

  return undefined;
}

function looksLikePatch(value) {
  return value.includes("diff --git") || value.includes("*** Begin Patch") || value.includes("*** Update File:");
}
