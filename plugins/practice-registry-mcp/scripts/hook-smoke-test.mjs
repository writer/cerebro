#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { currentPracticeDiff } from "../hooks/hook-utils.mjs";

const blocking = runHook([
  "*** Begin Patch",
  "*** Update File: services/sync/git_worker.py",
  "@@",
  "+subprocess.run(command, shell=True)",
  "*** End Patch",
]);
if (blocking.result.status !== 2) {
  writeHookOutput(blocking.result);
  throw new Error(`Expected pre-tool hook to exit 2 for blocking practice, got ${blocking.result.status}`);
}
if (blocking.parsed.decision !== "change_code") {
  throw new Error(`Expected change_code decision, got ${blocking.parsed.decision}`);
}
if (blocking.parsed.passed !== false || blocking.parsed.action_required !== true) {
  throw new Error(`Expected explicit blocking outcome fields, got ${JSON.stringify(blocking.parsed)}`);
}

const actionable = runHook([
  "*** Begin Patch",
  "*** Update File: src/api/users.py",
  "@@",
  "+import os",
  '+feature_flag = os.environ.get("FEATURE_FLAG", "")',
  "*** End Patch",
]);
if (actionable.result.status !== 2) {
  writeHookOutput(actionable.result);
  throw new Error(`Expected pre-tool hook to exit 2 for actionable practice, got ${actionable.result.status}`);
}
if (actionable.parsed.decision !== "revise_or_justify") {
  throw new Error(`Expected revise_or_justify decision, got ${actionable.parsed.decision}`);
}
if (actionable.parsed.passed !== false || actionable.parsed.action_required !== true) {
  throw new Error(`Expected explicit actionable outcome fields, got ${JSON.stringify(actionable.parsed)}`);
}

const typescriptBlocking = runHook([
  "*** Begin Patch",
  "*** Update File: src/routes/users.ts",
  "@@",
  "+const rows = db.query(`SELECT * FROM users WHERE id = ${userId}`);",
  "*** End Patch",
]);
if (typescriptBlocking.result.status !== 2) {
  writeHookOutput(typescriptBlocking.result);
  throw new Error(`Expected pre-tool hook to exit 2 for TypeScript blocking practice, got ${typescriptBlocking.result.status}`);
}
if (typescriptBlocking.parsed.findings[0]?.practice_id !== "typescript.db.parameterized-sql") {
  throw new Error(`Expected TypeScript SQL finding, got ${JSON.stringify(typescriptBlocking.parsed)}`);
}

const rustBlocking = runHook([
  "*** Begin Patch",
  "*** Update File: src/release.rs",
  "@@",
  '+Command::new("sh").arg("-c").arg(command).status()?;',
  "*** End Patch",
]);
if (rustBlocking.result.status !== 2) {
  writeHookOutput(rustBlocking.result);
  throw new Error(`Expected pre-tool hook to exit 2 for Rust blocking practice, got ${rustBlocking.result.status}`);
}
if (rustBlocking.parsed.findings[0]?.practice_id !== "rust.process.no-shell-command") {
  throw new Error(`Expected Rust shell finding, got ${JSON.stringify(rustBlocking.parsed)}`);
}

const diffSmoke = smokeCurrentPracticeDiff();

console.log(
  JSON.stringify(
    {
      hook: "practice-pre-tool-use",
      blocking: {
        exit: blocking.result.status,
        finding: blocking.parsed.findings[0]?.practice_id,
      },
      actionable: {
        exit: actionable.result.status,
        finding: actionable.parsed.findings[0]?.practice_id,
      },
      typescript: {
        exit: typescriptBlocking.result.status,
        finding: typescriptBlocking.parsed.findings[0]?.practice_id,
      },
      rust: {
        exit: rustBlocking.result.status,
        finding: rustBlocking.parsed.findings[0]?.practice_id,
      },
      current_diff: diffSmoke,
    },
    null,
    2,
  ),
);

function runHook(patchLines) {
  const input = JSON.stringify({
    tool: "apply_patch",
    tool_input: {
      patch: patchLines.join("\n"),
    },
  });
  const result = spawnSync(process.execPath, ["hooks/practice-pre-tool-use.mjs"], {
    input,
    encoding: "utf8",
    maxBuffer: 20 * 1024 * 1024,
  });
  return {
    result,
    parsed: result.stderr.trim() ? JSON.parse(result.stderr.trim()) : {},
  };
}

function writeHookOutput(result) {
  process.stderr.write(result.stdout);
  process.stderr.write(result.stderr);
}

function smokeCurrentPracticeDiff() {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "practice-hook-diff-"));
  try {
    runGit(["init"], tempRoot);
    runGit(["config", "user.email", "practice-smoke@example.com"], tempRoot);
    runGit(["config", "user.name", "Practice Smoke"], tempRoot);
    fs.mkdirSync(path.join(tempRoot, "src", "components"), { recursive: true });
    fs.writeFileSync(path.join(tempRoot, "src", "components", "Profile.tsx"), "export function Profile() { return null; }\n");
    fs.writeFileSync(path.join(tempRoot, "src", "components", "Legacy.jsx"), "export function Legacy() { return null; }\n");
    fs.writeFileSync(path.join(tempRoot, "src", "release.rs"), "fn release() {}\n");
    fs.writeFileSync(path.join(tempRoot, "Cargo.toml"), "[package]\nname = \"hook-smoke\"\nversion = \"0.1.0\"\n");
    runGit(["add", "."], tempRoot);
    runGit(["commit", "-m", "baseline"], tempRoot);

    fs.writeFileSync(
      path.join(tempRoot, "src", "components", "Profile.tsx"),
      "export function Profile({ body }) { return <div dangerouslySetInnerHTML={{ __html: body }} />; }\n",
    );
    fs.writeFileSync(
      path.join(tempRoot, "src", "components", "Legacy.jsx"),
      "export function Legacy({ body }) { return <div dangerouslySetInnerHTML={{ __html: body }} />; }\n",
    );
    fs.writeFileSync(
      path.join(tempRoot, "src", "release.rs"),
      'fn release(command: String) { Command::new("sh").arg("-c").arg(command); }\n',
    );
    fs.appendFileSync(path.join(tempRoot, "Cargo.toml"), "edition = \"2024\"\n");
    const diff = currentPracticeDiff(tempRoot);
    if (!diff.includes("Profile.tsx") || !diff.includes("Legacy.jsx") || !diff.includes("release.rs") || !diff.includes("Cargo.toml")) {
      throw new Error(`currentPracticeDiff did not include TSX, JSX, Rust, and Cargo files: ${diff}`);
    }
    return {
      tsx: diff.includes("Profile.tsx"),
      jsx: diff.includes("Legacy.jsx"),
      rust: diff.includes("release.rs"),
      cargo: diff.includes("Cargo.toml"),
    };
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
}

function runGit(args, cwd) {
  const result = spawnSync("git", args, {
    cwd,
    encoding: "utf8",
    maxBuffer: 20 * 1024 * 1024,
  });
  if (result.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed: ${result.stdout}\n${result.stderr}`);
  }
}
