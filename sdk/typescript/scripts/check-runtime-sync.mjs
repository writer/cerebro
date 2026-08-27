import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptPath = fileURLToPath(import.meta.url);
const packageDir = path.resolve(path.dirname(scriptPath), "..");

const runtimePairs = [
  ["src/index.js", ".runtime-build/index.js"],
  ["src/jira.js", ".runtime-build/jira.js"],
];

export async function filesMatch(leftPath, rightPath) {
  const [left, right] = await Promise.all([readFile(leftPath), readFile(rightPath)]);
  return left.equals(right);
}

export async function checkRuntimeSync() {
  const staleFiles = [];
  for (const [committedPath, emittedPath] of runtimePairs) {
    const committed = path.join(packageDir, committedPath);
    const emitted = path.join(packageDir, emittedPath);
    if (!(await filesMatch(committed, emitted))) {
      staleFiles.push(committedPath);
    }
  }

  if (staleFiles.length > 0) {
    throw new Error(
      `${staleFiles.join(", ")} must match TypeScript compiler output; run npm run build:runtime and commit the generated JavaScript`,
    );
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === scriptPath) {
  await checkRuntimeSync();
}
