import { spawnSync } from "node:child_process";

const steps = [
  ["git", ["diff", "--check", "HEAD"], "Whitespace and conflict-marker scan"],
  ["npm", ["run", "typecheck"], "TypeScript"],
  ["npm", ["run", "architecture:check"], "Architecture boundaries"],
  ["npm", ["run", "eval:compliance"], "Compliance synthetic evals"],
];

const failures = [];
for (const [command, args, label] of steps) {
  console.log(`\n== ${label} ==`);
  const result = spawnSync(command, args, {
    cwd: process.cwd(),
    stdio: "inherit",
    shell: false,
  });
  if (result.status !== 0) failures.push(`${label} failed with exit ${result.status ?? "unknown"}.`);
}

if (failures.length) {
  console.error("\nLocal review failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exitCode = 1;
} else {
  console.log("\nLocal review passed.");
}
