import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));

const facadeBudgets = [
  ["src/agent/security-assistant.ts", 470],
  ["src/agent/tools/cerebro-tools.ts", 80],
  ["src/autonomy/goals.ts", 80],
  ["src/autonomy/runner.ts", 390],
  ["src/code/runtime-code.ts", 180],
  ["src/compliance/context.ts", 300],
  ["src/learning/security-memory/index.ts", 370],
  ["src/schedules/scheduled-jobs/index.ts", 260],
  ["src/slack/research/index.ts", 410],
  ["src/telemetry.ts", 350],
  ["src/triage/alert-triage.ts", 320],
] as const;

const requiredDomainModules = [
  "src/agent/slot-queue.ts",
  "src/agent/security-assistant-output.ts",
  "src/agent/security-assistant-prompts.ts",
  "src/agent/security-assistant-types.ts",
  "src/agent/specialist-team.ts",
  "src/agent/tools/cerebro-finding-tools.ts",
  "src/agent/tools/cerebro-graph-tools.ts",
  "src/agent/tools/cerebro-posture-tools.ts",
  "src/agent/tools/cerebro-runtime-tools.ts",
  "src/agent/tools/cerebro-source-tools.ts",
  "src/autonomy/goal-codec.ts",
  "src/autonomy/goal-store-dynamo.ts",
  "src/autonomy/goal-store-memory.ts",
  "src/autonomy/goal-types.ts",
  "src/autonomy/investigation-objective.ts",
  "src/autonomy/playbook.ts",
  "src/autonomy/runner-plan.ts",
  "src/autonomy/runner-utils.ts",
  "src/code/runtime-code-access.ts",
  "src/code/runtime-code-files.ts",
  "src/code/runtime-code-github.ts",
  "src/code/runtime-code-github-client.ts",
  "src/code/runtime-code-types.ts",
  "src/compliance/context-sources.ts",
  "src/compliance/context-text.ts",
  "src/compliance/context-types.ts",
  "src/learning/security-memory/hygiene-runner.ts",
  "src/learning/security-memory/recall.ts",
  "src/learning/security-memory/types.ts",
  "src/learning/security-memory/write.ts",
  "src/schedules/scheduled-jobs/context-collector.ts",
  "src/schedules/scheduled-jobs/step-runner.ts",
  "src/schedules/scheduled-jobs/trigger-matcher.ts",
  "src/slack/research/transport.ts",
  "src/telemetry/metrics.ts",
  "src/telemetry/resource.ts",
  "src/telemetry/sanitize.ts",
  "src/telemetry/types.ts",
  "src/triage/alert-triage-output.ts",
  "src/triage/alert-triage-prompts.ts",
  "src/triage/alert-triage-response.ts",
  "src/triage/alert-triage-types.ts",
] as const;

test("split facades stay small", () => {
  const violations = facadeBudgets.flatMap(([path, maxLines]) => {
    const lines = readFileSync(join(repoRoot, path), "utf8").split(/\r?\n/).length;
    return lines <= maxLines ? [] : [`${path} has ${lines} lines; max ${maxLines}`];
  });

  assert.deepEqual(violations, []);
});

test("domain-owned modules back the public facades", () => {
  const missing = requiredDomainModules.filter((path) => !existsSync(join(repoRoot, path)));
  assert.deepEqual(missing, []);
});
