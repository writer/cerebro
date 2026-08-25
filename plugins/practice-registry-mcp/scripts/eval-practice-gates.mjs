#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { PracticeRegistry } from "../dist/registry.js";

const root = process.cwd();
const cases = JSON.parse(fs.readFileSync(path.join(root, "evals", "practice-gate-cases.json"), "utf8"));
const results = [];

for (const entry of cases) {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "practice-registry-eval-"));
  const registry = new PracticeRegistry({
    practicesRoot: path.join(root, "practices"),
    dbPath: path.join(tempDir, "practices.db"),
  });
  try {
    registry.rebuild();
    const result = runCase(registry, entry);
    assertExpected(entry, result);
    results.push({
      name: entry.name,
      decision: result.decision,
      passed: result.passed,
      practice: reportedPractice(entry, result),
    });
  } finally {
    registry.close();
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

console.log(JSON.stringify({ cases: results.length, results }, null, 2));

function runCase(registry, entry) {
  if (entry.tool === "sequence") {
    let result;
    for (const step of entry.steps) {
      result = runTool(registry, step.tool, step.input);
    }
    return result;
  }
  return runTool(registry, entry.tool, entry.input);
}

function runTool(registry, tool, input) {
  if (tool === "check_plan") {
    return registry.check("plan", input);
  }
  if (tool === "preflight") {
    return registry.preflight(input);
  }
  if (tool === "scan_diff") {
    return registry.scanDiff(input.diff, {
      cwd: root,
      rulesPath: input.rules_path,
      useSemgrep: input.use_semgrep,
    });
  }
  if (tool === "finalize_change") {
    return registry.finalizeChange(input, { cwd: root });
  }
  throw new Error(`Unsupported eval tool: ${tool}`);
}

function assertExpected(entry, result) {
  const expected = entry.expect;
  if (expected.decision && result.decision !== expected.decision) {
    throw new Error(`${entry.name}: expected decision ${expected.decision}, got ${result.decision}`);
  }
  if (typeof expected.passed === "boolean" && result.passed !== expected.passed) {
    throw new Error(`${entry.name}: expected passed ${expected.passed}, got ${result.passed}`);
  }
  if (expected.practice_id && !resultContainsPractice(result, expected.practice_id)) {
    throw new Error(`${entry.name}: expected practice ${expected.practice_id}, got ${JSON.stringify(result)}`);
  }
  if (
    typeof expected.passing_plan_found === "boolean" &&
    result.observations?.passing_plan_found !== expected.passing_plan_found
  ) {
    throw new Error(
      `${entry.name}: expected passing_plan_found ${expected.passing_plan_found}, got ${result.observations?.passing_plan_found}`,
    );
  }
}

function resultContainsPractice(result, practiceId) {
  return Boolean(
    result.matched_practices?.some((practice) => practice.id === practiceId) ||
      result.plan_check?.matched_practices?.some((practice) => practice.id === practiceId) ||
      result.guardrails?.practices?.some((practice) => practice.id === practiceId) ||
      result.findings?.some((finding) => finding.practice_id === practiceId) ||
      result.scan_diff?.findings?.some((finding) => finding.practice_id === practiceId),
  );
}

function reportedPractice(entry, result) {
  if (entry.expect.practice_id && resultContainsPractice(result, entry.expect.practice_id)) {
    return entry.expect.practice_id;
  }
  return (
    result.matched_practices?.[0]?.id ??
    result.plan_check?.matched_practices?.[0]?.id ??
    result.guardrails?.practices?.[0]?.id ??
    result.findings?.[0]?.practice_id ??
    result.scan_diff?.findings?.[0]?.practice_id
  );
}
