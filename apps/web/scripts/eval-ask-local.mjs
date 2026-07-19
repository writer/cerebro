#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import {
  DEFAULT_OUT_DIR,
  buildAskEvalRunFromEvents,
  nowISO,
  reportTotals,
  writeReport,
} from "./eval-lib.mjs";

const fixturePath = process.env.CEREBRO_ASK_EVAL_FIXTURE ?? new URL("./fixtures/ask-eval-scenarios.json", import.meta.url);
const outputDir = process.env.CEREBRO_ASK_EVAL_OUT_DIR ?? DEFAULT_OUT_DIR;

async function runScenario(scenario) {
  const events = scenario.stream;
  return buildAskEvalRunFromEvents(scenario, events);
}

async function main() {
  const scenarios = JSON.parse(await readFile(fixturePath, "utf8"));
  const runs = [];
  for (const scenario of scenarios) {
    runs.push(await runScenario(scenario));
  }

  const report = await writeReport({
    generatedAt: nowISO(),
    localOnly: true,
    totals: reportTotals(runs),
    runs,
  }, outputDir);

  console.log(JSON.stringify(report, null, 2));
  if (report.totals.failed > 0) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
