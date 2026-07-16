#!/usr/bin/env node

import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import {
  nowISO,
  reportTotals,
  writeReport,
} from "./eval-lib.mjs";
import {
  buildCorpusRuns,
  buildSanitizedCorpusCandidates,
  corpusSummary,
  expandAdversarialCorpus,
  expandGoldenCorpus,
} from "./ask-adversarial-corpus.mjs";

const scenariosPath = new URL("./fixtures/ask-eval-scenarios.json", import.meta.url);
const liveScenariosPath = new URL("./fixtures/ask-live-golden-scenarios.json", import.meta.url);
const corpusPath = new URL("./fixtures/ask-golden-corpus.json", import.meta.url);

function parseArgs(argv) {
  const args = {
    count: 2400,
    adversarialCount: 600,
    outDir: process.env.CEREBRO_ASK_ADVERSARIAL_OUT_DIR ?? ".eval-reports/ask/adversarial",
    writeCandidates: true,
    fixturePaths: process.env.CEREBRO_ASK_CORPUS_FIXTURES?.split(",").filter(Boolean),
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--count") {
      args.count = Number(argv[++index]);
    } else if (arg === "--adversarial-count") {
      args.adversarialCount = Number(argv[++index]);
    } else if (arg === "--out") {
      args.outDir = argv[++index];
    } else if (arg === "--fixture") {
      args.fixturePaths = [...(args.fixturePaths ?? []), argv[++index]];
    } else if (arg === "--no-candidates") {
      args.writeCandidates = false;
    } else if (arg === "--help") {
      args.help = true;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  return args;
}

function usage() {
  return `Usage:
  npm run eval:ask:adversarial -- --count 2400 --adversarial-count 600
  npm run eval:ask:adversarial -- --count 100 --adversarial-count 25

This is local-only. It generates synthetic golden-corpus traces plus adversarial mutations,
scores them with the Ask rubric suite, and writes sanitized candidate JSONL alongside the report.`;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log(usage());
    return;
  }
  if (!Number.isFinite(args.count) || args.count <= 0) {
    throw new Error("--count must be a positive number");
  }
  if (!Number.isFinite(args.adversarialCount) || args.adversarialCount < 0) {
    throw new Error("--adversarial-count must be zero or greater");
  }

  const [baseScenarios, corpusConfig] = await Promise.all([
    readScenarios(args.fixturePaths),
    readJSON(corpusPath),
  ]);
  const goldenScenarios = expandGoldenCorpus(baseScenarios, corpusConfig, { count: args.count });
  const adversarialScenarios = expandAdversarialCorpus(baseScenarios, corpusConfig, { count: args.adversarialCount });
  const startedAt = Date.now();
  const runs = buildCorpusRuns(goldenScenarios, adversarialScenarios, {
    startedAt,
  });

  const summary = corpusSummary(runs);
  const report = await writeReport({
    generatedAt: nowISO(),
    localOnly: true,
    corpus: {
      schemaVersion: corpusConfig.schema_version,
      requestedGoldenCount: args.count,
      requestedAdversarialCount: args.adversarialCount,
    },
    adversarial: summary,
    totals: reportTotals(runs),
    runs,
  }, args.outDir);

  let candidateJSONLPath;
  if (args.writeCandidates) {
    const candidates = buildSanitizedCorpusCandidates([...goldenScenarios, ...adversarialScenarios]);
    candidateJSONLPath = await writeCandidateJSONL(candidates, args.outDir);
  }

  console.log(JSON.stringify({
    outputPath: report.outputPath,
    latestPath: path.join(args.outDir, "latest.json"),
    candidateJSONLPath,
    summary,
    totals: report.totals,
  }, null, 2));

  if (report.totals.failed > 0) {
    process.exitCode = 1;
  }
}

async function readJSON(url) {
  return JSON.parse(await readFile(url, "utf8"));
}

async function readScenarios(fixturePaths) {
  if (fixturePaths?.length) {
    const loaded = await Promise.all(fixturePaths.map((fixturePath) => readJSON(fixturePath)));
    return loaded.flat();
  }
  const loaded = await Promise.all([
    readJSON(scenariosPath),
    readJSON(liveScenariosPath).catch(() => []),
  ]);
  return loaded.flat();
}

async function writeCandidateJSONL(candidates, outDir) {
  await mkdir(outDir, { recursive: true });
  const outputPath = path.join(outDir, "sanitized-candidates.jsonl");
  await writeFile(outputPath, `${candidates.map((candidate) => JSON.stringify(candidate)).join("\n")}\n`);
  return outputPath;
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
