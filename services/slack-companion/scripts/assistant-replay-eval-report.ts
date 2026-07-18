import { readFileSync } from "node:fs";
import { evaluateAssistantReplayTurn, type AssistantReplayTurn } from "../src/learning/assistant-replay-eval.js";

const input = readFileSync(0, "utf8").trim();
const turns = input ? input.split(/\r?\n/).flatMap((line) => {
  try {
    return [JSON.parse(line) as AssistantReplayTurn];
  } catch {
    return [];
  }
}) : [];
const receipts = turns.map(evaluateAssistantReplayTurn);
const report = {
  turns: turns.length,
  passed: receipts.filter((receipt) => receipt.passed).length,
  pass_rate: turns.length > 0 ? receipts.filter((receipt) => receipt.passed).length / turns.length : 0,
  average_score: turns.length > 0 ? receipts.reduce((sum, receipt) => sum + receipt.score, 0) / turns.length : 0,
  blocker_counts: receipts.flatMap((receipt) => receipt.blockers).reduce<Record<string, number>>((counts, blocker) => {
    counts[blocker] = (counts[blocker] ?? 0) + 1;
    return counts;
  }, {}),
};

process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
