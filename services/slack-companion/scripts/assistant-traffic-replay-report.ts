import { readFileSync } from "node:fs";
import { buildTrafficReplayReport, parseTrafficReplayCase } from "../src/learning/traffic-replay.js";

const input = readFileSync(0, "utf8").trim();
const cases = input ? input.split(/\r?\n/).map((line, index) => {
  try {
    return parseTrafficReplayCase(JSON.parse(line));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Invalid traffic replay case on line ${index + 1}: ${message}`);
  }
}) : [];

const report = buildTrafficReplayReport(cases);
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
if (!report.releaseReady) process.exitCode = 1;
