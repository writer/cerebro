import { createInterface } from "node:readline";
import { loadSlackRuntimeConfig } from "./runtime/config.js";
import {
  runOffSlackTransportJsonl,
} from "./runtime/off-slack-transport.js";
import { createProductionOffSlackAdapter } from "./runtime/production-off-slack-adapter.js";

async function main(): Promise<void> {
  const config = loadSlackRuntimeConfig();
  const adapter = createProductionOffSlackAdapter(config);
  const lines = createInterface({
    crlfDelay: Infinity,
    input: process.stdin,
    terminal: false,
  });
  await runOffSlackTransportJsonl(lines, adapter, (line) => {
    if (!process.stdout.write(line)) {
      return new Promise<void>((resolve) => process.stdout.once("drain", resolve));
    }
  });
}

main().catch((error: unknown) => {
  process.stderr.write(`${JSON.stringify({
    component: "off-slack-transport",
    error_kind: error instanceof Error ? error.name : "unknown",
    operation: "run",
    state: "failed",
  })}\n`);
  process.exitCode = 1;
});
