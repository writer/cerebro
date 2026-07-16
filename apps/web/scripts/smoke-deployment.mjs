#!/usr/bin/env node

import { pathToFileURL } from "node:url";

import { smokeBaseUrl } from "./smoke-http.mjs";

const parseArgs = (argv) => {
  const options = { baseUrl: "", chunkLimit: 5 };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--chunks") {
      options.chunkLimit = Number.parseInt(argv[index + 1] ?? "", 10);
      index += 1;
    } else if (arg.startsWith("--chunks=")) {
      options.chunkLimit = Number.parseInt(arg.slice("--chunks=".length), 10);
    } else if (!arg.startsWith("--") && !options.baseUrl) {
      options.baseUrl = arg;
    }
  }
  options.baseUrl ||= process.env.CEREBRO_WEB_SMOKE_BASE_URL ?? "";
  return options;
};

export async function smokeDeployment(options) {
  if (!options.baseUrl) {
    throw new Error("Provide a base URL argument or CEREBRO_WEB_SMOKE_BASE_URL.");
  }
  return smokeBaseUrl(options.baseUrl, {
    chunkLimit: Number.isFinite(options.chunkLimit) && options.chunkLimit > 0 ? options.chunkLimit : 5,
  });
}

async function runCli() {
  const options = parseArgs(process.argv.slice(2));
  const result = await smokeDeployment(options);
  console.log(`[smoke:deploy] ${options.baseUrl}`);
  console.log(`[smoke:deploy] checked ${result.chunkResponses.length}/${result.scriptCount} script chunks`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runCli().catch((error) => {
    console.error(`[smoke:deploy] failed: ${error.stack || error.message}`);
    process.exitCode = 1;
  });
}
