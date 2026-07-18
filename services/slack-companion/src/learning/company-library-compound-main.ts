import "dotenv/config";

import { pathToFileURL } from "node:url";
import { loadConfig } from "../config/index.js";
import { logger } from "../logger.js";
import { configureTelemetry, telemetryOptionsFromConfig } from "../telemetry.js";
import { CompanyLibraryCompoundingService } from "./company-library-compounding.js";
import { CompanyLibraryCurator } from "./company-library-curator.js";
import { SecurityMemoryStore } from "./security-memory/index.js";

export async function runCompanyLibraryCompounding(argv = process.argv.slice(2)): Promise<void> {
  const args = parseArgs(argv);
  const config = loadConfig();
  configureTelemetry(telemetryOptionsFromConfig(config));
  if (!config.learning.enabled || !config.learning.tableName) {
    throw new Error("Company library compounding requires durable security learning.");
  }
  const memory = new SecurityMemoryStore(config);
  const service = new CompanyLibraryCompoundingService(
    config,
    memory,
    memory.companyLibrary,
    new CompanyLibraryCurator(config),
  );
  await service.run({ force: args.force, minNewRecords: args.minRecords });
}

function parseArgs(argv: string[]): { force: boolean; minRecords: number } {
  let force = false;
  let minRecords = 1;
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--force") {
      force = true;
      continue;
    }
    if (arg === "--min-records") {
      const value = Number(argv[index + 1]);
      if (!Number.isInteger(value) || value < 1 || value > 5_000) throw new Error("--min-records must be an integer from 1 to 5000.");
      minRecords = value;
      index += 1;
      continue;
    }
    throw new Error(`Unsupported company library option: ${arg}`);
  }
  return { force, minRecords };
}

const isEntrypoint = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isEntrypoint) {
  runCompanyLibraryCompounding().catch((error) => {
    logger.error("company library compounding process failed", {
      event: "company.library.compounding.process_failed",
      errorType: error instanceof Error ? error.name : "unknown",
    });
    process.exitCode = 1;
  });
}
