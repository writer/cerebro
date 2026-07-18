import { loadImprovementWorkerConfig } from "../config/improvement-worker.js";
import { logger } from "../logger.js";
import { ImprovementWorker } from "./worker.js";

const config = loadImprovementWorkerConfig();
const worker = new ImprovementWorker(config);

for (const signal of ["SIGTERM", "SIGINT"] as const) {
  process.once(signal, () => worker.stop());
}

worker.start().catch((error) => {
  logger.error("improvement worker stopped", {
    event: "improvement.worker.stopped",
    error: (error instanceof Error ? error.message : String(error)).replace(/\s+/g, " ").slice(0, 300),
  });
  process.exitCode = 1;
});
