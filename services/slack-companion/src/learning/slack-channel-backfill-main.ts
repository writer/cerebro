import "dotenv/config";

import { pathToFileURL } from "node:url";
import { loadConfig } from "../config/index.js";
import { logger } from "../logger.js";
import { SlackChannelHistoryClient } from "../slack/channel-history.js";
import { configureTelemetry, telemetryOptionsFromConfig } from "../telemetry.js";
import { SecurityMemoryCurator } from "./security-memory-curator.js";
import { SecurityMemoryStore } from "./security-memory/index.js";
import { SlackChannelBackfillService } from "./slack-channel-backfill.js";
import { SlackChannelBackfillStore } from "./slack-channel-backfill-store.js";
import { SlackChannelLearningService } from "./slack-channel-learning.js";
import { CompanyLibraryCompoundingService } from "./company-library-compounding.js";
import { CompanyLibraryCurator } from "./company-library-curator.js";

interface SlackChannelBackfillCliOptions {
  days: number;
  batchSize?: number;
  maxChannels: number;
  maxRootsPerChannel: number;
  pageSize: number;
  maxThreadMessages: number;
}

export async function runSlackChannelBackfill(argv = process.argv.slice(2)): Promise<void> {
  const args = parseSlackChannelBackfillArgs(argv);
  const config = loadConfig();
  configureTelemetry(telemetryOptionsFromConfig(config));
  if (!config.learning.enabled || !config.learning.channelLearningEnabled) {
    throw new Error("Joined Slack channel learning is disabled.");
  }
  if (!config.learning.tableName) {
    throw new Error("SECURITY_LEARNING_TABLE_NAME is required for a resumable backfill.");
  }
  const batchSize = args.batchSize ?? config.learning.channelLearningBatchSize;
  if (batchSize > config.learning.channelLearningBatchSize) {
    throw new Error("Backfill batch size cannot exceed CEREBRO_SLACK_CHANNEL_LEARNING_BATCH_SIZE.");
  }

  const snapshotSeconds = Math.floor(Date.now() / 1_000);
  const curator = new SecurityMemoryCurator(config);
  const memory = new SecurityMemoryStore(config, { curator });
  const learning = new SlackChannelLearningService(config, memory);
  const service = new SlackChannelBackfillService({
    history: new SlackChannelHistoryClient(config),
    learning,
    store: new SlackChannelBackfillStore(config),
    excludedChannelIds: config.learning.channelLearningExcludedChannelIds,
  });
  await service.run({
    targetOldestTs: String(snapshotSeconds - args.days * 86_400),
    snapshotTs: String(snapshotSeconds),
    batchSize,
    maxChannels: args.maxChannels,
    maxRootsPerChannel: args.maxRootsPerChannel,
    pageSize: args.pageSize,
    maxThreadMessages: args.maxThreadMessages,
  });
  const companyLibrary = new CompanyLibraryCompoundingService(
    config,
    memory,
    memory.companyLibrary,
    new CompanyLibraryCurator(config),
  );
  await companyLibrary.run({ force: true, minNewRecords: 1 });
}

export function parseSlackChannelBackfillArgs(argv: string[]): SlackChannelBackfillCliOptions {
  const values = new Map<string, string>();
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]!;
    if (!arg.startsWith("--")) throw new Error(`Unexpected backfill argument: ${arg}`);
    const equals = arg.indexOf("=");
    if (equals > 2) {
      values.set(arg.slice(2, equals), arg.slice(equals + 1));
      continue;
    }
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) throw new Error(`Missing value for ${arg}`);
    values.set(arg.slice(2), value);
    index += 1;
  }
  const supported = new Set(["days", "batch-size", "max-channels", "max-roots-per-channel", "page-size", "max-thread-messages"]);
  const unsupported = [...values.keys()].find((key) => !supported.has(key));
  if (unsupported) throw new Error(`Unsupported backfill option: --${unsupported}`);
  return {
    days: integerOption(values, "days", 180, 1, 1_825),
    batchSize: optionalIntegerOption(values, "batch-size", 2, 50),
    maxChannels: integerOption(values, "max-channels", 100, 1, 500),
    maxRootsPerChannel: integerOption(values, "max-roots-per-channel", 20_000, 1, 100_000),
    pageSize: integerOption(values, "page-size", 100, 1, 200),
    maxThreadMessages: integerOption(values, "max-thread-messages", 500, 1, 2_000),
  };
}

function integerOption(values: Map<string, string>, key: string, fallback: number, min: number, max: number): number {
  return boundedInteger(values.get(key), key, fallback, min, max);
}

function optionalIntegerOption(values: Map<string, string>, key: string, min: number, max: number): number | undefined {
  const value = values.get(key);
  return value === undefined ? undefined : boundedInteger(value, key, min, min, max);
}

function boundedInteger(value: string | undefined, key: string, fallback: number, min: number, max: number): number {
  if (value === undefined) return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(`--${key} must be an integer from ${min} to ${max}.`);
  }
  return parsed;
}

const isEntrypoint = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isEntrypoint) {
  runSlackChannelBackfill().catch((error) => {
    logger.error("slack channel backfill process failed", {
      event: "slack.channel_backfill.process_failed",
      errorType: error instanceof Error ? error.name : "unknown",
    });
    process.exitCode = 1;
  });
}
