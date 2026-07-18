import type { ParsedEnv } from "./env.js";
import { parseBoolean } from "./parsing.js";
import type { AppConfig } from "./types.js";

export function buildSelfRepairConfig(parsed: ParsedEnv): AppConfig["selfRepair"] {
  return {
    enabled: parseBoolean(parsed.CEREBRO_SELF_REPAIR_ENABLED),
    createPr: parseBoolean(parsed.CEREBRO_SELF_REPAIR_CREATE_PR),
    threshold: parsed.CEREBRO_SELF_REPAIR_THRESHOLD,
    lookbackHours: parsed.CEREBRO_SELF_REPAIR_LOOKBACK_HOURS,
    cooldownHours: parsed.CEREBRO_SELF_REPAIR_COOLDOWN_HOURS,
  };
}
