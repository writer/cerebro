import type { ParsedEnv } from "./env.js";
import { parseBoolean } from "./parsing.js";
import type { CodeModeConfig } from "./types.js";

export function buildCodeModeConfig(parsed: ParsedEnv): CodeModeConfig {
  return {
    enabled: parseBoolean(parsed.CEREBRO_CODE_MODE_ENABLED),
    maxToolCalls: parsed.CEREBRO_CODE_MODE_MAX_TOOL_CALLS,
    maxSideEffectCalls: parsed.CEREBRO_CODE_MODE_MAX_SIDE_EFFECT_CALLS,
    timeoutMs: parsed.CEREBRO_CODE_MODE_TIMEOUT_MS,
    memoryLimitBytes: parsed.CEREBRO_CODE_MODE_MEMORY_LIMIT_BYTES,
    maxScriptBytes: parsed.CEREBRO_CODE_MODE_MAX_SCRIPT_BYTES,
    maxOutputBytes: parsed.CEREBRO_CODE_MODE_MAX_OUTPUT_BYTES,
  };
}
